using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace YaoVpn.Core;

/// <summary>
/// Treat subscriptions as credentials, never as executable sing-box configuration.
/// Every emitted field is constructed here from a small, validated connection schema.
/// </summary>
public static class SubscriptionParser
{
    public const int MaxSubscriptionBytes = 2 * 1024 * 1024;
    public const int MaxNodes = 512;
    private const int MaxOutboundBytes = 64 * 1024;
    private const string Invalid = "The subscription contains an invalid or unsupported connection.";
    private static readonly JsonDocumentOptions Options = new() { MaxDepth = 24 };
    private static readonly Regex DurationPattern = new(@"^(?:[0-9]+(?:\.[0-9]+)?)(ms|s|m|h)$", RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(100));

    public static SubscriptionResult Parse(string text)
    {
        if (string.IsNullOrWhiteSpace(text) || text.Length > MaxSubscriptionBytes || Encoding.UTF8.GetByteCount(text) > MaxSubscriptionBytes)
            throw new FormatException("The subscription is empty or exceeds the size limit.");

        try
        {
            using var document = JsonDocument.Parse(text, Options);
            var root = document.RootElement;
            EnsureUnambiguous(root);
            JsonElement outbounds;
            if (root.ValueKind == JsonValueKind.Array) outbounds = root;
            else if (root.ValueKind == JsonValueKind.Object && root.TryGetProperty("outbounds", out outbounds)) { }
            else throw new FormatException("Expected a sing-box outbounds array.");
            if (outbounds.ValueKind != JsonValueKind.Array || outbounds.GetArrayLength() > MaxNodes)
                throw new FormatException("The subscription has an invalid connection count.");

            var nodes = new List<VpnNode>();
            var seen = new HashSet<string>(StringComparer.Ordinal);
            var rejected = 0;
            var index = 0;
            foreach (var item in outbounds.EnumerateArray())
            {
                index++;
                try
                {
                    if (item.ValueKind != JsonValueKind.Object) throw new FormatException(Invalid);
                    var type = RequiredString(item, "type", 16);
                    // These are subscription navigation/routing entries, not connections.
                    if (type is "selector" or "urltest" or "direct" or "block" or "dns") continue;
                    var fields = Sanitize(item, out var protocol, out var server, out var port);
                    var name = OptionalString(item, "tag", 160) ?? $"{protocol.ToUpperInvariant()} {index}";
                    var node = CreateNode(fields, DisplayName(name), protocol, server, port);
                    if (seen.Add(node.Id)) nodes.Add(node);
                }
                catch (FormatException) { rejected++; }
            }
            return new SubscriptionResult(nodes.AsReadOnly(), rejected);
        }
        catch (JsonException) { throw new FormatException("The subscription is not valid bounded JSON."); }
    }

    /// <summary>Rebuild a persisted or IPC-supplied node. No caller-supplied JSON is trusted.</summary>
    public static VpnNode Revalidate(VpnNode node)
    {
        ArgumentNullException.ThrowIfNull(node);
        var fields = GetSanitizedFields(node, out var protocol, out var server, out var port);
        return CreateNode(fields, DisplayName(node.DisplayName), protocol, server, port);
    }

    internal static Dictionary<string, object?> GetSanitizedFields(VpnNode node, out string protocol, out string server, out int port)
    {
        ArgumentNullException.ThrowIfNull(node);
        if (string.IsNullOrWhiteSpace(node.OutboundJson) || node.OutboundJson.Length > MaxOutboundBytes || Encoding.UTF8.GetByteCount(node.OutboundJson) > MaxOutboundBytes)
            throw new FormatException(Invalid);
        try
        {
            using var document = JsonDocument.Parse(node.OutboundJson, Options);
            EnsureUnambiguous(document.RootElement);
            return Sanitize(document.RootElement, out protocol, out server, out port);
        }
        catch (JsonException) { throw new FormatException(Invalid); }
    }

    private static VpnNode CreateNode(Dictionary<string, object?> fields, string name, string protocol, string server, int port)
    {
        var json = JsonSerializer.Serialize(fields);
        var id = Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(json)));
        return new VpnNode(id, name, protocol, server, port, json);
    }

    private static Dictionary<string, object?> Sanitize(JsonElement item, out string protocol, out string server, out int port)
    {
        if (item.ValueKind != JsonValueKind.Object || Encoding.UTF8.GetByteCount(item.GetRawText()) > MaxOutboundBytes)
            throw new FormatException(Invalid);
        protocol = RequiredString(item, "type", 16);
        if (protocol is not ("vless" or "hysteria2" or "anytls")) throw new FormatException(Invalid);
        server = ValidateEndpointHost(RequiredString(item, "server", 253));
        port = OptionalInt(item, "server_port", 1, 65535) ?? 0;
        var fields = new Dictionary<string, object?> { ["type"] = protocol, ["tag"] = "vpn", ["server"] = server };

        if (protocol == "hysteria2" && item.TryGetProperty("server_ports", out var ranges) && ranges.ValueKind != JsonValueKind.Null)
        {
            var ports = Strings(ranges, 16, 11, allowEmptyArray: true);
            if (ports.Count > 0)
            {
                foreach (var range in ports) ValidatePortRange(range);
                fields["server_ports"] = ports;
                // sing-box gives server_ports precedence; emit just one port representation.
                port = int.Parse(ports[0].Split(':')[0], CultureInfo.InvariantCulture);
            }
        }
        if (!fields.ContainsKey("server_ports"))
        {
            if (port == 0) throw new FormatException(Invalid);
            fields["server_port"] = port;
        }
        fields["tls"] = Tls(RequiredObject(item, "tls"), protocol);

        if (protocol == "vless")
        {
            var uuid = RequiredString(item, "uuid", 36);
            if (!Guid.TryParseExact(uuid, "D", out var parsedUuid) || parsedUuid == Guid.Empty) throw new FormatException(Invalid);
            fields["uuid"] = parsedUuid.ToString("D");
            CopyEnum(item, fields, "flow", "", "xtls-rprx-vision");
            CopyEnum(item, fields, "packet_encoding", "", "packetaddr", "xudp");
            CopyEnum(item, fields, "network", "tcp", "udp");
            if (item.TryGetProperty("transport", out var transport)) fields["transport"] = Transport(transport);
        }
        else
        {
            fields["password"] = RequiredString(item, "password", 4096);
            if (protocol == "hysteria2")
            {
                // Zero is sing-box's unspecified bandwidth, selecting BBR congestion control.
                CopyInt(item, fields, "up_mbps", 0, 100000);
                CopyInt(item, fields, "down_mbps", 0, 100000);
                CopyDuration(item, fields, "hop_interval", 1, 3600);
                CopyDuration(item, fields, "hop_interval_max", 1, 3600);
                CopyEnum(item, fields, "network", "tcp", "udp");
                if (item.TryGetProperty("obfs", out var obfs))
                {
                    RequireObject(obfs);
                    var type = RequiredString(obfs, "type", 16);
                    if (type != "salamander") throw new FormatException(Invalid);
                    fields["obfs"] = new Dictionary<string, object?> { ["type"] = type, ["password"] = RequiredString(obfs, "password", 4096) };
                }
            }
            else
            {
                CopyDuration(item, fields, "idle_session_check_interval", 1, 3600);
                CopyDuration(item, fields, "idle_session_timeout", 1, 3600);
                CopyInt(item, fields, "min_idle_session", 0, 32);
            }
        }
        return fields;
    }

    private static Dictionary<string, object?> Tls(JsonElement tls, string protocol)
    {
        if (!RequiredBool(tls, "enabled") || OptionalBool(tls, "insecure") == true || OptionalBool(tls, "disable_sni") == true)
            throw new FormatException(Invalid);
        var result = new Dictionary<string, object?> { ["enabled"] = true, ["insecure"] = false };
        if (tls.TryGetProperty("server_name", out _)) result["server_name"] = Host(RequiredString(tls, "server_name", 253));
        if (tls.TryGetProperty("alpn", out var alpn)) result["alpn"] = Strings(alpn, 16, 255, allowEmptyArray: true);
        CopyEnum(tls, result, "min_version", "1.2", "1.3");
        CopyEnum(tls, result, "max_version", "1.2", "1.3");
        if (result.TryGetValue("min_version", out var min) && result.TryGetValue("max_version", out var max) && string.CompareOrdinal((string?)min, (string?)max) > 0)
            throw new FormatException(Invalid);

        if (tls.TryGetProperty("utls", out var utls))
        {
            RequireObject(utls);
            var enabled = RequiredBool(utls, "enabled");
            var value = new Dictionary<string, object?> { ["enabled"] = enabled };
            CopyEnum(utls, value, "fingerprint", "", "chrome", "firefox", "edge", "safari", "360", "qq", "ios", "android", "random", "randomized");
            if (enabled && protocol == "hysteria2") throw new FormatException(Invalid);
            result["utls"] = value;
        }
        if (tls.TryGetProperty("reality", out var reality))
        {
            RequireObject(reality);
            var enabled = RequiredBool(reality, "enabled");
            var value = new Dictionary<string, object?> { ["enabled"] = enabled };
            if (enabled)
            {
                if (protocol != "vless" || !result.ContainsKey("server_name")) throw new FormatException(Invalid);
                var key = RequiredString(reality, "public_key", 43);
                if (!Regex.IsMatch(key, "^[A-Za-z0-9_-]{43}$", RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(100))) throw new FormatException(Invalid);
                try { if (Convert.FromBase64String(key.Replace('-', '+').Replace('_', '/') + "=").Length != 32) throw new FormatException(Invalid); }
                catch (FormatException) { throw new FormatException(Invalid); }
                var shortId = OptionalString(reality, "short_id", 16, allowEmpty: true) ?? "";
                if (shortId.Length % 2 != 0 || shortId.Any(c => !Uri.IsHexDigit(c))) throw new FormatException(Invalid);
                value["public_key"] = key;
                value["short_id"] = shortId.ToLowerInvariant();
            }
            result["reality"] = value;
        }
        return result;
    }

    private static Dictionary<string, object?> Transport(JsonElement transport)
    {
        RequireObject(transport);
        var type = RequiredString(transport, "type", 16);
        if (type is not ("ws" or "http" or "httpupgrade" or "grpc" or "quic")) throw new FormatException(Invalid);
        var result = new Dictionary<string, object?> { ["type"] = type };
        if (type is "ws" or "http" or "httpupgrade")
        {
            if (transport.TryGetProperty("path", out _))
            {
                var path = RequiredString(transport, "path", 2048, allowEmpty: true);
                if (path.Length > 0 && (!path.StartsWith('/') || path.StartsWith("//", StringComparison.Ordinal) || path.Contains('\\'))) throw new FormatException(Invalid);
                result["path"] = path;
            }
            if (transport.TryGetProperty("headers", out var headers))
            {
                RequireObject(headers);
                if (headers.EnumerateObject().Count() > 16) throw new FormatException(Invalid);
                // Host is a connection parameter; arbitrary headers are not imported.
                var hostHeaders = new Dictionary<string, object?>();
                foreach (var header in headers.EnumerateObject())
                {
                    if (!header.Name.Equals("Host", StringComparison.OrdinalIgnoreCase)) continue;
                    if (hostHeaders.Count > 0 || header.Value.ValueKind != JsonValueKind.String) throw new FormatException(Invalid);
                    hostHeaders["Host"] = HostAuthority(header.Value.GetString()!);
                }
                if (hostHeaders.Count > 0) result["headers"] = hostHeaders;
            }
        }
        if (type == "ws")
        {
            CopyInt(transport, result, "max_early_data", 0, 65536);
            CopyEnum(transport, result, "early_data_header_name", "", "Sec-WebSocket-Protocol");
        }
        if (type == "http")
        {
            if (transport.TryGetProperty("host", out var hosts)) result["host"] = Strings(hosts, 16, 253).Select(Host).ToArray();
            CopyEnum(transport, result, "method", "GET", "POST", "PUT");
            CopyDuration(transport, result, "idle_timeout", 0, 3600);
            CopyDuration(transport, result, "ping_timeout", 1, 3600);
        }
        if (type == "httpupgrade" && transport.TryGetProperty("host", out _)) result["host"] = Host(RequiredString(transport, "host", 253));
        if (type == "grpc")
        {
            var service = OptionalString(transport, "service_name", 256, allowEmpty: true);
            if (service is not null)
            {
                if (service.Any(c => !(char.IsAsciiLetterOrDigit(c) || c is '_' or '-' or '.' or '/'))) throw new FormatException(Invalid);
                result["service_name"] = service;
            }
            CopyDuration(transport, result, "idle_timeout", 0, 3600);
            CopyDuration(transport, result, "ping_timeout", 1, 3600);
            if (transport.TryGetProperty("permit_without_stream", out _)) result["permit_without_stream"] = RequiredBool(transport, "permit_without_stream");
        }
        return result;
    }

    private static string HostAuthority(string authority)
    {
        if (string.IsNullOrWhiteSpace(authority) || authority.Length > 261 ||
            authority.Any(c => char.IsControl(c) || char.IsWhiteSpace(c))) throw new FormatException(Invalid);
        string host;
        string remainder;
        if (authority.StartsWith('['))
        {
            var close = authority.IndexOf(']');
            if (close < 2 || !IPAddress.TryParse(authority[1..close], out var address) ||
                address.AddressFamily != AddressFamily.InterNetworkV6 || authority[1..close].Contains('%'))
                throw new FormatException(Invalid);
            host = "[" + address + "]";
            remainder = authority[(close + 1)..];
        }
        else
        {
            var colon = authority.IndexOf(':');
            host = Host(colon < 0 ? authority : authority[..colon]);
            remainder = colon < 0 ? "" : authority[colon..];
        }
        if (remainder.Length == 0) return host;
        if (remainder[0] != ':' || remainder.Length == 1 || remainder[1..].Any(c => !char.IsAsciiDigit(c)) ||
            !int.TryParse(remainder.AsSpan(1), NumberStyles.None, CultureInfo.InvariantCulture, out var port) || port is < 1 or > 65535)
            throw new FormatException(Invalid);
        return host + ":" + port.ToString(CultureInfo.InvariantCulture);
    }

    private static string Host(string host)
    {
        if (string.IsNullOrWhiteSpace(host) || host.Length > 253 || host.Any(c => char.IsControl(c) || char.IsWhiteSpace(c)) || host.Contains('%')) throw new FormatException(Invalid);
        if (IPAddress.TryParse(host, out var ip)) return ip.ToString();
        // No URLs, authorities, paths, wildcards, escapes, or IPv6 scope IDs.
        if (host.Any(c => !(char.IsAsciiLetterOrDigit(c) || c is '.' or '-'))) throw new FormatException(Invalid);
        var canonical = host.TrimEnd('.').ToLowerInvariant();
        if (canonical.Length == 0 || canonical.Split('.').Any(part => part.Length is 0 or > 63 || part[0] == '-' || part[^1] == '-')) throw new FormatException(Invalid);
        return canonical;
    }

    /// <summary>
    /// The provider may select a public VPN endpoint, never a service on this PC or LAN.
    /// DNS answers must additionally be checked and pinned by the caller before dialing.
    /// SNI and transport Host fields intentionally use only the syntactic Host validator.
    /// </summary>
    public static string ValidateEndpointHost(string host)
    {
        var canonical = Host(host);
        if (IPAddress.TryParse(canonical, out var address))
        {
            if (!IsPublicEndpointAddress(address)) throw new FormatException(Invalid);
            // Canonicalize mapped IPv4 too, so downstream parsers agree on the destination.
            return address.IsIPv4MappedToIPv6 ? address.MapToIPv4().ToString() : address.ToString();
        }
        if (!canonical.Contains('.') || canonical.EndsWith(".localhost", StringComparison.Ordinal)
            || canonical.EndsWith(".local", StringComparison.Ordinal)
            || canonical.EndsWith(".internal", StringComparison.Ordinal)
            || canonical == "home.arpa" || canonical.EndsWith(".home.arpa", StringComparison.Ordinal))
            throw new FormatException(Invalid);
        return canonical;
    }

    /// <summary>Conservative public unicast policy for provider-controlled connection targets.</summary>
    public static bool IsPublicEndpointAddress(IPAddress address)
    {
        ArgumentNullException.ThrowIfNull(address);
        if (address.IsIPv4MappedToIPv6) address = address.MapToIPv4();
        var bytes = address.GetAddressBytes();
        if (address.AddressFamily == AddressFamily.InterNetwork)
        {
            // IANA special-use ranges: local, private, shared, documentation, benchmark,
            // deprecated transition, multicast and reserved addresses are not VPN targets.
            return !(bytes[0] is 0 or 10 or 127 || bytes[0] >= 224
                || bytes[0] == 100 && bytes[1] is >= 64 and <= 127
                || bytes[0] == 169 && bytes[1] == 254
                || bytes[0] == 172 && bytes[1] is >= 16 and <= 31
                || bytes[0] == 192 && (bytes[1] == 168
                    || bytes[1] == 0 && bytes[2] is 0 or 2
                    || bytes[1] == 88 && bytes[2] == 99)
                || bytes[0] == 198 && (bytes[1] is 18 or 19 || bytes[1] == 51 && bytes[2] == 100)
                || bytes[0] == 203 && bytes[1] == 0 && bytes[2] == 113);
        }
        if (address.AddressFamily != AddressFamily.InterNetworkV6 || address.ScopeId != 0)
            return false;
        // Public IPv6 unicast is 2000::/3. Exclude protocol assignments (including
        // Teredo), documentation and 6to4, which can encode an otherwise blocked IPv4.
        return (bytes[0] & 0xe0) == 0x20
            && !(bytes[0] == 0x20 && bytes[1] == 0x01 && bytes[2] < 2)
            && !(bytes[0] == 0x20 && bytes[1] == 0x01 && bytes[2] == 0x0d && bytes[3] == 0xb8)
            && !(bytes[0] == 0x20 && bytes[1] == 0x02)
            && !(bytes[0] == 0x3f && bytes[1] == 0xff && (bytes[2] & 0xf0) == 0);
    }

    private static string DisplayName(string? name)
    {
        if (string.IsNullOrWhiteSpace(name) || name.Length > 160 || name.Any(char.IsControl)) throw new FormatException(Invalid);
        return name.Trim();
    }

    private static void ValidatePortRange(string value)
    {
        var parts = value.Split(':');
        if (parts.Length is < 1 or > 2 || parts.Any(p => p.Length == 0 || p.Any(c => !char.IsAsciiDigit(c)) || !int.TryParse(p, NumberStyles.None, CultureInfo.InvariantCulture, out var n) || n is < 1 or > 65535))
            throw new FormatException(Invalid);
        if (parts.Length == 2 && int.Parse(parts[0], CultureInfo.InvariantCulture) > int.Parse(parts[1], CultureInfo.InvariantCulture)) throw new FormatException(Invalid);
    }

    private static void EnsureUnambiguous(JsonElement element)
    {
        if (element.ValueKind == JsonValueKind.Object)
        {
            var names = new HashSet<string>(StringComparer.Ordinal);
            foreach (var property in element.EnumerateObject())
            {
                if (!names.Add(property.Name)) throw new FormatException("Duplicate JSON properties are not allowed.");
                EnsureUnambiguous(property.Value);
            }
        }
        else if (element.ValueKind == JsonValueKind.Array)
            foreach (var item in element.EnumerateArray()) EnsureUnambiguous(item);
    }

    private static JsonElement RequiredObject(JsonElement item, string name)
    {
        if (!item.TryGetProperty(name, out var value)) throw new FormatException(Invalid);
        RequireObject(value);
        return value;
    }

    private static void RequireObject(JsonElement value)
    {
        if (value.ValueKind != JsonValueKind.Object) throw new FormatException(Invalid);
    }

    private static string RequiredString(JsonElement item, string name, int max, bool allowEmpty = false)
    {
        if (!item.TryGetProperty(name, out var value) || value.ValueKind != JsonValueKind.String) throw new FormatException(Invalid);
        return ValidateString(value.GetString()!, max, allowEmpty);
    }

    private static string? OptionalString(JsonElement item, string name, int max, bool allowEmpty = false) =>
        item.TryGetProperty(name, out _) ? RequiredString(item, name, max, allowEmpty) : null;

    private static string ValidateString(string text, int max, bool allowEmpty = false)
    {
        if ((!allowEmpty && text.Length == 0) || text.Length > max || text.Any(char.IsControl)) throw new FormatException(Invalid);
        return text;
    }

    private static bool RequiredBool(JsonElement item, string name)
    {
        if (!item.TryGetProperty(name, out var value) || value.ValueKind is not (JsonValueKind.True or JsonValueKind.False)) throw new FormatException(Invalid);
        return value.GetBoolean();
    }

    private static bool? OptionalBool(JsonElement item, string name) => item.TryGetProperty(name, out _) ? RequiredBool(item, name) : null;

    private static int? OptionalInt(JsonElement item, string name, int min, int max)
    {
        if (!item.TryGetProperty(name, out var value)) return null;
        if (value.ValueKind != JsonValueKind.Number || !value.TryGetInt32(out var number) || number < min || number > max) throw new FormatException(Invalid);
        return number;
    }

    private static void CopyInt(JsonElement item, Dictionary<string, object?> fields, string name, int min, int max)
    {
        var number = OptionalInt(item, name, min, max);
        if (number.HasValue) fields[name] = number.Value;
    }

    private static void CopyEnum(JsonElement item, Dictionary<string, object?> fields, string name, params string[] allowed)
    {
        var value = OptionalString(item, name, 64, allowEmpty: true);
        if (value is null) return;
        if (!allowed.Contains(value, StringComparer.Ordinal)) throw new FormatException(Invalid);
        fields[name] = value;
    }

    private static void CopyDuration(JsonElement item, Dictionary<string, object?> fields, string name, double minSeconds, double maxSeconds)
    {
        var text = OptionalString(item, name, 24);
        if (text is null) return;
        var match = DurationPattern.Match(text);
        if (!match.Success) throw new FormatException(Invalid);
        var unit = match.Groups[1].Value;
        if (!double.TryParse(text[..^unit.Length], NumberStyles.AllowDecimalPoint, CultureInfo.InvariantCulture, out var number)) throw new FormatException(Invalid);
        var seconds = number * (unit switch { "ms" => 0.001, "s" => 1, "m" => 60, "h" => 3600, _ => 0 });
        if (!double.IsFinite(seconds) || seconds < minSeconds || seconds > maxSeconds) throw new FormatException(Invalid);
        fields[name] = text;
    }

    private static List<string> Strings(JsonElement array, int maxCount, int maxLength, bool allowEmptyArray = false)
    {
        if (array.ValueKind != JsonValueKind.Array || array.GetArrayLength() > maxCount || (!allowEmptyArray && array.GetArrayLength() == 0)) throw new FormatException(Invalid);
        var result = new List<string>();
        foreach (var value in array.EnumerateArray())
        {
            if (value.ValueKind != JsonValueKind.String) throw new FormatException(Invalid);
            result.Add(ValidateString(value.GetString()!, maxLength));
        }
        return result;
    }
}
