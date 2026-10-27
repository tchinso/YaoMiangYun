using System.Globalization;
using System.Net;
using System.Text.RegularExpressions;
using YaoVpn.Core;

namespace YaoVpn.App.Services;

/// <summary>Connection attempt metadata only; never packet bodies, paths, credentials, or raw logs.</summary>
public sealed record TrafficRecord(DateTimeOffset Timestamp, string Host, int Port, string Network, string Route)
{
    public string DisplayTime => Timestamp.ToLocalTime().ToString("HH:mm:ss", CultureInfo.InvariantCulture);
    public string RouteLabel => Route == "vpn" ? "VPN" : "일반 통신";
    public bool IsDomain => !IPAddress.TryParse(Host, out _);

    internal static TrafficRecord? Validate(TrafficRecord? record)
    {
        if (record == null || record.Host == null || record.Host.Length > 253 || record.Port is < 1 or > 65535
            || record.Network is not ("TCP" or "UDP") || record.Route is not ("vpn" or "direct")) return null;
        string host;
        if (IPAddress.TryParse(record.Host, out var address) && !record.Host.Contains('%')) host = address.ToString();
        else
        {
            try { host = RoutingPolicy.NormalizeDomain(record.Host); }
            catch (FormatException) { return null; }
        }
        return record with { Host = host };
    }
}

/// <summary>Allowlist parser for pinned sing-box log syntax. All other text is discarded.</summary>
internal sealed class TrafficLogParser
{
    private sealed record Pending(string? Host = null, int Port = 0, string? Domain = null, bool Emitted = false);
    private readonly Dictionary<string, Pending> pending = new(StringComparer.Ordinal);
    private readonly Queue<string> order = new();
    private readonly object sync = new();
    private static readonly Regex Ansi = new(@"\x1B\[[0-9;]*m", RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(20));
    private static readonly Regex Header = new(@"^(?:INFO|DEBUG)(?:\[\d{1,12}\])?\s+\[(?<id>\d{1,20}) [^\]\r\n]{1,32}\] (?<message>[^\r\n]+)$", RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(20));
    private static readonly Regex Outbound = new(@"^outbound/(?:direct|vless|hysteria2|anytls)\[(?<route>vpn|direct)\]: outbound (?<packet>packet )?connection(?: to (?<destination>[^\s]+))?$", RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(20));
    private static readonly Regex Inbound = new(@"^inbound/tun\[tun-in\]: inbound (?:packet )?connection to (?<destination>[^\s]+)$", RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(20));
    private static readonly Regex Sniff = new(@"^router: sniffed (?:packet )?protocol: [a-z0-9_-]{1,20}, domain: (?<domain>[^,\s]{1,253})(?:, client: [a-zA-Z0-9_.-]{1,64})?$", RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(20));

    public TrafficRecord? Parse(string line)
    {
        if (line.Length > 2048) return null;
        try
        {
            line = Ansi.Replace(line, "");
            var header = Header.Match(line);
            if (!header.Success) return null;
            lock (sync)
            {
                var id = header.Groups["id"].Value;
                var message = header.Groups["message"].Value;
                var input = Inbound.Match(message);
                var sniff = Sniff.Match(message);
                var output = Outbound.Match(message);
                if (!input.Success && !sniff.Success && !output.Success) return null;
                if (!pending.TryGetValue(id, out var entry))
                {
                    if (pending.Count >= 512) pending.Remove(order.Dequeue());
                    pending[id] = entry = new();
                    order.Enqueue(id);
                }
                if (entry.Emitted) return null;
                if (sniff.Success)
                {
                    try { pending[id] = entry with { Domain = RoutingPolicy.NormalizeDomain(sniff.Groups["domain"].Value) }; }
                    catch (FormatException) { }
                    return null;
                }
                var destination = (input.Success ? input : output).Groups["destination"].Value;
                if (destination.Length > 0 && TryEndpoint(destination, out var host, out var port))
                    entry = entry with { Host = host, Port = port };
                if (input.Success) { pending[id] = entry; return null; }
                if (entry.Host == null || entry.Port == 0) return null;
                var record = TrafficRecord.Validate(new(DateTimeOffset.Now, entry.Domain ?? entry.Host, entry.Port,
                    output.Groups["packet"].Success ? "UDP" : "TCP", output.Groups["route"].Value));
                if (record != null) pending[id] = entry with { Emitted = true };
                return record;
            }
        }
        catch (RegexMatchTimeoutException) { return null; }
    }

    private static bool TryEndpoint(string destination, out string host, out int port)
    {
        host = ""; port = 0;
        var colon = destination.LastIndexOf(':');
        if (colon < 1 || !int.TryParse(destination.AsSpan(colon + 1), NumberStyles.None, CultureInfo.InvariantCulture, out port)
            || port is < 1 or > 65535) return false;
        host = destination[..colon];
        if (host.StartsWith('[') && host.EndsWith(']')) host = host[1..^1];
        return TrafficRecord.Validate(new(DateTimeOffset.Now, host, port, "TCP", "vpn")) != null;
    }
}
