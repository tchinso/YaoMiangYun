using System.Text.Json;
using YaoVpn.Core;

namespace YaoVpn.Tests;

public static class ParserTests
{
    private const string Vless = """
        {"type":"vless","tag":"Test VLESS","server":"vpn.example.com","server_port":443,
         "uuid":"bf000d23-0752-40b4-affe-68f7707a9661","flow":"xtls-rprx-vision","packet_encoding":"xudp",
         "tls":{"enabled":true,"insecure":false,"server_name":"cover.example.com","utls":{"enabled":true,"fingerprint":"chrome"},
                "reality":{"enabled":true,"public_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","short_id":"0123456789abcdef"}},
         "transport":{"type":"ws","path":"/tunnel","headers":{"Host":"cover.example.com"},"max_early_data":2048}}
        """;
    private const string Hysteria = """
        {"type":"hysteria2","tag":"Test Hysteria","server":"hy.example.com","server_port":443,
         "server_ports":["20000:30000","443"],"hop_interval":"30s","up_mbps":100,"down_mbps":200,"password":"test-password",
         "tls":{"enabled":true,"server_name":"hy.example.com"},"obfs":{"type":"salamander","password":"obfuscation"}}
        """;
    private const string AnyTls = """
        {"type":"anytls","tag":"Test AnyTLS","server":"any.example.com","server_port":443,"password":"test-password",
         "tls":{"enabled":true,"insecure":false,"server_name":"any.example.com","alpn":["h2","http/1.1"]},
         "idle_session_check_interval":"30s","idle_session_timeout":"1m","min_idle_session":2}
        """;

    public static void Run()
    {
        ValidProtocols();
        ExcludesProviderPolicyAndFileAccess();
        RejectsUnsafeAndMalformedNodes();
        BoundsInput();
        RevalidatesPersistedNodes();
        BuildsApplicationPolicy();
    }

    private static void ValidProtocols()
    {
        var result = SubscriptionParser.Parse(Wrap(Vless, Hysteria, AnyTls, """{"type":"selector","outbounds":["evil"]}""", """{"type":"direct"}"""));
        Assert(result.Nodes.Count == 3 && result.RejectedCount == 0, "All three supported TLS protocols parse.");
        Assert(result.Nodes.Select(n => n.Id).Distinct().Count() == 3, "Node identities are distinct.");
        foreach (var node in result.Nodes)
        {
            Assert(node.Id.Length == 64, "Identity is a SHA256 digest.");
            Assert(node.ToString() == node.DisplayName, "Diagnostic node formatting excludes credentials.");
            Assert(SubscriptionParser.Revalidate(node) == node, "Canonical nodes round-trip without changes.");
            using var outbound = JsonDocument.Parse(node.OutboundJson);
            Assert(outbound.RootElement.GetProperty("tag").GetString() == "vpn", "Only the application tag is used.");
            Assert(!outbound.RootElement.GetProperty("tls").GetProperty("insecure").GetBoolean(), "TLS verification is enabled.");
        }
        using var hy = JsonDocument.Parse(result.Nodes[1].OutboundJson);
        Assert(hy.RootElement.GetProperty("server_ports").GetArrayLength() == 2 && !hy.RootElement.TryGetProperty("server_port", out _), "Port hopping has one unambiguous representation.");
        Assert(result.Nodes[1].Port == 20000, "Port metadata matches the effective hopping range.");
        Assert(SubscriptionParser.Parse(Wrap(Vless, Vless)).Nodes.Count == 1, "Duplicate connections are deduplicated.");
        var bbr = Hysteria.Replace("\"up_mbps\":100,\"down_mbps\":200", "\"up_mbps\":0,\"down_mbps\":0", StringComparison.Ordinal)
            .Replace("\"server_ports\":[\"20000:30000\",\"443\"]", "\"server_ports\":null", StringComparison.Ordinal);
        var bbrResult = SubscriptionParser.Parse(Wrap(bbr));
        Assert(bbrResult.Nodes.Count == 1 && bbrResult.RejectedCount == 0, "Hysteria accepts zero bandwidth for BBR and null disabled hopping.");
        using var bbrJson = JsonDocument.Parse(bbrResult.Nodes.Single().OutboundJson);
        Assert(!bbrJson.RootElement.TryGetProperty("server_ports", out _) && bbrJson.RootElement.GetProperty("server_port").GetInt32() == 443, "Null hopping retains the validated single server port.");
    }

    private static void ExcludesProviderPolicyAndFileAccess()
    {
        var injected = Vless.Replace("\"flow\":", "\"detour\":\"MALICIOUS\",\"bind_interface\":\"MALICIOUS\",\"routing_mark\":1,\"domain_resolver\":\"MALICIOUS\",\"netns\":\"C:/MALICIOUS\",\"flow\":", StringComparison.Ordinal)
            .Replace("\"enabled\":true,\"insecure\":false", "\"certificate_path\":\"C:/MALICIOUS\",\"client_key_path\":\"C:/MALICIOUS\",\"ech\":{\"enabled\":true,\"config_path\":\"C:/MALICIOUS\"},\"certificate_provider\":\"MALICIOUS\",\"enabled\":true,\"insecure\":false", StringComparison.Ordinal)
            .Replace("\"fingerprint\":\"chrome\"", "\"fingerprint\":\"chrome\",\"script\":\"MALICIOUS\"", StringComparison.Ordinal)
            .Replace("\"Host\":\"cover.example.com\"", "\"Host\":\"cover.example.com\",\"X-Malicious\":\"MALICIOUS\"", StringComparison.Ordinal);
        var full = """
            {"log":{"output":"C:/MALICIOUS"},"route":{"final":"MALICIOUS","rule_set":[{"type":"remote","url":"https://MALICIOUS"}]},
             "dns":{"servers":[{"type":"https","server":"MALICIOUS"}]},"inbounds":[{"type":"mixed","listen":"0.0.0.0"}],
             "experimental":{"clash_api":{"external_controller":"0.0.0.0:9090","external_ui_download_url":"https://MALICIOUS"}},
             "services":[{"type":"MALICIOUS"}],"outbounds":[
            """ + injected + "]}";
        var result = SubscriptionParser.Parse(full);
        Assert(result.Nodes.Count == 1 && result.RejectedCount == 0, "Safe fields survive an untrusted whole configuration.");
        var json = ConfigBuilder.Build(result.Nodes[0], true);
        Assert(!json.Contains("MALICIOUS", StringComparison.Ordinal), "Provider policy, downloads, scripts, and paths never reach generated configuration.");
        foreach (var forbidden in new[] { "certificate_path", "client_key_path", "config_path", "certificate_provider", "bind_interface", "routing_mark", "netns", "experimental", "services", "rule_set", "external_controller", "external_ui_download_url", "script", "X-Malicious" })
            Assert(!json.Contains('"' + forbidden + '"', StringComparison.Ordinal), "Forbidden field removed: " + forbidden);
        using var clean = JsonDocument.Parse(result.Nodes[0].OutboundJson);
        Assert(!clean.RootElement.TryGetProperty("domain_resolver", out _), "Provider resolver removed before app policy is applied.");
        Assert(!clean.RootElement.TryGetProperty("detour", out _), "Provider dial detour removed.");
    }

    private static void RejectsUnsafeAndMalformedNodes()
    {
        var bad = new[]
        {
            Vless.Replace("\"insecure\":false", "\"insecure\":true", StringComparison.Ordinal),
            Vless.Replace("\"insecure\":false", "\"insecure\":\"false\"", StringComparison.Ordinal),
            Vless.Replace("\"enabled\":true", "\"enabled\":false", StringComparison.Ordinal),
            Vless.Replace("\"server_port\":443", "\"server_port\":\"443\"", StringComparison.Ordinal),
            Vless.Replace("\"server_port\":443", "\"server_port\":65536", StringComparison.Ordinal),
            Vless.Replace("\"server_port\":443", "\"server_port\":443.5", StringComparison.Ordinal),
            Vless.Replace("vpn.example.com", "https://vpn.example.com/file", StringComparison.Ordinal),
            Vless.Replace("vpn.example.com", "C:\\\\Windows\\\\secret", StringComparison.Ordinal),
            Vless.Replace("\"uuid\":\"bf000d23-0752-40b4-affe-68f7707a9661\"", "\"uuid\":\"invalid\"", StringComparison.Ordinal),
            Vless.Replace("\"path\":\"/tunnel\"", "\"path\":\"//evil.example\"", StringComparison.Ordinal),
            Vless.Replace("\"path\":\"/tunnel\"", "\"path\":\"/x\\r\\nInjected: yes\"", StringComparison.Ordinal),
            Vless.Replace("\"short_id\":\"0123456789abcdef\"", "\"short_id\":\"abc\"", StringComparison.Ordinal),
            AnyTls.Replace("[\"h2\",\"http/1.1\"]", "[1]", StringComparison.Ordinal),
            AnyTls.Replace("\"password\":\"test-password\"", "\"password\":{}", StringComparison.Ordinal),
            AnyTls.Replace("\"alpn\":[\"h2\",\"http/1.1\"]", "\"alpn\":\"h2\"", StringComparison.Ordinal),
            Hysteria.Replace("20000:30000", "0:65536", StringComparison.Ordinal),
            Hysteria.Replace("20000:30000", "30000:20000", StringComparison.Ordinal),
            Hysteria.Replace("\"up_mbps\":100", "\"up_mbps\":100001", StringComparison.Ordinal),
            Hysteria.Replace("\"up_mbps\":100", "\"up_mbps\":-1", StringComparison.Ordinal),
            Hysteria.Replace("\"server_ports\":[\"20000:30000\",\"443\"]", "\"server_ports\":\"20000:30000\"", StringComparison.Ordinal),
            Hysteria.Replace("\"hop_interval\":\"30s\"", "\"hop_interval\":\"-1s\"", StringComparison.Ordinal),
            """{"type":"ssh","server":"example.com","server_port":22}""",
            "null",
            "42"
        };
        var result = SubscriptionParser.Parse(Wrap(bad.Append(Vless).ToArray()));
        Assert(result.Nodes.Count == 1 && result.RejectedCount == bad.Length, "Unsafe nodes are rejected individually and counted.");
    }

    private static void BoundsInput()
    {
        Throws<FormatException>(() => SubscriptionParser.Parse(""));
        Throws<FormatException>(() => SubscriptionParser.Parse("{}"));
        Throws<FormatException>(() => SubscriptionParser.Parse("{\"outbounds\":{}}"));
        Throws<FormatException>(() => SubscriptionParser.Parse("{\"outbounds\":[],\"outbounds\":[]}"));
        Throws<FormatException>(() => SubscriptionParser.Parse(Wrap(Vless.Replace("\"server_port\":443", "\"server_port\":443,\"server_port\":80", StringComparison.Ordinal))));
        Throws<FormatException>(() => SubscriptionParser.Parse(new string(' ', SubscriptionParser.MaxSubscriptionBytes + 1)));
        Throws<FormatException>(() => SubscriptionParser.Parse(Wrap(Enumerable.Repeat(Vless, SubscriptionParser.MaxNodes + 1).ToArray())));
        Throws<FormatException>(() => SubscriptionParser.Parse(new string('[', 30) + "0" + new string(']', 30)));
        var tooManyAlpn = AnyTls.Replace("[\"h2\",\"http/1.1\"]", "[" + string.Join(',', Enumerable.Repeat("\"h2\"", 17)) + "]", StringComparison.Ordinal);
        Assert(SubscriptionParser.Parse(Wrap(tooManyAlpn)).RejectedCount == 1, "ALPN array count is bounded.");
        var tooLong = AnyTls.Replace("test-password", new string('a', 4097), StringComparison.Ordinal);
        Assert(SubscriptionParser.Parse(Wrap(tooLong)).RejectedCount == 1, "Passwords are bounded.");
    }

    private static void RevalidatesPersistedNodes()
    {
        var node = SubscriptionParser.Parse(Wrap(Vless)).Nodes.Single();
        var tampered = node with { Id = "forged", Protocol = "direct", Server = "MALICIOUS", Port = 1, OutboundJson = node.OutboundJson.Replace("\"tag\":\"vpn\"", "\"tag\":\"MALICIOUS\",\"detour\":\"MALICIOUS\",\"certificate_path\":\"C:/MALICIOUS\"", StringComparison.Ordinal) };
        Assert(SubscriptionParser.Revalidate(tampered) == node, "Persisted fields are reconstructed from the safe schema.");
        Assert(!ConfigBuilder.Build(tampered, true).Contains("MALICIOUS", StringComparison.Ordinal), "ConfigBuilder revalidates independently at the privilege boundary.");
        Throws<FormatException>(() => ConfigBuilder.Build(node with { OutboundJson = "{\"type\":\"direct\"}" }, true));
        Throws<FormatException>(() => SubscriptionParser.Revalidate(node with { DisplayName = "Injected\r\nname" }));
    }

    private static void BuildsApplicationPolicy()
    {
        var node = SubscriptionParser.Parse(Wrap(AnyTls)).Nodes.Single();
        using var document = JsonDocument.Parse(ConfigBuilder.Build(node, true));
        var root = document.RootElement;
        var inbound = root.GetProperty("inbounds")[0];
        Assert(inbound.GetProperty("type").GetString() == "tun" && inbound.GetProperty("interface_name").GetString() == "YaoVPN", "TUN interface uses the application name.");
        Assert(inbound.GetProperty("address").GetArrayLength() == 2 && inbound.GetProperty("auto_route").GetBoolean() && inbound.GetProperty("strict_route").GetBoolean(), "TUN routes both IP families strictly.");
        Assert(inbound.GetProperty("dns_mode").GetString() == "hijack" && inbound.GetProperty("dns_address").GetArrayLength() == 2, "TUN DNS follows the 1.14 schema.");
        var route = root.GetProperty("route");
        Assert(route.GetProperty("final").GetString() == "vpn" && route.GetProperty("auto_detect_interface").GetBoolean(), "Routing has VPN final and interface loop prevention.");
        Assert(route.GetProperty("default_domain_resolver").GetString() == "secure-dns", "Other domain lookups use the VPN resolver.");
        Assert(route.GetProperty("rules").GetArrayLength() == 1 && route.GetProperty("rules")[0].GetProperty("action").GetString() == "hijack-dns", "Routing has no direct fallback rules.");
        var outbounds = root.GetProperty("outbounds");
        Assert(outbounds.GetArrayLength() == 1 && outbounds[0].GetProperty("tag").GetString() == "vpn", "Only the VPN outbound exists; there is no selectable direct fallback.");
        Assert(outbounds[0].GetProperty("domain_resolver").GetString() == "bootstrap", "Bootstrap is attached only to the VPN server dialer.");
        var dns = root.GetProperty("dns");
        Assert(dns.GetProperty("final").GetString() == "secure-dns", "General DNS defaults to secure VPN resolver.");
        Assert(!dns.TryGetProperty("rules", out _), "No general DNS can select bootstrap through provider rules.");
        var bootstrap = dns.GetProperty("servers")[0];
        Assert(bootstrap.GetProperty("type").GetString() == "https" && bootstrap.GetProperty("server").GetString() == "1.1.1.1" && !bootstrap.TryGetProperty("detour", out _) && bootstrap.GetProperty("tls").GetProperty("server_name").GetString() == "cloudflare-dns.com", "VPN server bootstrapping uses separately authenticated DoH with the typed DNS direct dialer.");
        var secure = dns.GetProperty("servers")[1];
        Assert(secure.GetProperty("type").GetString() == "https" && secure.GetProperty("server").GetString() == "1.1.1.1" && secure.GetProperty("detour").GetString() == "vpn" && secure.GetProperty("tls").GetProperty("server_name").GetString() == "cloudflare-dns.com", "General DNS is DoH over VPN with authenticated Cloudflare TLS.");
        using var smoke = JsonDocument.Parse(ConfigBuilder.Build(node, false, 19080));
        var mixed = smoke.RootElement.GetProperty("inbounds")[0];
        Assert(smoke.RootElement.GetProperty("inbounds").GetArrayLength() == 1 && mixed.GetProperty("type").GetString() == "mixed" && mixed.GetProperty("listen").GetString() == "127.0.0.1" && mixed.GetProperty("listen_port").GetInt32() == 19080, "Non-admin smoke proxy is loopback only.");
        var ipNode = SubscriptionParser.Parse(Wrap(AnyTls.Replace("\"server\":\"any.example.com\"", "\"server\":\"2001:db8::1\"", StringComparison.Ordinal))).Nodes.Single();
        using var ipConfig = JsonDocument.Parse(ConfigBuilder.Build(ipNode, true));
        Assert(!ipConfig.RootElement.GetProperty("outbounds")[0].TryGetProperty("domain_resolver", out _), "Literal VPN IPs need no bootstrap resolution.");
        Throws<ArgumentOutOfRangeException>(() => ConfigBuilder.Build(node, false));
        Throws<ArgumentOutOfRangeException>(() => ConfigBuilder.Build(node, true, 65536));
        Throws<ArgumentOutOfRangeException>(() => ConfigBuilder.Build(node, true, -1));
    }

    private static string Wrap(params string[] nodes) => "{\"outbounds\":[" + string.Join(',', nodes) + "]}";
    private static void Assert(bool condition, string message) { if (!condition) throw new InvalidOperationException(message); }
    private static void Throws<T>(Action action) where T : Exception
    {
        try { action(); }
        catch (T) { return; }
        throw new InvalidOperationException("Expected " + typeof(T).Name + ".");
    }
}
