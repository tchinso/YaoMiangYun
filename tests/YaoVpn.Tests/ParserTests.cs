using System.Net;
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
        PreservesTransportAuthorities();
        PublicEndpointsOnly();
        BuildsApplicationPolicy();
        BuildsUserRoutingPolicy();
        EvictsOldestRoutingRules();
        BuildsUnprivilegedProxyPolicy();
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

    private static void PreservesTransportAuthorities()
    {
        foreach (var authority in new[] { "cover.example.com", "cover.example.com:443", "cover.example.com:8443", "1.1.1.1:443", "[2606:4700:4700::1111]", "[2606:4700:4700::1111]:443" })
        {
            var candidate = Vless.Replace("\"Host\":\"cover.example.com\"", "\"Host\":" + JsonSerializer.Serialize(authority), StringComparison.Ordinal);
            var result = SubscriptionParser.Parse(Wrap(candidate));
            Assert(result.Nodes.Count == 1 && result.RejectedCount == 0, "Safe transport Host authority is accepted.");
            using var clean = JsonDocument.Parse(result.Nodes[0].OutboundJson);
            Assert(clean.RootElement.GetProperty("transport").GetProperty("headers").GetProperty("Host").GetString() == authority, "Transport Host authority is preserved exactly.");
        }
        foreach (var authority in new[] { "https://example.com", "example.com/path", "example.com@evil.test", "example.com?x=1", "example.com#fragment", "example.com:0", "example.com:65536", "example.com:-1", "example.com:", "example.com:443:80", "example.com:４４３", "example.com:443\\file", "example.com\r\nInjected:yes", "example.com%00", "[::1%25eth0]:443", "[1.1.1.1]:443", "[::1]extra", "[::1]:", "[::1]:0", "[::1]:443/path" })
        {
            var candidate = Vless.Replace("\"Host\":\"cover.example.com\"", "\"Host\":" + JsonSerializer.Serialize(authority), StringComparison.Ordinal);
            Assert(SubscriptionParser.Parse(Wrap(candidate)).RejectedCount == 1, "Transport Host authority rejects injection and invalid ports.");
        }
        Throws<FormatException>(() => SubscriptionParser.ValidateEndpointHost("example.com:443"));
    }

    private static void PublicEndpointsOnly()
    {
        var blocked = new[]
        {
            "0.0.0.0", "0.1.2.3", "10.1.2.3", "100.64.0.1", "100.127.255.254", "127.0.0.1",
            "127.1", "2130706433", "0x7f000001", "0177.0.0.1", "169.254.169.254", "172.16.1.1",
            "172.31.255.254", "192.168.1.1", "192.0.0.1", "192.0.2.1", "192.88.99.1", "198.18.0.1",
            "198.19.255.254", "198.51.100.1", "203.0.113.1", "224.0.0.1", "255.255.255.255",
            "::", "::1", "::ffff:127.0.0.1", "::ffff:10.1.2.3", "fc00::1", "fe80::1", "ff02::1",
            "64:ff9b::7f00:1", "2001:0:1::1", "2001:db8::1", "2002:7f00:1::", "3fff:fff::1",
            "localhost", "localhost.", "test.localhost", "router", "router.local", "host.internal", "home.arpa", "router.home.arpa"
        };
        foreach (var host in blocked)
        {
            Throws<FormatException>(() => SubscriptionParser.ValidateEndpointHost(host));
            var json = AnyTls.Replace("any.example.com", host, StringComparison.Ordinal);
            Assert(SubscriptionParser.Parse(Wrap(json)).RejectedCount == 1, "Provider endpoints cannot target a private or reserved destination: " + host);
        }
        foreach (var host in new[] { "1.1.1.1", "8.8.8.8", "100.128.0.1", "172.32.0.1", "2606:4700:4700::1111", "2001:4860:4860::8888", "::ffff:8.8.8.8" })
            Assert(SubscriptionParser.IsPublicEndpointAddress(IPAddress.Parse(host)), "Public VPN endpoints remain supported: " + host);
        Assert(SubscriptionParser.ValidateEndpointHost("::ffff:8.8.8.8") == "8.8.8.8", "Mapped IPv4 is canonicalized before the dialer sees it.");
        Assert(SubscriptionParser.ValidateEndpointHost("VPN.Example.com.") == "vpn.example.com", "Public endpoint DNS names are canonicalized.");
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
        Assert(route.GetProperty("rules").GetArrayLength() == 3 && route.GetProperty("rules")[0].GetProperty("action").GetString() == "hijack-dns"
            && route.GetProperty("rules")[1].GetProperty("action").GetString() == "sniff", "Full-tunnel routing intercepts DNS, observes metadata and verifies VPN health; it has no direct fallback.");
        Assert(route.GetProperty("rules")[2].GetProperty("domain")[0].GetString() == ConfigBuilder.VpnHealthHost
            && route.GetProperty("rules")[2].GetProperty("outbound").GetString() == "vpn", "The application's exact health hostname always exercises the VPN.");
        var outbounds = root.GetProperty("outbounds");
        Assert(outbounds.GetArrayLength() == 1 && outbounds[0].GetProperty("tag").GetString() == "vpn", "Only the VPN outbound exists; there is no selectable direct fallback.");
        Assert(outbounds[0].GetProperty("domain_resolver").GetString() == "bootstrap", "Bootstrap is attached only to the VPN server dialer.");
        var dns = root.GetProperty("dns");
        Assert(dns.GetProperty("final").GetString() == "secure-dns", "General DNS defaults to secure VPN resolver.");
        Assert(dns.GetProperty("reverse_mapping").GetBoolean() && dns.GetProperty("cache_capacity").GetInt32() == 1024, "Bounded DNS reverse mapping supports domain rules without decrypting application content.");
        Assert(dns.GetProperty("rules").GetArrayLength() == 1
            && dns.GetProperty("rules")[0].GetProperty("domain")[0].GetString() == ConfigBuilder.VpnHealthHost
            && dns.GetProperty("rules")[0].GetProperty("server").GetString() == "secure-dns", "The sole default DNS rule reserves the exact VPN health hostname; provider rules cannot select bootstrap.");
        var bootstrap = dns.GetProperty("servers")[0];
        Assert(bootstrap.GetProperty("type").GetString() == "https" && bootstrap.GetProperty("server").GetString() == "1.1.1.1" && !bootstrap.TryGetProperty("detour", out _) && bootstrap.GetProperty("tls").GetProperty("server_name").GetString() == "cloudflare-dns.com", "VPN server bootstrapping uses separately authenticated DoH with the typed DNS direct dialer.");
        var secure = dns.GetProperty("servers")[1];
        Assert(secure.GetProperty("type").GetString() == "https" && secure.GetProperty("server").GetString() == "1.1.1.1" && secure.GetProperty("detour").GetString() == "vpn" && secure.GetProperty("tls").GetProperty("server_name").GetString() == "cloudflare-dns.com", "General DNS is DoH over VPN with authenticated Cloudflare TLS.");
        using var smoke = JsonDocument.Parse(ConfigBuilder.Build(node, false, 19080));
        var mixed = smoke.RootElement.GetProperty("inbounds")[0];
        Assert(smoke.RootElement.GetProperty("inbounds").GetArrayLength() == 1 && mixed.GetProperty("type").GetString() == "mixed" && mixed.GetProperty("listen").GetString() == "127.0.0.1" && mixed.GetProperty("listen_port").GetInt32() == 19080, "Non-admin smoke proxy is loopback only.");
        var ipNode = SubscriptionParser.Parse(Wrap(AnyTls.Replace("\"server\":\"any.example.com\"", "\"server\":\"2606:4700:4700::1111\"", StringComparison.Ordinal))).Nodes.Single();
        using var ipConfig = JsonDocument.Parse(ConfigBuilder.Build(ipNode, true));
        Assert(!ipConfig.RootElement.GetProperty("outbounds")[0].TryGetProperty("domain_resolver", out _), "Literal VPN IPs need no bootstrap resolution.");
        Throws<ArgumentOutOfRangeException>(() => ConfigBuilder.Build(node, false));
        Throws<ArgumentOutOfRangeException>(() => ConfigBuilder.Build(node, true, 65536));
        Throws<ArgumentOutOfRangeException>(() => ConfigBuilder.Build(node, true, -1));
    }

    private static void BuildsUserRoutingPolicy()
    {
        var node = SubscriptionParser.Parse(Wrap(AnyTls)).Nodes.Single();
        var policy = new RoutingPolicy("vpn", ["vpn.example.com"], ["Example.Com."]);
        using var document = JsonDocument.Parse(ConfigBuilder.Build(node, true, policy: policy));
        var root = document.RootElement;
        var rules = root.GetProperty("route").GetProperty("rules");
        Assert(rules[3].GetProperty("domain_suffix")[0].GetString() == "vpn.example.com" && rules[3].GetProperty("outbound").GetString() == "vpn", "Specific VPN subdomains precede a parent direct suffix.");
        Assert(rules[4].GetProperty("domain_suffix")[0].GetString() == "example.com" && rules[4].GetProperty("outbound").GetString() == "direct", "User direct suffixes are canonicalized and explicit.");
        var dns = root.GetProperty("dns");
        Assert(dns.GetProperty("final").GetString() == "secure-dns" && dns.GetProperty("rules")[1].GetProperty("server").GetString() == "secure-dns"
            && dns.GetProperty("rules")[2].GetProperty("server").GetString() == "bootstrap", "DNS follows the same specificity and user-selected route after the reserved health lookup.");
        var direct = root.GetProperty("outbounds")[1];
        Assert(direct.GetProperty("type").GetString() == "direct" && direct.GetProperty("domain_resolver").GetString() == "bootstrap", "Direct DNS is scoped to the approved direct route.");

        using var allowlist = JsonDocument.Parse(ConfigBuilder.Build(node, true, policy: new("direct", ["example.com"], [])));
        Assert(allowlist.RootElement.GetProperty("route").GetProperty("final").GetString() == "direct"
            && allowlist.RootElement.GetProperty("dns").GetProperty("final").GetString() == "bootstrap"
            && allowlist.RootElement.GetProperty("route").GetProperty("rules")[3].GetProperty("outbound").GetString() == "vpn", "VPN-only listed sites are supported with direct as the explicit default.");
        using var inverse = JsonDocument.Parse(ConfigBuilder.Build(node, true, policy: new("direct", ["example.com"], ["direct.example.com"])));
        Assert(inverse.RootElement.GetProperty("route").GetProperty("rules")[3].GetProperty("outbound").GetString() == "direct", "Specific direct subdomains also precede a parent VPN suffix.");
        using var health = JsonDocument.Parse(ConfigBuilder.Build(node, true, policy: new("direct", [], ["gstatic.com", ConfigBuilder.VpnHealthHost])));
        var healthRoute = health.RootElement.GetProperty("route").GetProperty("rules")[2];
        Assert(healthRoute.GetProperty("domain")[0].GetString() == ConfigBuilder.VpnHealthHost
            && !healthRoute.TryGetProperty("domain_suffix", out _) && healthRoute.GetProperty("outbound").GetString() == "vpn"
            && health.RootElement.GetProperty("dns").GetProperty("rules")[0].GetProperty("server").GetString() == "secure-dns",
            "An exact reserved health route and DNS lookup precede both parent and exact direct exceptions.");
        Throws<FormatException>(() => ConfigBuilder.Build(node, true, policy: new("block", [], [])));
        Throws<FormatException>(() => ConfigBuilder.Build(node, true, policy: new("vpn", ["https://example.com/path"], [])));
        Throws<FormatException>(() => ConfigBuilder.Build(node, true, policy: new("vpn", ["*.example.com"], [])));
        Throws<FormatException>(() => ConfigBuilder.Build(node, true, policy: new("vpn", ["1.1.1.1"], [])));
        Throws<FormatException>(() => ConfigBuilder.Build(node, true, policy: new("vpn", ["example.com\r\ncommand"], [])));
        Throws<FormatException>(() => ConfigBuilder.Build(node, true, policy: new("vpn", ["EXAMPLE.COM"], ["example.com"])));
        Throws<FormatException>(() => ConfigBuilder.Build(node, true, policy: new("vpn", Enumerable.Range(0, 65).Select(i => "d" + i + ".example.com").ToArray(), [])));
        Assert(RoutingPolicy.NormalizeDomain("예시.한국") == "xn--vv4b11d.xn--3e0b707e", "Internationalized domain rules use canonical IDN ASCII.");
    }

    private static void EvictsOldestRoutingRules()
    {
        var policy = RoutingPolicy.SelectedSites.AddDomains(["z.example"], "direct")
            .AddDomains(["a.example"], "vpn")
            .AddDomains(Enumerable.Range(0, 62).Select(i => $"site{i}.example"), "vpn");
        policy = RoutingPolicy.Validate(JsonSerializer.Deserialize<RoutingPolicy>(JsonSerializer.Serialize(policy)));
        Assert(policy.RuleOrder[0] == "z.example" && policy.RuleOrder[1] == "a.example",
            "Registration order survives persistence despite alphabetical display and mixed routes.");
        policy = policy.AddDomains(["Z.EXAMPLE.", "z.example"], "vpn");
        Assert(policy.RuleOrder.Length == 64 && policy.RuleOrder[0] == "z.example" && policy.DirectDomains.Length == 0,
            "Duplicate additions and route changes retain original registration age without evicting rules.");
        policy = policy.AddDomains(["new.example"], "direct");
        Assert(!policy.VpnDomains.Contains("z.example") && policy.VpnDomains.Contains("a.example")
            && policy.DirectDomains.SequenceEqual(new[] { "new.example" }) && policy.DefaultRoute == "direct",
            "The oldest rule is evicted across routes while preserving default routing.");
        policy = policy.AddDomains(Enumerable.Range(0, 100).Select(i => $"bulk{i}.example"), "vpn");
        Assert(policy.RuleOrder.Length == 64 && policy.RuleOrder[0] == "bulk36.example"
            && policy.RuleOrder[^1] == "bulk99.example" && policy.DirectDomains.Length == 0,
            "Oversized batches retain the last 64 newly registered domains.");
        policy = RoutingPolicy.Validate(policy with { VpnDomains = policy.VpnDomains.Where(d => d != "bulk36.example").ToArray() });
        policy = policy.AddDomains(["bulk36.example"], "direct");
        Assert(policy.RuleOrder[^1] == "bulk36.example", "Deleted and re-added domains receive a new registration age.");
        policy = RoutingPolicy.Validate(policy with { VpnDomains = [], DirectDomains = [] });
        Assert(policy.RuleOrder.Length == 0, "Deleting all rules also clears registration history.");
        var legacy = RoutingPolicy.Validate(JsonSerializer.Deserialize<RoutingPolicy>(
            """{"DefaultRoute":"vpn","VpnDomains":["z.example","a.example"],"DirectDomains":["b.example"]}"""));
        Assert(legacy.RuleOrder.SequenceEqual(new[] { "z.example", "a.example", "b.example" }),
            "Legacy policies without history use a deterministic stored-order fallback.");
    }

    private static void BuildsUnprivilegedProxyPolicy()
    {
        var node = SubscriptionParser.Parse(Wrap(AnyTls)).Nodes.Single();
        foreach (var policy in new[] { RoutingPolicy.FullTunnel, new RoutingPolicy("direct", ["example.com"], []),
            new RoutingPolicy("vpn", ["trusted.localhost", "router.home.arpa", "public.example.com"], []) })
        {
            var config = ConfigBuilder.Build(node, false, 19080, policy);
            using var document = JsonDocument.Parse(config);
            var root = document.RootElement;
            var inbounds = root.GetProperty("inbounds");
            Assert(inbounds.GetArrayLength() == 1 && inbounds[0].GetProperty("type").GetString() == "mixed"
                && inbounds[0].GetProperty("listen").GetString() == "127.0.0.1" && inbounds[0].GetProperty("listen_port").GetInt32() == 19080,
                "Unprivileged mode exposes exactly one HTTP/SOCKS listener on IPv4 loopback.");
            foreach (var forbidden in new[] { "auto_route", "strict_route", "auto_detect_interface", "bind_interface", "dns_mode", "dns_address", "interface_name", "address", "system_proxy" })
                Assert(!config.Contains('"' + forbidden + '"', StringComparison.Ordinal), "Unprivileged config cannot mutate adapters, system routes, DNS or proxy settings: " + forbidden);
            Assert(!root.TryGetProperty("experimental", out _) && !root.TryGetProperty("services", out _), "Unprivileged mode cannot expose control APIs or provider services.");
            Assert(root.GetProperty("route").GetProperty("final").GetString() == policy.DefaultRoute,
                "Unprivileged mode preserves the user's explicit routing policy.");
            Assert(root.GetProperty("outbounds").EnumerateArray().Any(outbound => outbound.GetProperty("tag").GetString() == "direct"),
                "A local-only direct route is available even when the user's public default is VPN.");
            var rules = root.GetProperty("route").GetProperty("rules");
            Assert(rules[1].GetProperty("ip_is_private").GetBoolean() && rules[1].GetProperty("outbound").GetString() == "direct",
                "Literal loopback and private destinations bypass the provider before sniffing or user rules.");
            var local = new[] { "localhost", "local", "internal", "home.arpa" };
            Assert(rules[2].GetProperty("action").GetString() == "resolve" && rules[2].GetProperty("server").GetString() == "local-system"
                && rules[2].GetProperty("domain_suffix").EnumerateArray().Select(value => value.GetString()).SequenceEqual(local)
                && rules[3].GetProperty("domain_suffix").EnumerateArray().Select(value => value.GetString()).SequenceEqual(local)
                && rules[3].GetProperty("outbound").GetString() == "direct", "Local names resolve through Windows and always stay direct.");
            Assert(rules[4].GetProperty("action").GetString() == "sniff" && !rules[4].TryGetProperty("override_destination", out _)
                && rules[5].GetProperty("action").GetString() == "resolve" && !rules[5].TryGetProperty("server", out _)
                && rules[5].GetProperty("disable_optimistic_cache").GetBoolean(),
                "Public names are resolved using policy DNS while preserving the original domain and handshake metadata.");
            Assert(rules[6].GetProperty("ip_is_private").GetBoolean() && rules[6].GetProperty("outbound").GetString() == "direct"
                && rules[7].GetProperty("domain")[0].GetString() == ConfigBuilder.VpnHealthHost,
                "Resolved private addresses stay direct before the health route and any user VPN suffix.");
            var dns = root.GetProperty("dns");
            Assert(dns.GetProperty("servers")[2].GetProperty("type").GetString() == "local"
                && dns.GetProperty("servers")[2].GetProperty("tag").GetString() == "local-system"
                && dns.GetProperty("rules")[0].GetProperty("server").GetString() == "local-system"
                && dns.GetProperty("rules")[1].GetProperty("domain")[0].GetString() == ConfigBuilder.VpnHealthHost,
                "Only local suffixes use Windows DNS; public health and user DNS routing remain explicit.");
            if (policy.VpnDomains.Contains("trusted.localhost", StringComparer.Ordinal))
                Assert(rules.EnumerateArray().Skip(8).Any(rule => rule.GetProperty("domain_suffix")[0].GetString() == "trusted.localhost"
                    && rule.GetProperty("outbound").GetString() == "vpn"), "Even a conflicting user VPN suffix remains after the mandatory local-origin protections.");
        }
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
