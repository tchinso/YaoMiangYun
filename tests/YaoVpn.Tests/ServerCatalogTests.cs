using System.Text.Json;
using YaoVpn.App.Services;
using YaoVpn.Core;

namespace YaoVpn.Tests;

internal static class ServerCatalogTests
{
    internal static void Run()
    {
        static VpnNode Node(string name, int index) => new(index.ToString(), name, "vless", "1.1.1.1", 443, "");
        var entries = ServerCatalog.Create(new[]
        {
            Node("US 1", 1), Node("Singapore 2", 2), Node("🇯🇵 Tokyo 10", 3), Node("香港 1", 4),
            Node("剩余流量：99 GB", 5), Node("JP 2", 6), Node("中国 1", 7), Node("台湾 1", 8), Node("JP 10", 9)
        });
        Require(!entries[0].IsConnectable && entries[0].DisplayName.Contains("剩余", StringComparison.Ordinal), "Subscription information must sort first without being connectable.");
        Require(entries.Skip(1).Take(3).All(entry => entry.CountryCode == "JP"), "Japan sorts before China/Hong Kong/Singapore/others.");
        var cn = entries.ToList().FindIndex(entry => entry.CountryCode == "CN");
        var hk = entries.ToList().FindIndex(entry => entry.CountryCode == "HK");
        var sg = entries.ToList().FindIndex(entry => entry.CountryCode == "SG");
        Require(cn < sg && hk < sg && entries[^1].CountryCode is "US" or "TW", "China/Hong Kong share the requested bucket while retaining distinct country metadata.");
        Require(entries.ToList().FindIndex(entry => entry.DisplayName == "JP 2") < entries.ToList().FindIndex(entry => entry.DisplayName == "JP 10"), "Numbered Japan servers use natural numeric order.");
        Require(ServerCatalog.SelectDefault(entries)?.CountryCode == "JP", "First startup prefers a real Japan server, never the quota banner.");
        Require(ServerCatalog.SelectDefault(entries, "2")?.Node.Id == "2", "Refreshing preserves an existing deliberate selection.");
        Require(ServerCatalog.SelectDefault(entries, "5")?.CountryCode == "JP", "A previous information row is not a valid selection.");
        var protocolChoices = ServerCatalog.Create(new[]
        {
            Node("JP 1", 101) with { Protocol = "anytls" },
            Node("JP 2", 102) with { Protocol = "hysteria2" },
            Node("JP 3", 103) with { Protocol = "vless" }
        });
        Require(protocolChoices[0].Node.Protocol == "anytls" && ServerCatalog.SelectDefault(protocolChoices)?.Node.Protocol == "vless",
            "Protocol preference affects the initial choice without changing the requested list order.");
        Require(ServerCatalog.SelectDefault(protocolChoices, "101")?.Node.Protocol == "anytls", "A deliberate previous protocol choice is retained.");
        Require(ServerCatalog.SelectDefault(protocolChoices.Where(entry => entry.Node.Protocol != "vless").ToArray())?.Node.Protocol == "hysteria2",
            "Japan Hysteria2 is the compatible initial fallback when VLESS is unavailable in the catalog.");
        Require(ServerCatalog.GetCountryCode("USJP gateway") == null && ServerCatalog.GetCountryCode("US / JP 1") == null, "Embedded and conflicting country markers must not be guessed as Japan.");
        Require(ServerCatalog.GetCountryCode("🇯🇵 provider JP 01") == "JP" && ServerCatalog.GetCountryCode("日本 1") == "JP" && ServerCatalog.GetCountryCode("일본 2") == "JP", "Flags and multilingual provider labels are recognized.");
        Require(!ServerCatalog.IsInformation("JP 10Gbps") && ServerCatalog.IsInformation("Remaining data: 99 GB"), "Link speed is not subscription quota metadata.");

        var template = """
            {"type":"anytls","tag":"TAG","server":"example.com","server_port":443,"password":"fixture","tls":{"enabled":true}}
            """;
        var parsed = SubscriptionParser.Parse("[" + template.Replace("TAG", "剩余流量：99GB", StringComparison.Ordinal) + ","
            + template.Replace("TAG", "JP 1", StringComparison.Ordinal) + "," + template.Replace("TAG", "JP duplicate", StringComparison.Ordinal) + "]");
        Require(parsed.Nodes.Count == 2 && parsed.Nodes.Any(node => node.DisplayName == "JP 1"), "A quota clone cannot consume the real Japan server identity during deduplication.");

        var trace = IpVerification.ParseObservation("ip=203.0.113.42\nloc=JP\ncolo=LAX\n");
        Require(trace is { CountryCode: "JP" }, "Country uses IP geolocation, not the Cloudflare datacenter colo.");
        Require(IpVerification.ParseObservation("ip=203.0.113.42\nloc=JP\nloc=US\n")?.CountryCode == null, "Duplicate country lines cannot create a confident country assertion.");
        Require(IpVerification.ParseObservation("ip=203.0.113.42\nloc=<script>\n")?.CountryCode == null, "Untrusted country content never reaches display metadata.");
        foreach (var unknown in new[] { "XX", "T1", "ZZ", "unknown" })
            Require(IpVerification.ParseObservation("ip=203.0.113.42\nloc=" + unknown + "\n")?.CountryCode == null, "Unknown/anonymous region codes cannot create a mismatch warning.");
        var mismatch = new IpCheckResult("203.0.113.42", "203.0.113.42")
        { AdvertisedCountryCode = "JP", VpnEgress = new("198.51.100.2", "US", DateTimeOffset.UtcNow) };
        Require(mismatch.HasCountryMismatch && mismatch.DisplayText.Contains("서버 표시와 출구 국가가 다릅니다", StringComparison.Ordinal), "A Japan label with US exit is explicitly warned rather than silently relabeled.");

        foreach (var tun in new[] { false, true })
        {
            using var config = JsonDocument.Parse(ConfigBuilder.Build(parsed.Nodes.Single(node => node.DisplayName == "JP 1"), tun, tun ? 0 : 19080,
                new("direct", [], [ConfigBuilder.VpnDiagnosticHost])));
            var route = config.RootElement.GetProperty("route").GetProperty("rules").EnumerateArray()
                .First(rule => rule.TryGetProperty("domain", out var domains) && domains.EnumerateArray().Any(domain => domain.GetString() == ConfigBuilder.VpnDiagnosticHost));
            Require(route.GetProperty("outbound").GetString() == "vpn", "The dedicated egress diagnostic cannot accidentally follow a general direct website rule.");
            var dns = config.RootElement.GetProperty("dns").GetProperty("rules").EnumerateArray()
                .First(rule => rule.TryGetProperty("domain", out var domains) && domains.EnumerateArray().Any(domain => domain.GetString() == ConfigBuilder.VpnDiagnosticHost));
            Require(dns.GetProperty("server").GetString() == "secure-dns", "The diagnostic's DNS follows its forced VPN path.");
        }
        Console.WriteLine("PASS: fixed server groups/numeric order, quota clone preservation, dedicated VPN-country diagnostics");
    }

    private static void Require(bool condition, string message) { if (!condition) throw new Exception(message); }
}
