using System.Net;
using System.Text.Json;

namespace YaoVpn.Core;

/// <summary>Build application-owned tunnel policy for sing-box 1.14.4. Provider policy is never imported.</summary>
public static class ConfigBuilder
{
    public const string VpnHealthHost = "connectivitycheck.gstatic.com";
    public const string VpnDiagnosticHost = "one.one.one.one";
    public const string AutomaticRuleFile = "automatic-rules.json";
    public const string AutomaticRuleTag = "automatic-vpn";

    public static string Build(VpnNode node, bool tun, int mixedPort = 0, RoutingPolicy? policy = null)
    {
        if (mixedPort is < 0 or > 65535 || (!tun && mixedPort == 0))
            throw new ArgumentOutOfRangeException(nameof(mixedPort), "A loopback verification port is required without TUN.");
        var vpn = SubscriptionParser.GetSanitizedFields(node, out _, out var server, out _);
        policy = RoutingPolicy.Validate(policy);
        var automatic = policy.DefaultRoute == "auto";
        var directAllowed = !tun || policy.DefaultRoute != "vpn" || policy.DirectDomains.Length > 0;
        var finalDns = policy.DefaultRoute != "vpn" ? "bootstrap" : "secure-dns";
        // VPN server dialing uses direct DoH; application DNS follows the user-owned policy below.
        if (!IPAddress.TryParse(server, out _)) vpn["domain_resolver"] = "bootstrap";

        var outbounds = new List<object> { vpn };
        if (directAllowed)
            outbounds.Add(new { type = "direct", tag = "direct", domain_resolver = "bootstrap" });
        var localSuffixes = new[] { "localhost", "local", "internal", "home.arpa" };
        var routeRules = new List<object>
        {
            new { port = 53, action = "hijack-dns" }
        };
        var dnsRules = new List<object>();
        if (!tun)
        {
            // A proxy must never let the provider serve content under a browser's
            // trusted localhost/LAN origin, even when a caller bypasses WinINET's list.
            routeRules.Add(new { ip_is_private = true, action = "route", outbound = "direct" });
            routeRules.Add(new { domain_suffix = localSuffixes, action = "resolve", server = "local-system", timeout = "8s" });
            routeRules.Add(new { domain_suffix = localSuffixes, action = "route", outbound = "direct" });
            dnsRules.Add(new { domain_suffix = localSuffixes, action = "route", server = "local-system" });
        }
        // Read only the handshake metadata needed for suffix matching; do not override
        // destinations or install a certificate to decrypt application content.
        routeRules.Add(new { action = "sniff", sniffer = new[] { "http", "tls", "quic" }, timeout = "300ms" });
        if (!tun)
        {
            // Resolve once before choosing an outbound. This fills the core's checked
            // destination-address list without replacing its domain/SNI metadata.
            // DNS routing still follows the user policy; no provider-side re-resolution
            // is needed to reach a public name which actually identifies a LAN service.
            routeRules.Add(new { action = "resolve", timeout = "8s", disable_optimistic_cache = true });
            routeRules.Add(new { ip_is_private = true, action = "route", outbound = "direct" });
        }
        // The application's HTTPS readiness probe must exercise the VPN even
        // when the user's default route and parent suffix both select direct.
        // This independent egress measurement must not accidentally measure a
        // user-selected direct route at the general IP-check website.
        routeRules.Add(new { domain = new[] { VpnHealthHost, VpnDiagnosticHost }, action = "route", outbound = "vpn" });
        dnsRules.Add(new { domain = new[] { VpnHealthHost, VpnDiagnosticHost }, action = "route", server = "secure-dns" });
        // First match wins. A specific subdomain must override a parent suffix even
        // when the rules live in opposite user-selected groups.
        var suffixes = policy.VpnDomains.Select(domain => (Domain: domain, Route: "vpn"))
            .Concat(policy.DirectDomains.Select(domain => (Domain: domain, Route: "direct")))
            .OrderByDescending(rule => rule.Domain.Length).ThenBy(rule => rule.Domain, StringComparer.Ordinal);
        foreach (var suffix in automatic ? Enumerable.Empty<(string Domain, string Route)>() : suffixes)
        {
            routeRules.Add(new { domain_suffix = new[] { suffix.Domain }, action = "route", outbound = suffix.Route });
            dnsRules.Add(new { domain_suffix = new[] { suffix.Domain }, action = "route", server = suffix.Route == "vpn" ? "secure-dns" : "bootstrap" });
        }
        if (automatic)
        {
            routeRules.Add(new { rule_set = new[] { AutomaticRuleTag }, action = "route", outbound = "vpn" });
            dnsRules.Add(new { rule_set = new[] { AutomaticRuleTag }, action = "route", server = "secure-dns" });
        }

        var inbounds = new List<object>();
        if (tun)
        {
            inbounds.Add(new Dictionary<string, object?>
            {
                ["type"] = "tun", ["tag"] = "tun-in", ["interface_name"] = "YaoVPN",
                ["address"] = new[] { "172.23.0.1/30", "fd42:7961:6f::1/126" },
                ["mtu"] = 1500, ["auto_route"] = true, ["strict_route"] = true,
                ["dns_mode"] = "hijack", ["dns_address"] = new[] { "172.23.0.2", "fd42:7961:6f::2" }
            });
        }
        if (mixedPort > 0)
        {
            // Windows system-proxy settings cannot supply generated proxy credentials.
            // This listener is loopback-only but is not isolated from other local users.
            inbounds.Add(new Dictionary<string, object?>
            {
                ["type"] = "mixed", ["tag"] = "verification-in", ["listen"] = "127.0.0.1", ["listen_port"] = mixedPort
            });
        }

        var dnsServers = new List<object>
        {
            // Typed DNS servers use a direct dialer by default. A detour to an empty
            // direct outbound is rejected by sing-box 1.14 at runtime.
            new { type = "https", tag = "bootstrap", server = "1.1.1.1", server_port = 443, path = "/dns-query", tls = new { enabled = true, server_name = "cloudflare-dns.com" } },
            new { type = "https", tag = "secure-dns", server = "1.1.1.1", server_port = 443, path = "/dns-query", tls = new { enabled = true, server_name = "cloudflare-dns.com" }, detour = "vpn" }
        };
        if (!tun) dnsServers.Add(new { type = "local", tag = "local-system" });
        var dns = new Dictionary<string, object?>
        {
            ["servers"] = dnsServers,
            ["final"] = finalDns, ["strategy"] = "prefer_ipv4", ["reverse_mapping"] = true, ["cache_capacity"] = 1024
        };
        if (dnsRules.Count > 0) dns["rules"] = dnsRules;

        var route = new Dictionary<string, object?>
        {
            ["default_domain_resolver"] = finalDns,
            ["rules"] = routeRules,
            ["final"] = automatic ? "direct" : policy.DefaultRoute
        };
        if (automatic) route["rule_set"] = new[] { new { type = "local", tag = AutomaticRuleTag, format = "source", path = AutomaticRuleFile } };
        // Socket-proxy mode needs no adapter binding, system routes or DNS mutation.
        if (tun) route["auto_detect_interface"] = true;

        var config = new Dictionary<string, object?>
        {
            ["log"] = new { level = "debug", timestamp = false },
            ["dns"] = dns,
            ["inbounds"] = inbounds,
            ["outbounds"] = outbounds,
            ["route"] = route
        };
        return JsonSerializer.Serialize(config, new JsonSerializerOptions { WriteIndented = true });
    }
}
