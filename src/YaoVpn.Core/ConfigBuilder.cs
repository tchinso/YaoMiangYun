using System.Net;
using System.Text.Json;

namespace YaoVpn.Core;

/// <summary>Build the complete application-owned full-tunnel policy for sing-box 1.14.4.</summary>
public static class ConfigBuilder
{
    public static string Build(VpnNode node, bool tun, int mixedPort = 0)
    {
        if (mixedPort is < 0 or > 65535 || (!tun && mixedPort == 0))
            throw new ArgumentOutOfRangeException(nameof(mixedPort), "A loopback verification port is required without TUN.");
        var vpn = SubscriptionParser.GetSanitizedFields(node, out _, out var server, out _);
        // This resolver is only attached to the VPN server dialer. General DNS uses DoH over vpn.
        if (!IPAddress.TryParse(server, out _)) vpn["domain_resolver"] = "bootstrap";

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
            inbounds.Add(new Dictionary<string, object?>
            {
                ["type"] = "mixed", ["tag"] = "verification-in", ["listen"] = "127.0.0.1", ["listen_port"] = mixedPort
            });
        }

        var config = new Dictionary<string, object?>
        {
            ["log"] = new { level = "info", timestamp = false },
            ["dns"] = new Dictionary<string, object?>
            {
                ["servers"] = new object[]
                {
                    // Typed DNS servers use a direct dialer by default. A detour to an empty
                    // direct outbound is rejected by sing-box 1.14 at runtime.
                    new { type = "https", tag = "bootstrap", server = "1.1.1.1", server_port = 443, path = "/dns-query", tls = new { enabled = true, server_name = "cloudflare-dns.com" } },
                    new { type = "https", tag = "secure-dns", server = "1.1.1.1", server_port = 443, path = "/dns-query", tls = new { enabled = true, server_name = "cloudflare-dns.com" }, detour = "vpn" }
                },
                ["final"] = "secure-dns", ["strategy"] = "prefer_ipv4"
            },
            ["inbounds"] = inbounds,
            ["outbounds"] = new object[] { vpn },
            ["route"] = new Dictionary<string, object?>
            {
                ["auto_detect_interface"] = true,
                ["default_domain_resolver"] = "secure-dns",
                ["rules"] = new object[] { new { port = 53, action = "hijack-dns" } },
                ["final"] = "vpn"
            }
        };
        return JsonSerializer.Serialize(config, new JsonSerializerOptions { WriteIndented = true });
    }
}
