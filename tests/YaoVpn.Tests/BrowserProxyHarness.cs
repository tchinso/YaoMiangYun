using System.Text.Json;
using YaoVpn.App.Services;
using YaoVpn.Core;

namespace YaoVpn.Tests;

/// <summary>Temporary ordinary-user system proxy for an interactive browser egress check.</summary>
internal static class BrowserProxyHarness
{
    internal static async Task RunAsync(bool recoveryChild = false)
    {
        await UserProxySession.RecoverProxyAsync();
        var original = SystemProxyLease.ReadCurrent();
        var saved = PrivateStorage.Load("subscription.dpapi") ?? throw new Exception("Missing saved subscription.");
        using var data = JsonDocument.Parse(saved);
        var nodes = SubscriptionParser.Parse(data.RootElement.GetProperty("Json").GetString() ?? "").Nodes;
        var policy = new RoutingPolicy("direct", ["orange.tw"], []);
        await using var service = new VpnService();
        try
        {
            var connected = false;
            foreach (var node in nodes.Where(node => node.Protocol == "vless").Take(4))
            {
                try
                {
                    await service.ConnectAsync(node, ConnectionMode.AppProxy, policy);
                    connected = true;
                    break;
                }
                catch (InvalidOperationException) { }
            }
            if (!connected || !service.Status.IsConnected || TunnelHealth.IsUp()) throw new Exception("Browser proxy startup failed.");
            var applied = SystemProxyLease.ReadCurrent();
            if (SystemProxyLease.Equivalent(original, applied)) throw new Exception("System proxy setting did not change.");
            Console.WriteLine("BROWSER_PROXY_READY: ordinary-user proxy; orange.tw=VPN, other sites=direct; press Enter to restore (3 minute limit)");
            try
            {
                if (recoveryChild) await Task.Delay(TimeSpan.FromMinutes(3));
                else await Task.Run(Console.ReadLine).WaitAsync(TimeSpan.FromMinutes(3));
            }
            catch (TimeoutException) { }
            var logs = service.DrainTraffic();
            Console.WriteLine(logs.Any(record => (record.Host == "orange.tw" || record.Host.EndsWith(".orange.tw", StringComparison.Ordinal)) && record.Route == "vpn")
                ? "PASS: orange.tw browser traffic observed on VPN outbound"
                : "LIMIT: orange.tw browser traffic was not observed by the proxy");
        }
        finally
        {
            await service.DisconnectAsync();
            if (!SystemProxyLease.Equivalent(original, SystemProxyLease.ReadCurrent())) throw new Exception("Original system proxy was not restored.");
            if (TunnelHealth.IsUp()) throw new Exception("Unexpected TUN adapter during non-admin verification.");
            Console.WriteLine("PASS: OFF restored the exact previous Windows user proxy; no TUN adapter used");
        }
    }
}
