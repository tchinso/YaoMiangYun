using System.Text.Json;
using YaoVpn.App.Services;
using YaoVpn.Core;

namespace YaoVpn.Tests;

/// <summary>Real session selection and diagnostic routing, with exact current-user proxy cleanup.</summary>
internal static class SessionIntegrationTests
{
    internal static async Task RunPrivateAsync()
    {
        var saved = PrivateStorage.Load("subscription.dpapi") ?? throw new IOException("Private subscription unavailable.");
        using var data = JsonDocument.Parse(saved);
        var nodes = SubscriptionParser.Parse(data.RootElement.GetProperty("Json").GetString() ?? "").Nodes
            .Where(node => !ServerCatalog.IsInformation(node.DisplayName) && node.Protocol == "vless").ToArray();
        var selected = nodes.FirstOrDefault() ?? throw new IOException("No supported connection fixture.");
        var different = nodes.FirstOrDefault(node => node.Id != selected.Id) ?? throw new IOException("No distinct connection fixture.");
        await UserProxySession.RecoverProxyAsync();
        var original = SystemProxyLease.ReadCurrent();
        await using var service = new VpnService();
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(75));
        var policy = new RoutingPolicy("direct", [], [ConfigBuilder.VpnDiagnosticHost]);
        try
        {
            await service.ConnectAsync(selected, ConnectionMode.AppProxy, policy, timeout.Token);
            if (!service.Status.IsConnected || service.ActiveServerId != selected.Id || service.ActiveServerName != selected.DisplayName
                || service.AdvertisedCountryCode != ServerCatalog.GetCountryCode(selected))
                throw new Exception("Active connection identity was not retained.");
            var rejected = false;
            try { await service.ConnectAsync(different, ConnectionMode.AppProxy, policy, timeout.Token); }
            catch (InvalidOperationException) { rejected = true; }
            if (!rejected || !service.Status.IsConnected || service.ActiveServerId != selected.Id)
                throw new Exception("A different server request silently reused or replaced the active session.");
            await service.ConnectAsync(selected, ConnectionMode.AppProxy, new("direct", [], [ConfigBuilder.VpnDiagnosticHost]), timeout.Token);
            var result = await service.CheckIpAsync(timeout.Token);
            if (result.SelectedServerName != selected.DisplayName || result.VpnEgress == null || result.BeforeIp == null
                || result.VpnEgress.Ip == result.BeforeIp || result.CurrentIp != result.BeforeIp)
                throw new Exception("Forced VPN diagnostic and ordinary website route were not separated.");
            Console.WriteLine("PASS: active server identity frozen, conflicting selection rejected, equivalent reconnect idempotent");
            Console.WriteLine("PASS: actual VPN IP/country diagnosed even with direct default and conflicting diagnostic-domain exception");
        }
        finally
        {
            await service.DisconnectAsync();
            if (!SystemProxyLease.Equivalent(original, SystemProxyLease.ReadCurrent()))
                throw new Exception("Session regression did not restore the exact Windows proxy.");
            if (service.ActiveServerId != null || service.ActiveServerName != null || service.Status.IsConnected)
                throw new Exception("Stopped session retained stale server metadata.");
        }
        Console.WriteLine("PASS: OFF restores settings and clears active server metadata");
    }
}
