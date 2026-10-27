using System.Diagnostics;
using YaoVpn.App.Services;
using YaoVpn.Core;

namespace YaoVpn.Tests;

internal static class GeneratedConfigTests
{
    public static async Task RunAsync()
    {
        var nodes = SubscriptionParser.Parse("""
            [
              {"type":"anytls","server":"example.com","server_port":443,"password":"fixture","tls":{"enabled":true}},
              {"type":"hysteria2","server":"example.com","server_port":443,"password":"fixture","tls":{"enabled":true}},
              {"type":"vless","server":"example.com","server_port":443,"uuid":"11111111-1111-1111-1111-111111111111","tls":{"enabled":true}}
            ]
            """).Nodes;
        var policies = new[]
        {
            RoutingPolicy.FullTunnel,
            new RoutingPolicy("vpn", ["private.example.com"], ["example.com"]),
            new RoutingPolicy("direct", ["example.com"], ["public.example.com"])
        };
        var directory = Path.Combine(PrivateStorage.Root, "test-" + Guid.NewGuid().ToString("N"));
        PrivateStorage.SecureDirectory(directory);
        var path = Path.Combine(directory, "config.json");
        using var binary = BinaryTrust.OpenVerifiedCore();
        try
        {
            foreach (var node in nodes)
                foreach (var policy in policies)
                {
                    await File.WriteAllTextAsync(path, ConfigBuilder.Build(node, true, policy: policy));
                    var start = CoreProcess.CreateStartInfo(path, directory);
                    start.ArgumentList[0] = "check";
                    start.CreateNoWindow = true;
                    using var child = Process.Start(start) ?? throw new Exception("Config checker failed to start.");
                    var drains = Task.WhenAll(DiscardAsync(child.StandardOutput), DiscardAsync(child.StandardError));
                    try { await child.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(10)); }
                    finally { if (!child.HasExited) { child.Kill(true); await child.WaitForExitAsync(); } }
                    await drains;
                    if (child.ExitCode != 0) throw new Exception("Pinned core rejected a generated routing configuration.");
                }
            Console.WriteLine("PASS: pinned core accepted all protocols with full VPN and both split-routing policies");
        }
        finally { File.Delete(path); Directory.Delete(directory, false); }
    }

    private static async Task DiscardAsync(StreamReader reader)
    {
        var buffer = new char[2048];
        while (await reader.ReadAsync(buffer) > 0) { }
    }
}
