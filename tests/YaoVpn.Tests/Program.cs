using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using System.Text.Json;
using YaoVpn.App.Services;
using YaoVpn.Core;

namespace YaoVpn.Tests;

public static class Program
{
    public static async Task<int> Main(string[] args)
    {
        try
        {
            if (args is ["--automatic-routing"])
            {
                await AutomaticRoutingTests.RunAsync();
                return 0;
            }
            if (args is ["--window-lifecycle"])
            {
                await WindowLifecycleTests.RunAsync();
                await TrayLifecycleTests.RunAsync();
                return 0;
            }
            if (args is ["--japan-diagnostic"])
            {
                await JapanDiagnostics.RunAsync();
                return 0;
            }
            if (args is ["--session-private"])
            {
                await SessionIntegrationTests.RunPrivateAsync();
                return 0;
            }
            if (args is ["--anytls-diagnostic"])
            {
                await AnyTlsDiagnostics.RunAsync();
                return 0;
            }
            if (args is ["--proxy-recovery"])
            {
                await ProxyRecoveryTests.RunAsync();
                return 0;
            }
            if (args is ["--browser-proxy"])
            {
                await BrowserProxyHarness.RunAsync();
                return 0;
            }
            if (args is ["--proxy-recovery-child"])
            {
                await BrowserProxyHarness.RunAsync(recoveryChild: true);
                return 0;
            }
            ParserTests.Run();
            ServerCatalogTests.Run();
            await ServiceLifecycleTests.RunAsync();
            await WindowLifecycleTests.RunAsync();
            await TrayLifecycleTests.RunAsync();
            StorageSecurityTests.Run();
            EndpointSecurityTests.Run();
            ProxySessionTests.Run();
            await IpcSecurityTests.RunAsync();
            await TrafficSecurityTests.RunAsync();
            await AutomaticRoutingTests.RunAsync();
            await GeneratedConfigTests.RunAsync();
            using (BinaryTrust.OpenVerifiedCore()) { }
            var name = "test-" + Guid.NewGuid().ToString("N") + ".dpapi";
            try
            {
                PrivateStorage.Save(name, "credential-roundtrip-한글");
                if (PrivateStorage.Load(name) != "credential-roundtrip-한글") throw new Exception("DPAPI roundtrip failed.");
            }
            finally { File.Delete(Path.Combine(PrivateStorage.Root, name)); }
            using (var oversized = new MemoryStream(new byte[] { 0xff, 0xff, 0xff, 0x7f }))
            {
                try { await PipeProtocol.ReadAsync(oversized); throw new Exception("Oversized IPC accepted."); }
                catch (IOException) { }
            }
            Console.WriteLine("PASS: parser/security policy, DPAPI, core SHA256, bounded IPC");
            if (args.Length == 2 && args[0] == "--tun")
            {
                await TunTests.RunAsync(Path.GetFullPath(args[1]));
                return 0;
            }
            if (args.Contains("--check-private") || args.Contains("--live"))
            {
                SubscriptionResult result;
                if (args.Contains("--live"))
                {
                    await using var subscription = new VpnService();
                    _ = await subscription.LoadSavedAsync() ?? throw new Exception("No private subscription available.");
                    result = await subscription.LoadSubscriptionAsync(subscription.SavedUrl ?? throw new Exception("No private URL available."));
                }
                else
                    result = SubscriptionParser.Parse(PrivateStorage.Load("bootstrap.dpapi") ?? throw new Exception("No private bootstrap available."));
                Console.WriteLine($"Private subscription: accepted={result.Nodes.Count}, rejected={result.RejectedCount}");
                await CheckAllAsync(result.Nodes);
                if (args.Contains("--live"))
                {
                    var working = await ProbeProtocolsAsync(result.Nodes);
                    await RoutingIntegrationTests.RunAsync(working.First());
                    await ProxyIntegrationTests.RunAsync(working.First());
                    await ProxyRecoveryTests.RunAsync();
                }
            }
            return 0;
        }
        catch (Exception e)
        {
            // Test assertions contain no provider data. Never emit arbitrary core output/config/exception payloads.
            Console.Error.WriteLine($"FAIL ({e.GetType().Name}): " + (args.Contains("--check-private") || args.Contains("--live") ? "private verification failed; no credentials logged" : e.Message));
            return 1;
        }
    }

    private static async Task CheckAllAsync(IReadOnlyList<VpnNode> nodes)
    {
        var directory = Path.Combine(PrivateStorage.Root, "test-" + Guid.NewGuid().ToString("N"));
        PrivateStorage.SecureDirectory(directory);
        var config = Path.Combine(directory, "config.json");
        try
        {
            foreach (var node in nodes)
            {
                await File.WriteAllTextAsync(config, ConfigBuilder.Build(node, true));
                var start = StartInfo(config, directory, "check");
                using var process = Process.Start(start) ?? throw new Exception("Check failed to start.");
                var error = process.StandardError.ReadToEndAsync();
                var output = process.StandardOutput.ReadToEndAsync();
                await process.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(15));
                await Task.WhenAll(error, output);
                if (process.ExitCode != 0) { Console.WriteLine($"Core check failed: protocol={node.Protocol}, node-index={nodes.ToList().IndexOf(node)}"); throw new Exception("Generated config rejected by pinned core."); }
            }
            Console.WriteLine($"PASS: pinned core validated {nodes.Count} generated TUN configurations");
        }
        finally { File.Delete(config); Directory.Delete(directory, false); }
    }

    private static async Task<IReadOnlyList<VpnNode>> ProbeProtocolsAsync(IReadOnlyList<VpnNode> nodes)
    {
        using var direct = new HttpClient(EndpointResolver.CreateSubscriptionHandler()) { Timeout = TimeSpan.FromSeconds(12) };
        var directTrace = await direct.GetStringAsync("https://www.cloudflare.com/cdn-cgi/trace");
        var directIp = TraceIp(directTrace);
        var checks = await Task.WhenAll(nodes.Where(node => !ServerCatalog.IsInformation(node.DisplayName)).GroupBy(n => n.Protocol).Select(async group =>
        {
            var attempts = 0;
            foreach (var node in group.Take(4))
            {
                attempts++;
                var success = await ProbeNodeAsync(node, directIp);
                if (success) { Console.WriteLine($"PASS: {group.Key} HTTPS + VPN egress differs (attempt {attempts})"); return node; }
            }
            Console.WriteLine($"LIMIT: {group.Key} no working endpoint among {attempts} checked");
            return (VpnNode?)null;
        }));
        var available = checks.OfType<VpnNode>().ToArray();
        if (available.Length == 0) throw new Exception("No working VPN endpoint verified.");
        return available;
    }

    private static string TraceIp(string trace) => trace.Split('\n').FirstOrDefault(line => line.StartsWith("ip=", StringComparison.Ordinal)) ?? throw new Exception("Trace response malformed.");

    private static async Task<bool> ProbeNodeAsync(VpnNode node, string directIp)
    {
        var directory = Path.Combine(PrivateStorage.Root, "test-" + Guid.NewGuid().ToString("N"));
        PrivateStorage.SecureDirectory(directory);
        var config = Path.Combine(directory, "config.json");
        using var listener = new TcpListener(IPAddress.Loopback, 0); listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port; listener.Stop();
        Process? process = null;
        Task? drains = null;
        var diagnostics = new HashSet<string>();
        var stage = "startup";
        try
        {
            node = await EndpointResolver.ResolvePublicAsync(node, CancellationToken.None);
            await File.WriteAllTextAsync(config, ConfigBuilder.Build(node, false, port));
            using var binary = BinaryTrust.OpenVerifiedCore();
            process = Process.Start(StartInfo(config, directory, "run")) ?? throw new Exception("Probe failed to start.");
            drains = Task.WhenAll(ClassifyAsync(process.StandardOutput, diagnostics), ClassifyAsync(process.StandardError, diagnostics));
            for (var attempt = 0; attempt < 30; attempt++)
            {
                if (process.HasExited) { if (drains != null) await drains; lock (diagnostics) Console.WriteLine($"Probe {node.Protocol}: startup exit={process.ExitCode}, flags={string.Join(',', diagnostics)}"); return false; }
                using var socket = new TcpClient();
                try { await socket.ConnectAsync(IPAddress.Loopback, port); break; }
                catch (SocketException) { await Task.Delay(100); }
            }
            using var client = new HttpClient(new HttpClientHandler { Proxy = new WebProxy($"socks5://127.0.0.1:{port}"), UseProxy = true, AllowAutoRedirect = false }) { Timeout = TimeSpan.FromSeconds(18) };
            stage = "https-204";
            using var response = await client.GetAsync("https://www.gstatic.com/generate_204");
            if (response.StatusCode != HttpStatusCode.NoContent) { Console.WriteLine($"Probe {node.Protocol}: unexpected HTTP {(int)response.StatusCode}"); return false; }
            stage = "egress";
            var trace = await client.GetStringAsync("https://www.cloudflare.com/cdn-cgi/trace");
            return TraceIp(trace) != directIp;
        }
        catch (Exception e) when (e is HttpRequestException or TaskCanceledException or SocketException or IOException or FormatException)
        {
            lock (diagnostics) Console.WriteLine($"Probe {node.Protocol}: stage={stage}, error={e.GetType().Name}, flags={string.Join(',', diagnostics)}");
            return false;
        }
        finally
        {
            if (process != null) { if (!process.HasExited) process.Kill(true); await process.WaitForExitAsync(); if (drains != null) await drains; process.Dispose(); }
            File.Delete(config); Directory.Delete(directory, false);
        }
    }

    private static async Task DiscardAsync(StreamReader stream)
    { var chars = new char[2048]; while (await stream.ReadAsync(chars) > 0) { } }

    private static async Task ClassifyAsync(StreamReader stream, HashSet<string> flags)
    {
        var chars = new char[2048]; int count;
        var known = new[] { "deadline", "timeout", "certificate", "refused", "unreachable", "reset", "EOF", "no such host", "handshake", "loopback", "permission", "started", "exchange failed", "detour", "empty direct outbound", "access is denied", "FATAL", "decode config", "DNS", "interface", "Wintun", "outbound", "deprecated" };
        while ((count = await stream.ReadAsync(chars)) > 0)
        { var text = new string(chars, 0, count); lock (flags) foreach (var flag in known) if (text.Contains(flag, StringComparison.OrdinalIgnoreCase)) flags.Add(flag); }
    }

    private static ProcessStartInfo StartInfo(string config, string directory, string command)
    {
        var info = new ProcessStartInfo(BinaryTrust.CorePath) { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true, WorkingDirectory = directory };
        info.ArgumentList.Add(command); info.ArgumentList.Add("-c"); info.ArgumentList.Add(config); info.ArgumentList.Add("-D"); info.ArgumentList.Add(directory);
        return info;
    }
}
