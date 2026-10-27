using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using System.Text;
using YaoVpn.App.Services;
using YaoVpn.Core;

namespace YaoVpn.Tests;

/// <summary>Real HTTPS egress and routing evidence through a non-admin loopback SOCKS listener.</summary>
internal static class RoutingIntegrationTests
{
    private const string TargetHost = "www.cloudflare.com";
    private const string TraceUrl = "https://www.cloudflare.com/cdn-cgi/trace";
    private const int MaximumTraceBytes = 8192;
    private const int MaximumConfigBytes = 128 * 1024;

    internal static async Task RunAsync(VpnNode workingNode)
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromMinutes(3));
        var scenario = "public-endpoint";
        try
        {
            workingNode = await EndpointResolver.ResolvePublicAsync(workingNode, timeout.Token);
            scenario = "direct-baseline";
            // The pinned public socket handler prefers IPv4, matching the core's
            // prefer_ipv4 DNS strategy so a direct IPv6 address cannot skew comparison.
            using var baselineHandler = EndpointResolver.CreateSubscriptionHandler();
            using var baselineClient = new HttpClient(baselineHandler) { Timeout = TimeSpan.FromSeconds(20) };
            var baselineIp = await ReadTraceIpAsync(baselineClient, timeout.Token);
            var scenarios = new[]
            {
                new Scenario("vpn-default-direct-site", new("vpn", [], ["cloudflare.com"]), "direct"),
                new Scenario("direct-default-vpn-site", new("direct", ["cloudflare.com"], []), "vpn"),
                new Scenario("specific-vpn-child", new("vpn", [TargetHost], ["cloudflare.com"]), "vpn")
            };
            foreach (var item in scenarios)
            {
                scenario = item.Name;
                await RunScenarioAsync(workingNode, item, baselineIp, timeout.Token);
                Console.WriteLine($"PASS: split routing {item.Name}; HTTPS egress and actual route metadata");
            }
        }
        catch
        {
            // Even HTTP/core exceptions may contain endpoint credentials or peer data.
            // The caller receives only an application-owned, fixed scenario label.
            throw new InvalidOperationException("Routing integration failed: " + scenario + ".");
        }
    }

    private static async Task RunScenarioAsync(VpnNode node, Scenario scenario, string baselineIp, CancellationToken token)
    {
        PrivateStorage.SecureDirectory(PrivateStorage.Root);
        var directory = Path.Combine(PrivateStorage.Root, "routing-test-" + Guid.NewGuid().ToString("N"));
        PrivateStorage.SecureDirectory(directory);
        var configPath = Path.Combine(directory, "config.json");
        Process? process = null;
        Task? drains = null;
        FileStream? configLock = null;
        FileStream? coreLock = null;
        try
        {
            using var listener = new TcpListener(IPAddress.Loopback, 0);
            listener.Start();
            var port = ((IPEndPoint)listener.LocalEndpoint).Port;
            listener.Stop();
            var config = Encoding.UTF8.GetBytes(ConfigBuilder.Build(node, false, port, scenario.Policy));
            if (config.Length > MaximumConfigBytes) throw new IOException();
            configLock = new FileStream(configPath, FileMode.CreateNew, FileAccess.ReadWrite, FileShare.Read);
            try
            {
                await configLock.WriteAsync(config, token);
                await configLock.FlushAsync(token);
            }
            finally { System.Security.Cryptography.CryptographicOperations.ZeroMemory(config); }

            coreLock = BinaryTrust.OpenVerifiedCore();
            var start = CoreProcess.CreateStartInfo(configPath, directory);
            start.CreateNoWindow = true;
            var started = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            var observed = new TaskCompletionSource<TrafficRecord>(TaskCreationOptions.RunContinuationsAsynchronously);
            var parser = new TrafficLogParser();
            process = Process.Start(start) ?? throw new IOException();
            drains = Task.WhenAll(
                DrainAsync(process.StandardOutput, parser, started, observed),
                DrainAsync(process.StandardError, parser, started, observed));
            using var startup = CancellationTokenSource.CreateLinkedTokenSource(token);
            startup.CancelAfter(TimeSpan.FromSeconds(12));
            await Task.WhenAny(started.Task, process.WaitForExitAsync()).WaitAsync(startup.Token);
            if (!started.Task.IsCompletedSuccessfully || process.HasExited) throw new IOException();

            using var handler = new HttpClientHandler
            {
                Proxy = new WebProxy($"socks5://127.0.0.1:{port}"),
                UseProxy = true,
                AllowAutoRedirect = false
            };
            using var client = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(25) };
            var actualIp = await ReadTraceIpAsync(client, token);
            if ((actualIp == baselineIp) != (scenario.ExpectedRoute == "direct")) throw new IOException();
            var record = await observed.Task.WaitAsync(TimeSpan.FromSeconds(3), token);
            if (record.Route != scenario.ExpectedRoute || process.HasExited) throw new IOException();
        }
        finally
        {
            // No TUN routes are created. Always terminate the exact child process tree,
            // consume/discard both pipes and release file locks before removing secrets.
            try
            {
                if (process != null)
                {
                    try
                    {
                        if (!process.HasExited) process.Kill(entireProcessTree: true);
                        await process.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(8));
                        if (drains != null) await drains.WaitAsync(TimeSpan.FromSeconds(5));
                    }
                    finally { process.Dispose(); }
                }
            }
            finally
            {
                coreLock?.Dispose();
                if (configLock != null) await configLock.DisposeAsync();
                try { File.Delete(configPath); }
                finally { Directory.Delete(directory, recursive: false); }
            }
        }
    }

    private static async Task<string> ReadTraceIpAsync(HttpClient client, CancellationToken token)
    {
        using var responseTimeout = CancellationTokenSource.CreateLinkedTokenSource(token);
        responseTimeout.CancelAfter(TimeSpan.FromSeconds(25));
        token = responseTimeout.Token;
        using var request = new HttpRequestMessage(HttpMethod.Get, TraceUrl);
        request.Headers.CacheControl = new() { NoCache = true, NoStore = true };
        using var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, token);
        if (!response.IsSuccessStatusCode || response.Content.Headers.ContentLength > MaximumTraceBytes) throw new IOException();
        await using var stream = await response.Content.ReadAsStreamAsync(token);
        using var output = new MemoryStream();
        var buffer = new byte[1024];
        int count;
        while ((count = await stream.ReadAsync(buffer, token)) > 0)
        {
            if (output.Length + count > MaximumTraceBytes) throw new IOException();
            output.Write(buffer, 0, count);
        }
        return IpVerification.ParseTrace(new UTF8Encoding(false, true).GetString(output.ToArray())) ?? throw new IOException();
    }

    private static async Task DrainAsync(StreamReader stream, TrafficLogParser parser, TaskCompletionSource started,
        TaskCompletionSource<TrafficRecord> observed)
    {
        // Never retain raw diagnostics or use ReadLine: a malicious peer can produce
        // unbounded lines, credential-bearing messages or terminal control sequences.
        var buffer = new char[1024];
        var line = new StringBuilder(2048);
        var overflow = false;
        int count;
        while ((count = await stream.ReadAsync(buffer)) > 0)
        {
            for (var i = 0; i < count; i++)
            {
                if (buffer[i] == '\n')
                {
                    if (!overflow)
                    {
                        var text = line.ToString().TrimEnd('\r');
                        if (text.Contains("sing-box started", StringComparison.Ordinal)) started.TrySetResult();
                        var record = parser.Parse(text);
                        if (record is { Host: TargetHost, Port: 443, Network: "TCP" }) observed.TrySetResult(record);
                    }
                    line.Clear();
                    overflow = false;
                }
                else if (!overflow)
                {
                    if (line.Length >= 2048) { line.Clear(); overflow = true; }
                    else line.Append(buffer[i]);
                }
            }
        }
    }

    private sealed record Scenario(string Name, RoutingPolicy Policy, string ExpectedRoute);
}
