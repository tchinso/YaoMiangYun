using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using YaoVpn.App.Services;
using YaoVpn.Core;

namespace YaoVpn.Tests;

/// <summary>Targeted follow-up for the untested AnyTLS endpoints; never prints provider data.</summary>
internal static class AnyTlsDiagnostics
{
    internal static async Task RunAsync()
    {
        var saved = PrivateStorage.Load("subscription.dpapi") ?? throw new IOException("AnyTLS diagnostic cache unavailable.");
        using var document = JsonDocument.Parse(saved);
        var nodes = SubscriptionParser.Parse(document.RootElement.GetProperty("Json").GetString() ?? "")
            .Nodes.Where(node => node.Protocol == "anytls").ToArray();
        using var overall = new CancellationTokenSource(TimeSpan.FromMinutes(2));
        var unchanged = 0;
        foreach (var node in nodes)
            if ((await EndpointResolver.ResolvePublicAsync(node, overall.Token)).OutboundJson == node.OutboundJson) unchanged++;
        Console.WriteLine($"AnyTLS diagnostic: nodes={nodes.Length}, pinning-unchanged={unchanged}");
        // The first four distinct endpoints have already failed in the final live run.
        // Reuse that evidence and test only endpoints that were never attempted.
        using var concurrency = new SemaphoreSlim(2, 2);
        var checks = nodes.Skip(4).Select(async (node, index) =>
        {
            await concurrency.WaitAsync(overall.Token);
            try { return await ProbeAsync(node, index + 5, overall.Token); }
            finally { concurrency.Release(); }
        }).ToArray();
        var results = await Task.WhenAll(checks);
        Console.WriteLine($"AnyTLS diagnostic: previously-untested={results.Length}, https-trace-success={results.Count(success => success)}");
    }

    private static async Task<bool> ProbeAsync(VpnNode node, int index, CancellationToken token)
    {
        var directory = Path.Combine(PrivateStorage.Root, "anytls-diagnostic-" + Guid.NewGuid().ToString("N"));
        PrivateStorage.SecureDirectory(directory);
        var configPath = Path.Combine(directory, "config.json");
        Process? process = null;
        Task? drains = null;
        FileStream? configLock = null;
        FileStream? binaryLock = null;
        var flags = new HashSet<string>(StringComparer.Ordinal);
        var success = false;
        var stage = "startup";
        try
        {
            using var listener = new TcpListener(IPAddress.Loopback, 0);
            listener.Start();
            var port = ((IPEndPoint)listener.LocalEndpoint).Port;
            listener.Stop();
            var config = Encoding.UTF8.GetBytes(ConfigBuilder.Build(node, false, port, RoutingPolicy.FullTunnel));
            if (config.Length > 128 * 1024) throw new IOException();
            configLock = new FileStream(configPath, FileMode.CreateNew, FileAccess.ReadWrite, FileShare.Read);
            try { await configLock.WriteAsync(config, token); await configLock.FlushAsync(token); }
            finally { System.Security.Cryptography.CryptographicOperations.ZeroMemory(config); }
            binaryLock = BinaryTrust.OpenVerifiedCore();
            var info = CoreProcess.CreateStartInfo(configPath, directory);
            info.CreateNoWindow = true;
            process = Process.Start(info) ?? throw new IOException();
            drains = Task.WhenAll(ClassifyAsync(process.StandardOutput, flags), ClassifyAsync(process.StandardError, flags));
            for (var attempt = 0; attempt < 30; attempt++)
            {
                if (process.HasExited) throw new IOException();
                using var socket = new TcpClient();
                try { await socket.ConnectAsync(IPAddress.Loopback, port, token); break; }
                catch (SocketException) { await Task.Delay(100, token); }
            }
            using var client = new HttpClient(new HttpClientHandler
            {
                UseProxy = true,
                Proxy = new WebProxy($"socks5://127.0.0.1:{port}"),
                AllowAutoRedirect = false
            }) { Timeout = TimeSpan.FromSeconds(14) };
            stage = "cloudflare-trace";
            using var response = await client.GetAsync("https://www.cloudflare.com/cdn-cgi/trace", HttpCompletionOption.ResponseHeadersRead, token);
            if (!response.IsSuccessStatusCode || response.Content.Headers.ContentLength > 8192) throw new IOException();
            using var readTimeout = CancellationTokenSource.CreateLinkedTokenSource(token);
            readTimeout.CancelAfter(TimeSpan.FromSeconds(14));
            await using var content = await response.Content.ReadAsStreamAsync(readTimeout.Token);
            using var output = new MemoryStream();
            var buffer = new byte[1024]; int count;
            while ((count = await content.ReadAsync(buffer, readTimeout.Token)) > 0)
            {
                if (output.Length + count > 8192) throw new IOException();
                output.Write(buffer, 0, count);
            }
            success = IpVerification.ParseTrace(new UTF8Encoding(false, true).GetString(output.ToArray())) != null;
            if (success) stage = "https-ok";
        }
        catch (Exception exception) when (exception is HttpRequestException or IOException or SocketException or OperationCanceledException)
        {
            lock (flags) flags.Add(exception is HttpRequestException ? "http-failed" : exception is OperationCanceledException ? "timed-out" : "io-failed");
        }
        finally
        {
            try
            {
                if (process != null)
                {
                    try
                    {
                        if (!process.HasExited) process.Kill(true);
                        await process.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(8));
                        if (drains != null) await drains.WaitAsync(TimeSpan.FromSeconds(5));
                    }
                    finally { process.Dispose(); }
                }
            }
            finally
            {
                binaryLock?.Dispose();
                if (configLock != null) await configLock.DisposeAsync();
                try { File.Delete(configPath); }
                finally { Directory.Delete(directory, false); }
            }
        }
        lock (flags) Console.WriteLine($"AnyTLS diagnostic: node-index={index}, stage={stage}, flags={string.Join(',', flags.Order(StringComparer.Ordinal))}");
        return success;
    }

    private static async Task ClassifyAsync(StreamReader reader, HashSet<string> flags)
    {
        var known = new[] { "certificate", "EOF", "unreachable", "deadline", "timeout", "refused", "handshake", "started", "authentication", "password", "session" };
        var buffer = new char[1024];
        var tail = "";
        int count;
        while ((count = await reader.ReadAsync(buffer)) > 0)
        {
            var text = tail + new string(buffer, 0, count);
            lock (flags)
                foreach (var word in known)
                    if (text.Contains(word, StringComparison.OrdinalIgnoreCase)) flags.Add(word);
            tail = text.Length > 32 ? text[^32..] : text;
        }
    }
}
