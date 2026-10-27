using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using YaoVpn.App.Services;
using YaoVpn.Core;

namespace YaoVpn.Tests;

/// <summary>Targeted current-subscription evidence. Never changes system proxy/routes or prints provider secrets.</summary>
internal static class JapanDiagnostics
{
    internal static async Task RunAsync()
    {
        var saved = PrivateStorage.Load("subscription.dpapi") ?? throw new IOException("Japan diagnostic cache unavailable.");
        using var cache = JsonDocument.Parse(saved);
        var json = cache.RootElement.GetProperty("Json").GetString() ?? throw new IOException();
        var result = SubscriptionParser.Parse(json);
        var entries = ServerCatalog.Create(result.Nodes);
        var japan = entries.Where(entry => entry.IsConnectable && entry.CountryCode == "JP").ToArray();
        ReportDuplicateLabels(json);
        Console.WriteLine($"JP inventory: connectable={japan.Length}, information={entries.Count(entry => !entry.IsConnectable)}");
        using var overall = new CancellationTokenSource(TimeSpan.FromMinutes(3));
        using var concurrency = new SemaphoreSlim(2, 2);
        var probes = japan.Select(async (entry, index) =>
        {
            await concurrency.WaitAsync(overall.Token);
            try { return await ProbeAsync(entry.Node, index + 1, overall.Token); }
            finally { concurrency.Release(); }
        }).ToArray();
        var countries = await Task.WhenAll(probes);
        Console.WriteLine("JP egress summary: " + string.Join(", ", countries.GroupBy(country => country ?? "unavailable")
            .OrderBy(group => group.Key, StringComparer.Ordinal).Select(group => group.Key + "=" + group.Count())));
    }

    private static void ReportDuplicateLabels(string json)
    {
        using var raw = JsonDocument.Parse(json);
        var outbounds = raw.RootElement.ValueKind == JsonValueKind.Array ? raw.RootElement : raw.RootElement.GetProperty("outbounds");
        var individual = new List<VpnNode>();
        foreach (var item in outbounds.EnumerateArray())
        {
            try { individual.AddRange(SubscriptionParser.Parse("[" + item.GetRawText() + "]").Nodes); }
            catch (FormatException) { }
        }
        var duplicates = individual.GroupBy(node => node.Id).Where(group => group.Count() > 1).ToArray();
        var hidden = duplicates.Count(group => group.Any(node => ServerCatalog.IsInformation(node.DisplayName))
            && group.Any(node => !ServerCatalog.IsInformation(node.DisplayName)));
        var conflicting = duplicates.Select(group => group.Where(node => !ServerCatalog.IsInformation(node.DisplayName))
            .Select(ServerCatalog.GetCountryCode).OfType<string>().Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal).ToArray())
            .Where(countries => countries.Length > 1).ToArray();
        Console.WriteLine($"Subscription duplicate-label audit: duplicate-identities={duplicates.Length}, info-hiding-real={hidden}, conflicting-country-identities={conflicting.Length}");
        if (conflicting.Length > 0) Console.WriteLine("Conflicting provider country labels: " + string.Join(",", conflicting.Select(countries => string.Join('/', countries)).Distinct(StringComparer.Ordinal)));
    }

    private static async Task<string?> ProbeAsync(VpnNode node, int index, CancellationToken token)
    {
        var directory = Path.Combine(PrivateStorage.Root, "japan-diagnostic-" + Guid.NewGuid().ToString("N"));
        PrivateStorage.SecureDirectory(directory);
        var configPath = Path.Combine(directory, "config.json");
        Process? process = null;
        Task? drains = null;
        FileStream? configLock = null;
        FileStream? binaryLock = null;
        string? country = null;
        try
        {
            node = await EndpointResolver.ResolvePublicAsync(node, token);
            using var listener = new TcpListener(IPAddress.Loopback, 0);
            listener.Start();
            var port = ((IPEndPoint)listener.LocalEndpoint).Port;
            listener.Stop();
            var bytes = Encoding.UTF8.GetBytes(ConfigBuilder.Build(node, false, port, new("direct", [], [ConfigBuilder.VpnDiagnosticHost])));
            if (bytes.Length > 128 * 1024) throw new IOException();
            configLock = new FileStream(configPath, FileMode.CreateNew, FileAccess.ReadWrite, FileShare.Read);
            try { await configLock.WriteAsync(bytes, token); await configLock.FlushAsync(token); }
            finally { System.Security.Cryptography.CryptographicOperations.ZeroMemory(bytes); }
            binaryLock = BinaryTrust.OpenVerifiedCore();
            var start = CoreProcess.CreateStartInfo(configPath, directory);
            start.CreateNoWindow = true;
            process = Process.Start(start) ?? throw new IOException();
            var ready = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            drains = Task.WhenAll(DiscardAsync(process.StandardOutput, ready), DiscardAsync(process.StandardError, ready));
            await Task.WhenAny(ready.Task, process.WaitForExitAsync()).WaitAsync(TimeSpan.FromSeconds(12), token);
            if (!ready.Task.IsCompletedSuccessfully || process.HasExited) throw new IOException();
            var observation = await IpVerification.ReadVpnAsync(token, new Uri($"socks5://127.0.0.1:{port}"));
            country = observation?.CountryCode;
            Console.WriteLine($"JP item {index}: protocol={node.Protocol}, country={country ?? "unavailable"}, HTTPS={(observation != null ? "ok" : "failed")}");
        }
        catch (Exception error) when (error is IOException or System.Net.Http.HttpRequestException or OperationCanceledException or SocketException or FormatException)
        { Console.WriteLine($"JP item {index}: protocol={node.Protocol}, country=unavailable, HTTPS=failed"); }
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
                File.Delete(configPath); Directory.Delete(directory, false);
            }
        }
        return country;
    }

    private static async Task DiscardAsync(StreamReader reader, TaskCompletionSource ready)
    {
        var buffer = new char[1024]; var tail = ""; int count;
        while ((count = await reader.ReadAsync(buffer)) > 0)
        {
            var text = tail + new string(buffer, 0, count);
            if (text.Contains("sing-box started", StringComparison.Ordinal)) ready.TrySetResult();
            tail = text.Length > 80 ? text[^80..] : text;
        }
    }
}
