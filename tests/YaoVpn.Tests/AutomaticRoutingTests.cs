using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Threading.Channels;
using YaoVpn.App.Services;
using YaoVpn.Core;

namespace YaoVpn.Tests;

internal static class AutomaticRoutingTests
{
    public static async Task RunAsync()
    {
        if (VpnService.ReadSavedRoutingPolicy(null).DefaultRoute != "auto") throw new Exception("Automatic routing is not the default.");
        var legacy = VpnService.ReadSavedRoutingPolicy("""{"DefaultRoute":"direct","VpnDomains":["saved.example"],"DirectDomains":[]}""");
        if (legacy.DefaultRoute != "auto" || legacy.VpnDomains.Single() != "saved.example") throw new Exception("Legacy routing migration lost rules or the new default.");
        if (VpnService.ReadSavedRoutingPolicy(JsonSerializer.Serialize(RoutingPolicy.SelectedSites)).DefaultRoute != "direct")
            throw new Exception("A manually saved routing mode was overwritten.");
        if (AutomaticRoutingSession.LearningDuration != TimeSpan.FromMinutes(2)) throw new Exception("Incorrect learning duration.");
        await VerifyLearningAsync();
        await VerifyCoreReloadAsync();
        Console.WriteLine("PASS: automatic default/migration, independent learning, freeze/cancel, pinned-core live routing switch without restart");
    }

    private static async Task VerifyLearningAsync()
    {
        var directory = Path.Combine(PrivateStorage.Root, "test-auto-" + Guid.NewGuid().ToString("N"));
        PrivateStorage.SecureDirectory(directory);
        var path = Path.Combine(directory, ConfigBuilder.AutomaticRuleFile);
        try
        {
            var policy = new RoutingPolicy("auto", ["saved.example"], ["direct.example"]);
            await using (var automatic = AutomaticRoutingSession.Create(directory, policy, TimeSpan.FromMilliseconds(100))!)
            {
                for (var i = 0; i < 350; i++) automatic.Observe(Record($"d{i}.deep.example.com"));
                automatic.Observe(Record("192.0.2.1"));
                automatic.Observe(Record("invalid"));
                automatic.Start();
                await automatic.Completion.WaitAsync(TimeSpan.FromSeconds(5));
                if (automatic.Failure.IsCompleted) throw new Exception("Automatic rules could not be published.");
                var contents = await File.ReadAllTextAsync(path);
                using var doc = JsonDocument.Parse(contents);
                var domains = doc.RootElement.GetProperty("rules")[0].GetProperty("domain_suffix").EnumerateArray().Select(d => d.GetString()).ToArray();
                if (domains.Length != 352 || !domains.Contains("d0.deep.example.com") || !domains.Contains("d349.deep.example.com")
                    || !domains.Contains("saved.example") || !domains.Contains("direct.example"))
                    throw new Exception("Learning discarded full hostnames, saved domains, or traffic beyond the UI log limit.");
                automatic.Observe(Record("late.example"));
                if (await File.ReadAllTextAsync(path) != contents) throw new Exception("Learning continued after the cutoff.");
            }
            File.Delete(path);
            await using (var cancelled = AutomaticRoutingSession.Create(directory, RoutingPolicy.Automatic)!)
            {
                cancelled.Start();
                await cancelled.DisposeAsync();
                if (await File.ReadAllTextAsync(path) != AutomaticRoutingSession.LearningRules || cancelled.Failure.IsCompleted)
                    throw new Exception("Disconnect did not cancel the learning timer cleanly.");
            }
            File.Delete(path);
            await using (var empty = AutomaticRoutingSession.Create(directory, RoutingPolicy.Automatic, TimeSpan.Zero)!)
            {
                empty.Start();
                await empty.Completion;
                using var doc = JsonDocument.Parse(await File.ReadAllTextAsync(path));
                if (doc.RootElement.GetProperty("rules").GetArrayLength() != 0 || empty.Failure.IsCompleted)
                    throw new Exception("Empty learning did not switch to a direct default.");
            }
            File.Delete(path);
            await using (var failed = AutomaticRoutingSession.Create(directory, RoutingPolicy.Automatic, TimeSpan.FromMilliseconds(20))!)
            {
                Directory.CreateDirectory(path + ".next");
                try
                {
                    failed.Start();
                    await failed.Completion.WaitAsync(TimeSpan.FromSeconds(5));
                    if (!failed.Failure.IsCompleted || await File.ReadAllTextAsync(path) != AutomaticRoutingSession.LearningRules)
                        throw new Exception("A failed transition did not signal shutdown while preserving the complete old rules.");
                }
                finally { Directory.Delete(path + ".next"); }
            }
        }
        finally { File.Delete(path); Directory.Delete(directory, false); }
    }

    private static TrafficRecord Record(string host) => new(DateTimeOffset.Now, host, 443, "TCP", "vpn");

    private static async Task VerifyCoreReloadAsync()
    {
        // Exercise the real core and generated routing on loopback only: no UAC, system proxy, TUN, or provider.
        var directory = Path.Combine(PrivateStorage.Root, "test-auto-core-" + Guid.NewGuid().ToString("N"));
        PrivateStorage.SecureDirectory(directory);
        var configPath = Path.Combine(directory, "config.json");
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        using var endpoint = new TcpListener(IPAddress.Loopback, 0);
        using var reservation = new TcpListener(IPAddress.Loopback, 0);
        endpoint.Start(); reservation.Start();
        var port = ((IPEndPoint)reservation.LocalEndpoint).Port;
        var destinationPort = ((IPEndPoint)endpoint.LocalEndpoint).Port;
        Process? process = null;
        Task? drains = null;
        AutomaticRoutingSession? automatic = null;
        var stage = "startup";
        var diagnostics = new StringBuilder();
        try
        {
            var node = SubscriptionParser.Parse("""[{"type":"anytls","server":"example.com","server_port":443,"password":"fixture","tls":{"enabled":true}}]""").Nodes.Single();
            var policy = new RoutingPolicy("auto", ["saved.example"], ["direct.example"]);
            automatic = AutomaticRoutingSession.Create(directory, policy, TimeSpan.FromSeconds(3))!;
            var config = JsonNode.Parse(ConfigBuilder.Build(node, true, port, policy))!;
            config["inbounds"]!.AsArray().RemoveAt(0); // Keep the mixed listener; never create the TUN adapter.
            config["outbounds"]![0] = new JsonObject { ["type"] = "direct", ["tag"] = "vpn", ["connect_timeout"] = "2s" };
            config["route"]!.AsObject().Remove("auto_detect_interface");
            if (config["dns"]!["final"]!.GetValue<string>() != "bootstrap"
                || config["dns"]!["rules"]![1]!["rule_set"]![0]!.GetValue<string>() != ConfigBuilder.AutomaticRuleTag
                || config["dns"]!["rules"]![1]!["server"]!.GetValue<string>() != "secure-dns")
                throw new Exception("Automatic DNS did not share the learned routing set.");
            await File.WriteAllTextAsync(configPath, config.ToJsonString(), timeout.Token);
            var start = CoreProcess.CreateStartInfo(configPath, directory);
            start.CreateNoWindow = true;
            using var binary = BinaryTrust.OpenVerifiedCore();
            reservation.Stop();
            process = Process.Start(start) ?? throw new Exception("Automatic routing test core failed to start.");
            var ready = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            var records = Channel.CreateUnbounded<TrafficRecord>();
            var parser = new TrafficLogParser();
            async Task DrainAsync(StreamReader reader)
            {
                while (await reader.ReadLineAsync(timeout.Token) is { } line)
                {
                    lock (diagnostics) if (diagnostics.Length < 6000) diagnostics.AppendLine(line);
                    if (line.Contains("sing-box started", StringComparison.Ordinal)) ready.TrySetResult();
                    TrafficRecord? record;
                    lock (parser) record = parser.Parse(line);
                    if (record == null) continue;
                    automatic.Observe(record);
                    records.Writer.TryWrite(record);
                }
            }
            drains = Task.WhenAll(DrainAsync(process.StandardOutput), DrainAsync(process.StandardError));
            await ready.Task.WaitAsync(timeout.Token);
            automatic.Start();
            stage = "initial request";

            async Task<string> RequestAsync(string host)
            {
                using var client = new TcpClient();
                await client.ConnectAsync(IPAddress.Loopback, port, timeout.Token);
                var stream = client.GetStream();
                await stream.WriteAsync(new byte[] { 5, 1, 0 }, timeout.Token);
                var auth = new byte[2]; await stream.ReadExactlyAsync(auth, timeout.Token);
                await stream.WriteAsync(new byte[] { 5, 1, 0, 1, 127, 0, 0, 1, (byte)(destinationPort >> 8), (byte)destinationPort }, timeout.Token);
                var reply = new byte[10]; await stream.ReadExactlyAsync(reply, timeout.Token);
                if (reply[1] != 0) throw new Exception("Test SOCKS connect failed.");
                await stream.WriteAsync(Encoding.ASCII.GetBytes($"GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"), timeout.Token);
                using var accepted = await endpoint.AcceptTcpClientAsync(timeout.Token);
                var request = new byte[1024];
                _ = await accepted.GetStream().ReadAsync(request, timeout.Token);
                await accepted.GetStream().WriteAsync("HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"u8.ToArray(), timeout.Token);
                var record = await records.Reader.ReadAsync(timeout.Token);
                if (record.Host != host) throw new Exception("The core did not preserve sniffed domain metadata.");
                return record.Route;
            }

            if (await RequestAsync("learned.example") != "vpn") throw new Exception("Automatic warmup was not full VPN.");
            if (await RequestAsync("127.0.0.1") != "vpn") throw new Exception("IP-only traffic bypassed automatic warmup.");
            await automatic.Completion.WaitAsync(timeout.Token);
            stage = "reload";
            if (automatic.Failure.IsCompleted) throw new Exception("Automatic file transition failed.");
            // File watchers reload asynchronously. Observe the switch with new connections, not a restart.
            var switched = false;
            for (var i = 0; i < 30; i++)
            {
                if (await RequestAsync("unseen.example") == "direct") { switched = true; break; }
                await Task.Delay(100, timeout.Token);
            }
            if (!switched) throw new Exception("Pinned core did not reload the learned policy.");
            stage = "learned requests";
            foreach (var host in new[] { "learned.example", "saved.example", "direct.example", "child.learned.example" })
                if (await RequestAsync(host) != "vpn") throw new Exception("Learned or saved domains did not retain VPN routing.");
            if (await RequestAsync("still-unseen.example") != "direct") throw new Exception("Unknown domains were learned after the cutoff.");
            if (await RequestAsync("127.0.0.1") != "direct") throw new Exception("IP-only traffic did not use the direct default after learning.");
            if (process.HasExited) throw new Exception("The core exited during automatic route transition.");
        }
        catch (OperationCanceledException)
        {
            throw new Exception($"Automatic routing fixture timed out at {stage}: {diagnostics}");
        }
        finally
        {
            if (automatic != null) await automatic.DisposeAsync();
            if (process != null)
            {
                if (!process.HasExited) process.Kill(true);
                await process.WaitForExitAsync();
                if (drains != null) { try { await drains; } catch (OperationCanceledException) { } }
                process.Dispose();
            }
            File.Delete(configPath);
            File.Delete(Path.Combine(directory, ConfigBuilder.AutomaticRuleFile));
            Directory.Delete(directory, false);
        }
    }
}
