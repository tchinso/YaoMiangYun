using System.IO.Pipes;
using System.Net.NetworkInformation;
using System.Text;
using System.Threading.Channels;
using System.Runtime.InteropServices;
using System.Security.Principal;
using Microsoft.Win32.SafeHandles;
using YaoVpn.Core;

namespace YaoVpn.App.Services;

internal static class Broker
{
    public static async Task<int> RunAsync(string pipeName, int parentPid)
    {
        // CurrentUserOnly on the CLIENT compares elevation-level token owners and rejects the ordinary UI.
        // The server retains its user-only ACL; additionally authenticate its process and ACL owner here.
        await using var pipe = new NamedPipeClientStream(".", pipeName, PipeDirection.InOut, PipeOptions.Asynchronous);
        string? session = null;
        var stage = "ipc";
        var trafficQueue = Channel.CreateBounded<TrafficRecord>(new BoundedChannelOptions(256)
        { FullMode = BoundedChannelFullMode.DropOldest, SingleReader = true, SingleWriter = false });
        using var trafficLifetime = new CancellationTokenSource();
        Task? trafficSender = null;
        async Task StopTrafficAsync()
        {
            trafficQueue.Writer.TryComplete();
            if (trafficSender == null) return;
            try { await trafficSender.WaitAsync(TimeSpan.FromSeconds(3)); }
            catch (TimeoutException)
            {
                // Never write a terminal frame after interrupting a partial traffic frame.
                trafficLifetime.Cancel();
                pipe.Dispose();
                await trafficSender;
            }
            trafficSender = null;
        }
        try
        {
            using var startup = new CancellationTokenSource(TimeSpan.FromSeconds(45));
            await pipe.ConnectAsync(startup.Token);
            if (!GetNamedPipeServerProcessId(pipe.SafePipeHandle, out var serverPid) || serverPid != parentPid)
                throw new UnauthorizedAccessException("Unexpected UI process.");
            var owner = pipe.GetAccessControl().GetOwner(typeof(SecurityIdentifier));
            var identity = WindowsIdentity.GetCurrent();
            if (!Equals(owner, identity.User) && !Equals(owner, identity.Owner))
                throw new UnauthorizedAccessException("Unexpected pipe owner.");
            var request = await PipeProtocol.ReadAsync(pipe, startup.Token);
            if (request.Kind != "connect" || request.Node == null) return 2;
            var node = SubscriptionParser.Revalidate(request.Node);
            var policy = RoutingPolicy.Validate(request.Policy);
            stage = "endpoint";
            node = await EndpointResolver.ResolvePublicAsync(node, startup.Token);
            stage = "storage";
            PrivateStorage.SecureDirectory(PrivateStorage.Root);
            await using var singleton = new FileStream(Path.Combine(PrivateStorage.Root, "broker.lock"), FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);
            if (NetworkInterface.GetAllNetworkInterfaces().Any(n => n.Name == "YaoVPN" && n.OperationalStatus == OperationalStatus.Up))
                throw new IOException("Adapter already in use.");
            session = Path.Combine(PrivateStorage.Root, "session-" + Guid.NewGuid().ToString("N"));
            PrivateStorage.SecureDirectory(session);
            var path = Path.Combine(session, "config.json");
            // Deny both writes and deletion from the initial creation through the child lifetime.
            await using var configLock = new FileStream(path, FileMode.CreateNew, FileAccess.ReadWrite, FileShare.Read);
            await configLock.WriteAsync(Encoding.UTF8.GetBytes(ConfigBuilder.Build(node, true, policy: policy)), startup.Token);
            await configLock.FlushAsync(startup.Token);
            using var coreLock = BinaryTrust.OpenVerifiedCore();
            stage = "core";
            await using (var core = await CoreProcess.StartAsync(path, session, startup.Token, record => trafficQueue.Writer.TryWrite(record)))
            {
                stage = "routes";
                if (!TunnelHealth.HasRoutes())
                    throw new IOException("Tunnel not ready.");
                stage = "running";
                await PipeProtocol.WriteAsync(pipe, new("started"), startup.Token);
                trafficSender = SendTrafficAsync(pipe, trafficQueue.Reader, trafficLifetime.Token);
                using var stopRead = new CancellationTokenSource();
                var command = PipeProtocol.ReadAsync(pipe, stopRead.Token);
                var finished = await Task.WhenAny(command, core.Exit);
                if (finished == command)
                {
                    // Any disconnect/unknown command stops the child; no arbitrary elevated operations.
                    try { await command; } catch (IOException) { }
                }
                else
                {
                    stopRead.Cancel();
                    try { await command; } catch (Exception e) when (e is OperationCanceledException or IOException) { }
                }
            }
            await StopTrafficAsync();
            var stillUp = NetworkInterface.GetAllNetworkInterfaces().Any(n => n.Name == "YaoVPN" && n.OperationalStatus == OperationalStatus.Up);
            try { await PipeProtocol.WriteAsync(pipe, new(stillUp ? "cleanup-warning" : "stopped")); }
            catch (Exception error) when (error is IOException or ObjectDisposedException) { }
            return stillUp ? 3 : 0;
        }
        catch
        {
            await StopTrafficAsync();
            try { if (pipe.IsConnected) await PipeProtocol.WriteAsync(pipe, new("failed-" + stage)); }
            catch (Exception error) when (error is IOException or ObjectDisposedException) { }
            return 1;
        }
        finally
        {
            await StopTrafficAsync();
            if (session != null)
            {
                // Only this broker's exact randomly-created session; never sweep/delete other sessions.
                try { File.Delete(Path.Combine(session, "config.json")); Directory.Delete(session, false); } catch (IOException) { } catch (UnauthorizedAccessException) { }
            }
        }
    }

    private static async Task SendTrafficAsync(NamedPipeClientStream pipe, ChannelReader<TrafficRecord> records, CancellationToken token)
    {
        try
        {
            await foreach (var record in records.ReadAllAsync(token))
            {
                using var writeTimeout = CancellationTokenSource.CreateLinkedTokenSource(token);
                writeTimeout.CancelAfter(TimeSpan.FromSeconds(3));
                await PipeProtocol.WriteAsync(pipe, new("traffic", Traffic: record), writeTimeout.Token);
            }
        }
        catch (Exception error) when (error is IOException or ObjectDisposedException or OperationCanceledException)
        {
            // A blocked/disconnected UI must stop the elevated tunnel, never block core stdout.
            if (!token.IsCancellationRequested) pipe.Dispose();
        }
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetNamedPipeServerProcessId(SafePipeHandle pipe, out uint processId);
}
