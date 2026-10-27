using System.Buffers.Binary;
using System.Text;
using YaoVpn.App.Services;
using YaoVpn.Core;

namespace YaoVpn.Tests;

internal static class ServiceLifecycleTests
{
    public static async Task RunAsync()
    {
        // A window may close while OFF and multiple owners may release it together.
        // Cleanup must stay idempotent, and queued work must never reuse a closed service.
        var service = new VpnService();
        await Task.WhenAll(Enumerable.Range(0, 8).Select(_ => service.DisposeAsync().AsTask()));
        await service.DisposeAsync();
        await service.DisconnectAsync();
        if (service.Status.State != "OFF" || service.Status.IsConnected || service.ActiveServerId != null)
            throw new Exception("Disposed service retained an active connection.");
        try
        {
            await service.SaveRoutingPolicyAsync(RoutingPolicy.SelectedSites);
            throw new Exception("Disposed service accepted new work.");
        }
        catch (ObjectDisposedException) { }

        foreach (var json in new[] { "{", "null", "{}", "{\"Kind\":\"\"}", "{\"Kind\":1}", "{\"Kind\":\"stop\\ncredential-marker\"}" })
        {
            using var stream = new MemoryStream();
            var payload = Encoding.UTF8.GetBytes(json);
            var header = new byte[4];
            BinaryPrimitives.WriteInt32LittleEndian(header, payload.Length);
            stream.Write(header); stream.Write(payload); stream.Position = 0;
            try { await PipeProtocol.ReadAsync(stream); throw new Exception("Malformed IPC was accepted."); }
            catch (IOException error)
            {
                if (error.Message.Contains("credential-marker", StringComparison.Ordinal))
                    throw new Exception("Malformed IPC exposed peer content.");
            }
        }
        Console.WriteLine("PASS: idempotent service shutdown, disposed-work rejection, malformed IPC recovery boundary");
    }
}
