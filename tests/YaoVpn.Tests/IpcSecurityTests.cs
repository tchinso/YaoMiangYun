using System.Buffers.Binary;
using YaoVpn.App.Services;

namespace YaoVpn.Tests;

internal static class IpcSecurityTests
{
    public static async Task RunAsync()
    {
        // Force header/body writes to yield, exposing frame corruption without the
        // per-stream writer lock when startup, traffic and stop messages race.
        using var stream = new YieldingStream();
        await Task.WhenAll(Enumerable.Range(1, 128).Select(port => PipeProtocol.WriteAsync(stream,
            new("traffic", Traffic: new(DateTimeOffset.UnixEpoch, "example.com", port, "TCP", "vpn")))));
        stream.Position = 0;
        var seen = new HashSet<int>();
        while (stream.Position < stream.Length)
        {
            var message = await PipeProtocol.ReadAsync(stream);
            if (message.Kind != "traffic" || message.Traffic == null || !seen.Add(message.Traffic.Port))
                throw new InvalidOperationException("Concurrent IPC frame was lost or corrupted.");
        }
        if (seen.Count != 128) throw new InvalidOperationException("Concurrent IPC frame count mismatch.");

        using var cancelled = new MemoryStream();
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();
        try { await PipeProtocol.WriteAsync(cancelled, new("stop"), cancellation.Token); throw new InvalidOperationException("Cancelled IPC write accepted."); }
        catch (OperationCanceledException) { }
        if (cancelled.Length != 0) throw new InvalidOperationException("Cancelled IPC write emitted a partial header.");

        foreach (var length in new[] { -1, 0, 32769, int.MaxValue })
        {
            var header = new byte[4];
            BinaryPrimitives.WriteInt32LittleEndian(header, length);
            using var invalid = new MemoryStream(header);
            try { await PipeProtocol.ReadAsync(invalid); throw new InvalidOperationException("Unsafe IPC length accepted."); }
            catch (IOException) { }
        }
        using var truncated = new MemoryStream(new byte[] { 5, 0, 0, 0, (byte)'{' });
        try { await PipeProtocol.ReadAsync(truncated); throw new InvalidOperationException("Truncated IPC frame accepted."); }
        catch (EndOfStreamException) { }
    }

    private sealed class YieldingStream : MemoryStream
    {
        public override async ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
        {
            await Task.Yield();
            await base.WriteAsync(buffer, cancellationToken);
        }
    }
}
