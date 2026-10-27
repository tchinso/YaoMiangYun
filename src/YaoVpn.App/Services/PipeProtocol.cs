using System.Buffers.Binary;
using System.Text.Json;
using YaoVpn.Core;

namespace YaoVpn.App.Services;

internal sealed record PipeMessage(string Kind, VpnNode? Node = null);

internal static class PipeProtocol
{
    private const int MaximumBytes = 32768;
    public static async Task WriteAsync(Stream stream, PipeMessage message, CancellationToken token = default)
    {
        var bytes = JsonSerializer.SerializeToUtf8Bytes(message);
        if (bytes.Length > MaximumBytes) throw new IOException("Message too large.");
        var header = new byte[4];
        BinaryPrimitives.WriteInt32LittleEndian(header, bytes.Length);
        await stream.WriteAsync(header, token);
        await stream.WriteAsync(bytes, token);
        await stream.FlushAsync(token);
    }
    public static async Task<PipeMessage> ReadAsync(Stream stream, CancellationToken token = default)
    {
        var header = new byte[4];
        await stream.ReadExactlyAsync(header, token);
        var length = BinaryPrimitives.ReadInt32LittleEndian(header);
        if (length is <= 0 or > MaximumBytes) throw new IOException("Invalid message size.");
        var buffer = new byte[length];
        await stream.ReadExactlyAsync(buffer, token);
        return JsonSerializer.Deserialize<PipeMessage>(buffer, new JsonSerializerOptions { MaxDepth = 16 })
            ?? throw new IOException("Invalid message.");
    }
}
