using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using System.Text.Json.Nodes;
using YaoVpn.Core;

namespace YaoVpn.App.Services;

/// <summary>Resolve once, reject local destinations, then dial the checked address without another DNS lookup.</summary>
internal static class EndpointResolver
{
    public static async Task<VpnNode> ResolvePublicAsync(VpnNode node, CancellationToken cancellationToken)
    {
        node = SubscriptionParser.Revalidate(node);
        var address = await ResolveAddressAsync(node.Server, cancellationToken);
        if (IPAddress.TryParse(node.Server, out _)) return node;
        return PinAddress(node, address);
    }

    internal static VpnNode PinAddress(VpnNode node, IPAddress address)
    {
        node = SubscriptionParser.Revalidate(node);
        if (!SubscriptionParser.IsPublicEndpointAddress(address))
            throw new IOException("The VPN endpoint must use a public address.");
        var outbound = JsonNode.Parse(node.OutboundJson)?.AsObject() ?? throw new FormatException();
        var tls = outbound["tls"]?.AsObject() ?? throw new FormatException();
        // Replacing the dial address must not replace the name used for certificate verification.
        if (tls["server_name"] is null) tls["server_name"] = node.Server;
        // WebSocket's default HTTP Host is the dial authority, independently of SNI.
        // Preserve it before replacing a DNS server name with the checked IP address.
        if (outbound["transport"] is JsonObject transport && transport["type"]?.GetValue<string>() == "ws")
        {
            var headers = transport["headers"]?.AsObject();
            if (headers == null) transport["headers"] = headers = new JsonObject();
            if (headers["Host"] is null)
                headers["Host"] = (node.Server.Contains(':') ? "[" + node.Server + "]" : node.Server)
                    + ":" + node.Port.ToString(System.Globalization.CultureInfo.InvariantCulture);
        }
        outbound["server"] = address.ToString();
        return SubscriptionParser.Revalidate(node with { OutboundJson = outbound.ToJsonString() });
    }

    private static async Task<IPAddress> ResolveAddressAsync(string host, CancellationToken cancellationToken)
    {
        SubscriptionParser.ValidateEndpointHost(host);
        if (IPAddress.TryParse(host, out var literal)) return literal;
        var addresses = await Dns.GetHostAddressesAsync(host, cancellationToken);
        if (addresses.Length == 0 || addresses.Any(ip => !SubscriptionParser.IsPublicEndpointAddress(ip)))
            throw new IOException("The endpoint did not resolve exclusively to public addresses.");
        return addresses.OrderBy(ip => ip.AddressFamily == AddressFamily.InterNetwork ? 0 : 1).First();
    }

    /// <summary>Preserves normal HTTPS validation; only the socket's public destination is pinned.</summary>
    public static SocketsHttpHandler CreateSubscriptionHandler() => new()
    {
        AllowAutoRedirect = false,
        UseProxy = false,
        AutomaticDecompression = DecompressionMethods.GZip | DecompressionMethods.Deflate,
        ConnectTimeout = TimeSpan.FromSeconds(10),
        ConnectCallback = async (context, cancellationToken) =>
        {
            var address = await ResolveAddressAsync(context.DnsEndPoint.Host, cancellationToken);
            var socket = new Socket(address.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
            try
            {
                await socket.ConnectAsync(new IPEndPoint(address, context.DnsEndPoint.Port), cancellationToken);
                return new NetworkStream(socket, ownsSocket: true);
            }
            catch { socket.Dispose(); throw; }
        }
    };
}
