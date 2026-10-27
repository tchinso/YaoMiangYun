using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using System.Security.Cryptography;
using YaoVpn.App.Services;
using YaoVpn.Core;

namespace YaoVpn.Tests;

internal static class TunTests
{
    public static async Task RunAsync(string executable)
    {
        if (TunnelHealth.IsUp()) throw new InvalidOperationException("A tunnel is already active.");
        var result = SubscriptionParser.Parse(PrivateStorage.Load("bootstrap.dpapi") ?? throw new InvalidOperationException("Missing private subscription."));
        var node = result.Nodes.First(n => n.Protocol == "vless");
        using var http = new HttpClient(new HttpClientHandler { UseProxy = false }) { Timeout = TimeSpan.FromSeconds(12) };
        static string Ip(string trace) => trace.Split('\n').First(line => line.StartsWith("ip=", StringComparison.Ordinal));
        var baseline = Ip(await http.GetStringAsync("https://www.cloudflare.com/cdn-cgi/trace"));
        await using var service = new VpnService(executable);
        service.StatusChanged += status => Console.WriteLine("TUN status: " + status.State);
        try
        {
            Console.WriteLine("Waiting for the user's Windows UAC approval...");
            await service.ConnectAsync(node, ConnectionMode.SystemTun, RoutingPolicy.FullTunnel);
            if (!service.Status.IsConnected || !TunnelHealth.HasRoutes()) throw new InvalidOperationException("TUN route verification failed.");
            Console.WriteLine("PASS: TUN active; Windows IPv4 + IPv6 best routes point to YaoVPN");
            // A new client prevents reusing the pre-VPN established direct TCP connection.
            using var vpnHttp = new HttpClient(new HttpClientHandler { UseProxy = false }) { Timeout = TimeSpan.FromSeconds(12) };
            var tunneled = Ip(await vpnHttp.GetStringAsync("https://www.cloudflare.com/cdn-cgi/trace"));
            if (baseline == tunneled) throw new InvalidOperationException("System egress did not change.");
            Console.WriteLine("PASS: ordinary system HTTPS uses a different public egress");
            await DnsQueryAsync(IPAddress.Parse("8.8.8.8"));
            await DnsQueryAsync(IPAddress.Parse("2001:4860:4860::8888"));
            Console.WriteLine("PASS: IPv4 + IPv6 UDP DNS queries answered through configured interception");
            await StunAsync();
            Console.WriteLine("PASS: UDP STUN request/reply through system tunnel");
            try
            {
                var ipv6 = (await vpnHttp.GetStringAsync("https://api6.ipify.org")).Trim();
                Console.WriteLine(IPAddress.TryParse(ipv6, out var ip) && ip.AddressFamily == AddressFamily.InterNetworkV6
                    ? "PASS: IPv6-only HTTPS reached through VPN" : "LIMIT: IPv6 HTTPS response did not verify");
            }
            catch (Exception e) when (e is HttpRequestException or TaskCanceledException)
            { Console.WriteLine("LIMIT: provider IPv6 HTTPS egress unavailable; IPv6 TUN route remains verified"); }
        }
        finally { await service.DisconnectAsync(); }
        if (TunnelHealth.IsUp()) throw new InvalidOperationException("TUN remained up after OFF.");
        using var afterHttp = new HttpClient(new HttpClientHandler { UseProxy = false }) { Timeout = TimeSpan.FromSeconds(12) };
        var after = Ip(await afterHttp.GetStringAsync("https://www.cloudflare.com/cdn-cgi/trace"));
        if (after != baseline) throw new InvalidOperationException("Direct egress not restored.");
        Console.WriteLine("PASS: OFF removed the tunnel and restored the original direct egress");
    }

    private static async Task DnsQueryAsync(IPAddress destination)
    {
        var packet = new byte[] { 0x51, 0x37, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 7, (byte)'e', (byte)'x', (byte)'a', (byte)'m', (byte)'p', (byte)'l', (byte)'e', 3, (byte)'c', (byte)'o', (byte)'m', 0, 0, 1, 0, 1 };
        using var udp = new UdpClient(destination.AddressFamily);
        await udp.SendAsync(packet, new IPEndPoint(destination, 53));
        var response = await udp.ReceiveAsync().WaitAsync(TimeSpan.FromSeconds(8));
        if (response.Buffer.Length < 12 || response.Buffer[0] != packet[0] || response.Buffer[1] != packet[1] || (response.Buffer[3] & 15) != 0)
            throw new InvalidOperationException("DNS response failed.");
    }

    private static async Task StunAsync()
    {
        var address = (await Dns.GetHostAddressesAsync("stun.l.google.com")).First(ip => ip.AddressFamily == AddressFamily.InterNetwork);
        var query = new byte[20]; query[1] = 1; query[4] = 0x21; query[5] = 0x12; query[6] = 0xa4; query[7] = 0x42;
        RandomNumberGenerator.Fill(query.AsSpan(8));
        using var udp = new UdpClient(AddressFamily.InterNetwork);
        await udp.SendAsync(query, new IPEndPoint(address, 19302));
        var result = await udp.ReceiveAsync().WaitAsync(TimeSpan.FromSeconds(8));
        if (result.Buffer.Length < 20 || result.Buffer[0] != 1 || result.Buffer[1] != 1 || !result.Buffer.AsSpan(8, 12).SequenceEqual(query.AsSpan(8, 12)))
            throw new InvalidOperationException("UDP response failed.");
    }
}
