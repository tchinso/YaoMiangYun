using System.Collections.Concurrent;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using YaoVpn.App.Services;
using YaoVpn.Core;

namespace YaoVpn.Tests;

internal static class ProxyIntegrationTests
{
    public static async Task RunAsync(VpnNode node)
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(90));
        await UserProxySession.RecoverProxyAsync(timeout.Token);
        var original = SystemProxyLease.ReadCurrent();
        var baseline = await IpVerification.ReadAsync(timeout.Token) ?? throw new Exception("Direct IP check unavailable.");
        var records = new ConcurrentQueue<TrafficRecord>();
        await using var session = await UserProxySession.StartAsync(node,
            new RoutingPolicy("direct", ["cloudflare.com"], []), records.Enqueue, timeout.Token);
        try
        {
            if (UserProxySession.IsCurrentProcessElevated() || TunnelHealth.IsUp()) throw new Exception("Non-admin proxy used elevated/TUN mode.");
            if (!SystemProxyLease.Equivalent(SystemProxyLease.ReadCurrent(), SystemProxyLease.ForPort(session.ProxyAddress.Port)))
                throw new Exception("Windows did not apply the exact loopback proxy settings.");
            var proxied = await IpVerification.ReadAsync(timeout.Token, session.ProxyAddress);
            if (proxied == null || proxied == baseline) throw new Exception("Non-admin VPN egress did not change.");
            var systemIp = await Task.Run(ReadWinInetIp, timeout.Token).WaitAsync(TimeSpan.FromSeconds(25), timeout.Token);
            if (systemIp == null || systemIp != proxied) throw new Exception("Windows system-proxy HTTP did not use VPN egress.");
            var direct = await IpVerification.ReadAsync(timeout.Token);
            if (direct != baseline) throw new Exception("An explicit non-proxy app did not retain direct egress.");
            if (!records.Any(record => record.Host == "www.cloudflare.com" && record.Route == "vpn"))
                throw new Exception("Real proxy connection metadata missing.");
            Console.WriteLine("PASS: non-admin HTTP/SOCKS + Windows WinINET proxy use VPN; non-proxy app stays direct; metadata observed");
            using var child = Process.GetProcessById(session.CoreProcessId);
            child.Kill(entireProcessTree: true);
            await session.Exit.WaitAsync(TimeSpan.FromSeconds(8));
        }
        finally
        {
            await session.DisposeAsync();
            if (!SystemProxyLease.Equivalent(original, SystemProxyLease.ReadCurrent())) throw new Exception("Original Windows proxy was not restored after core termination.");
            if (TunnelHealth.IsUp()) throw new Exception("Unexpected TUN adapter after proxy test.");
        }
        Console.WriteLine("PASS: core termination cleanup restores the exact previous flags/server/bypass/PAC without TUN");
    }

    private static string? ReadWinInetIp()
    {
        var internet = InternetOpen("YaoVPN verification", 0, null, null, 0);
        if (internet == IntPtr.Zero) throw new IOException("WinINET session unavailable.");
        try
        {
            var requestTimeout = 15000u;
            foreach (var option in new[] { 2u, 5u, 6u }) InternetSetOption(internet, option, ref requestTimeout, 4);
            var request = InternetOpenUrl(internet, "https://www.cloudflare.com/cdn-cgi/trace", null, 0, 0x84000200, IntPtr.Zero);
            if (request == IntPtr.Zero) throw new IOException("WinINET HTTPS verification failed.");
            try
            {
                using var output = new MemoryStream();
                var buffer = new byte[1024];
                while (true)
                {
                    if (!InternetReadFile(request, buffer, (uint)buffer.Length, out var count)) throw new IOException("WinINET HTTPS read failed.");
                    if (count == 0) break;
                    if (output.Length + count > 8192) throw new IOException("WinINET HTTPS response exceeded its bound.");
                    output.Write(buffer, 0, (int)count);
                }
                return IpVerification.ParseTrace(new UTF8Encoding(false, true).GetString(output.ToArray()));
            }
            finally { InternetCloseHandle(request); }
        }
        finally { InternetCloseHandle(internet); }
    }

    [DllImport("wininet.dll", EntryPoint = "InternetOpenW", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr InternetOpen(string agent, uint access, string? proxy, string? bypass, uint flags);
    [DllImport("wininet.dll", EntryPoint = "InternetOpenUrlW", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr InternetOpenUrl(IntPtr internet, string url, string? headers, uint length, uint flags, IntPtr context);
    [DllImport("wininet.dll", EntryPoint = "InternetSetOptionW", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)] private static extern bool InternetSetOption(IntPtr internet, uint option, ref uint value, uint size);
    [DllImport("wininet.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)] private static extern bool InternetReadFile(IntPtr request, byte[] buffer, uint length, out uint read);
    [DllImport("wininet.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)] private static extern bool InternetCloseHandle(IntPtr handle);
}
