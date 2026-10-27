using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;

namespace YaoVpn.App.Services;

internal static class TunnelHealth
{
    public static bool IsUp() => NetworkInterface.GetAllNetworkInterfaces().Any(n => n.Name == "YaoVPN" && n.OperationalStatus == OperationalStatus.Up);

    public static bool HasRoutes()
    {
        var adapter = NetworkInterface.GetAllNetworkInterfaces().FirstOrDefault(n => n.Name == "YaoVPN" && n.OperationalStatus == OperationalStatus.Up);
        if (adapter == null) return false;
        var properties = adapter.GetIPProperties();
        var ipv4 = properties.GetIPv4Properties()?.Index;
        var ipv6 = properties.GetIPv6Properties()?.Index;
        return ipv4.HasValue && ipv6.HasValue
            && BestInterface("1.1.1.1") == ipv4.Value && BestInterface("8.8.8.8") == ipv4.Value
            && BestInterface("2606:4700:4700::1111") == ipv6.Value && BestInterface("2001:4860:4860::8888") == ipv6.Value;
    }

    private static int BestInterface(string address)
    {
        var ip = IPAddress.Parse(address);
        var isV6 = ip.AddressFamily == AddressFamily.InterNetworkV6;
        var socketAddress = new byte[28];
        socketAddress[0] = isV6 ? (byte)23 : (byte)2;
        ip.GetAddressBytes().CopyTo(socketAddress, isV6 ? 8 : 4);
        return GetBestInterfaceEx(socketAddress, out var index) == 0 ? (int)index : -1;
    }

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetBestInterfaceEx(byte[] destination, out uint interfaceIndex);
}
