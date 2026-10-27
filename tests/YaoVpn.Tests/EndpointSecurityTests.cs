using System.Net;
using System.Text.Json;
using YaoVpn.App.Services;
using YaoVpn.Core;

namespace YaoVpn.Tests;

internal static class EndpointSecurityTests
{
    public static void Run()
    {
        var node = SubscriptionParser.Parse("""
            [{"type":"anytls","tag":"test","server":"example.com","server_port":443,
              "password":"test-only","tls":{"enabled":true}}]
            """).Nodes.Single();
        var pinned = EndpointResolver.PinAddress(node, IPAddress.Parse("1.1.1.1"));
        using (var json = JsonDocument.Parse(pinned.OutboundJson))
        {
            if (json.RootElement.GetProperty("server").GetString() != "1.1.1.1" ||
                json.RootElement.GetProperty("tls").GetProperty("server_name").GetString() != "example.com")
                throw new Exception("Endpoint pinning changed the TLS identity.");
        }
        foreach (var address in new[] { "127.0.0.1", "10.0.0.1", "169.254.169.254", "::1", "::ffff:127.0.0.1", "fd00::1" })
        {
            try { EndpointResolver.PinAddress(node, IPAddress.Parse(address)); throw new Exception("Local endpoint accepted."); }
            catch (IOException) { }
        }
        var ws = SubscriptionParser.Parse("""
            [{"type":"vless","tag":"test","server":"edge.example.com","server_port":8443,
              "uuid":"bf000d23-0752-40b4-affe-68f7707a9661","tls":{"enabled":true,"server_name":"tls.example.com"},
              "transport":{"type":"ws","path":"/tunnel"}}]
            """).Nodes.Single();
        using (var json = JsonDocument.Parse(EndpointResolver.PinAddress(ws, IPAddress.Parse("1.1.1.1")).OutboundJson))
        {
            if (json.RootElement.GetProperty("server").GetString() != "1.1.1.1" ||
                json.RootElement.GetProperty("tls").GetProperty("server_name").GetString() != "tls.example.com" ||
                json.RootElement.GetProperty("transport").GetProperty("headers").GetProperty("Host").GetString() != "edge.example.com:8443")
                throw new Exception("Endpoint pinning changed the implicit WebSocket authority or explicit SNI.");
        }
        var explicitHost = ws with { OutboundJson = ws.OutboundJson.Replace("\"path\":\"/tunnel\"", "\"path\":\"/tunnel\",\"headers\":{\"Host\":\"cover.example.com:9443\"}", StringComparison.Ordinal) };
        using (var json = JsonDocument.Parse(EndpointResolver.PinAddress(explicitHost, IPAddress.Parse("1.1.1.1")).OutboundJson))
        {
            if (json.RootElement.GetProperty("transport").GetProperty("headers").GetProperty("Host").GetString() != "cover.example.com:9443")
                throw new Exception("Endpoint pinning replaced an explicit WebSocket authority.");
        }
        foreach (var type in new[] { "httpupgrade", "grpc", "http" })
        {
            var transported = ws with { OutboundJson = ws.OutboundJson.Replace("\"type\":\"ws\"", "\"type\":\"" + type + "\"", StringComparison.Ordinal) };
            using var json = JsonDocument.Parse(EndpointResolver.PinAddress(transported, IPAddress.Parse("1.1.1.1")).OutboundJson);
            if (json.RootElement.GetProperty("tls").GetProperty("server_name").GetString() != "tls.example.com")
                throw new Exception("Endpoint pinning changed a transport TLS/authority identity.");
        }
    }
}
