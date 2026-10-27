using YaoVpn.App.Services;
using YaoVpn.Core;

namespace YaoVpn.Tests;

internal static class TrafficSecurityTests
{
    public static async Task RunAsync()
    {
        var parser = new TrafficLogParser();
        Require(parser.Parse("DEBUG[0000] [10 1ms] router: sniffed protocol: tls, domain: example.com") == null, "Sniff alone is not an outbound attempt.");
        var record = parser.Parse("INFO[0000] [10 2ms] outbound/vless[vpn]: outbound connection to 93.184.216.34:443");
        Require(record is { Host: "example.com", Port: 443, Network: "TCP", Route: "vpn" }, "Correlate handshake metadata with chosen outbound.");
        Require(parser.Parse("INFO[0000] [10 3ms] outbound/vless[vpn]: outbound connection to 93.184.216.34:443") == null, "Duplicate outbound messages must not duplicate rows.");
        parser.Parse("INFO [20 1ms] inbound/tun[tun-in]: inbound packet connection to [2606:4700:4700::1111]:443");
        var udp = parser.Parse("INFO [20 1ms] outbound/direct[direct]: outbound packet connection");
        Require(udp is { Host: "2606:4700:4700::1111", Port: 443, Network: "UDP", Route: "direct" }, "Correlate UDP direct logs without destinations.");
        Require(parser.Parse("ERROR [21 1ms] outbound/vless[vpn]: attacker error password=secret-value") == null, "Never forward arbitrary peer errors.");
        Require(parser.Parse("INFO [22 1ms] outbound/vless[vpn]: outbound connection to https://example.com/secret-token:443") == null, "Never forward URL paths or credentials.");
        Require(parser.Parse("INFO [23 1ms] outbound/vless[vpn]: outbound connection to example.com:443\npassword=secret-value") == null, "Reject injected multiline metadata.");
        Require(parser.Parse(new string('x', 3000)) == null, "Reject overlong raw output.");
        Require(TrafficRecord.Validate(new(DateTimeOffset.Now, "example.com/?secret-value", 443, "TCP", "vpn")) == null, "Validate typed IPC again before display.");
        Require(TrafficRecord.Validate(new(DateTimeOffset.Now, "example.com", 443, "TCP", "arbitrary")) == null, "Reject unknown routes.");
        var colored = parser.Parse("\u001b[36mINFO\u001b[0m[0000] [24 1ms] outbound/anytls[vpn]: outbound connection to example.com:443");
        Require(colored is { Host: "example.com" }, "Parse the pinned core's ANSI log colors safely.");
        var bounded = new TrafficLogParser();
        bounded.Parse("DEBUG [0 1ms] router: sniffed protocol: tls, domain: stale.example.com");
        for (var i = 1; i <= 513; i++) bounded.Parse($"DEBUG [{i} 1ms] router: sniffed protocol: tls, domain: fresh.example.com");
        var evicted = bounded.Parse("INFO [0 1ms] outbound/vless[vpn]: outbound connection to 93.184.216.34:443");
        Require(evicted is { Host: "93.184.216.34" }, "Correlation cache must evict stale entries at its bound.");

        using var stream = new MemoryStream();
        await PipeProtocol.WriteAsync(stream, new("traffic", Traffic: record));
        await PipeProtocol.WriteAsync(stream, new("connect", Policy: new RoutingPolicy("direct", ["example.com"], [])));
        stream.Position = 0;
        var log = await PipeProtocol.ReadAsync(stream);
        var policy = await PipeProtocol.ReadAsync(stream);
        Require(log.Kind == "traffic" && log.Traffic == record && policy.Policy?.DefaultRoute == "direct", "Typed traffic/routing IPC roundtrip.");
        Require(IpVerification.ParseTrace("fl=123\nip=203.0.113.42\ntls=TLSv1.3\n") == "203.0.113.42", "Extract only a validated IP from HTTPS trace.");
        Require(IpVerification.ParseTrace("ip=203.0.113.42\nip=203.0.113.43\n") == null, "Reject ambiguous IP-check responses.");
        Require(IpVerification.ParseTrace("ip=<script>alert(1)</script>\n") == null, "Never display arbitrary IP-check content.");
        Console.WriteLine("PASS: bounded metadata parser, typed traffic IPC, IP response validation");
    }

    private static void Require(bool condition, string message) { if (!condition) throw new Exception(message); }
}
