using System.Net;
using System.Net.Http;
using System.Text;
using System.Globalization;
using YaoVpn.Core;

namespace YaoVpn.App.Services;

public sealed record IpCheckResult(string? BeforeIp, string? CurrentIp)
{
    public override string ToString() => "VPN egress diagnostic result";
    public IpObservation? VpnEgress { get; init; }
    public string? AdvertisedCountryCode { get; init; }
    public string? SelectedServerName { get; init; }
    public bool HasCountryMismatch => AdvertisedCountryCode != null && VpnEgress?.CountryCode != null
        && AdvertisedCountryCode != VpnEgress.CountryCode;

    public string DisplayText
    {
        get
        {
            var text = new StringBuilder();
            if (VpnEgress == null) text.Append("실제 VPN 출구 국가·IP를 확인하지 못했습니다.");
            else
            {
                text.Append("실제 VPN 출구: ").Append(VpnEgress.Ip).Append(" · ").Append(VpnEgress.CountryLabel)
                    .Append(" · ").Append(VpnEgress.ObservedAt.ToLocalTime().ToString("HH:mm:ss"));
                if (AdvertisedCountryCode != null)
                    text.Append("\n서버 이름의 표시 국가: ").Append(ServerCatalog.CountryName(AdvertisedCountryCode)).Append(" (").Append(AdvertisedCountryCode).Append(')');
                if (HasCountryMismatch) text.Append("\n주의: 서버 표시와 출구 국가가 다릅니다. 다른 서버를 직접 선택하고 다시 확인해 주세요.");
            }
            text.Append("\n사이트 규칙 IP: ").Append(CurrentIp ?? "확인 불가").Append(" · 직접 연결: ").Append(BeforeIp ?? "확인 불가");
            text.Append("\n국가 표시는 IP 위치 DB 판정이며 물리적 서버 위치를 보장하지 않습니다.");
            return text.ToString();
        }
    }
}

public sealed record IpObservation(string Ip, string? CountryCode, DateTimeOffset ObservedAt)
{
    public string CountryLabel => CountryCode == null ? "국가 미확인" : ServerCatalog.CountryName(CountryCode) + " (" + CountryCode + ")";
}

internal static class IpVerification
{
    public static async Task<string?> ReadAsync(CancellationToken cancellationToken, Uri? proxyAddress = null)
        => (await ReadObservationAsync("www.cloudflare.com", cancellationToken, proxyAddress))?.Ip;

    public static Task<IpObservation?> ReadVpnAsync(CancellationToken cancellationToken, Uri? proxyAddress = null)
        => ReadObservationAsync(ConfigBuilder.VpnDiagnosticHost, cancellationToken, proxyAddress);

    private static async Task<IpObservation?> ReadObservationAsync(string host, CancellationToken cancellationToken, Uri? proxyAddress)
    {
        // Compare the same address family as the core's prefer_ipv4 DNS policy.
        // Otherwise direct IPv6 and proxied IPv4 can look like an egress change.
        using HttpMessageHandler handler = proxyAddress == null ? EndpointResolver.CreateSubscriptionHandler() : new SocketsHttpHandler
        {
            UseProxy = proxyAddress != null,
            Proxy = proxyAddress == null ? null : new WebProxy(proxyAddress) { BypassProxyOnLocal = false },
            AllowAutoRedirect = false
        };
        using var client = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(8) };
        try
        {
            // Independent HTTPS endpoint: never execute the response or trust an HTTP IP-check page.
            using var request = new HttpRequestMessage(HttpMethod.Get, "https://" + host + "/cdn-cgi/trace");
            request.Headers.CacheControl = new() { NoCache = true, NoStore = true };
            using var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
            if (!response.IsSuccessStatusCode || response.Content.Headers.ContentLength > 8192) return null;
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeout.CancelAfter(TimeSpan.FromSeconds(8));
            await using var stream = await response.Content.ReadAsStreamAsync(timeout.Token);
            using var output = new MemoryStream();
            var buffer = new byte[1024]; int count;
            while ((count = await stream.ReadAsync(buffer, timeout.Token)) != 0)
            {
                if (output.Length + count > 8192) return null;
                output.Write(buffer, 0, count);
            }
            var text = new UTF8Encoding(false, true).GetString(output.ToArray());
            return ParseObservation(text);
        }
        catch (Exception e) when (e is HttpRequestException or IOException or TaskCanceledException or DecoderFallbackException)
        { cancellationToken.ThrowIfCancellationRequested(); return null; }
    }

    internal static string? ParseTrace(string text)
    {
        if (text.Length > 8192) return null;
        var lines = text.Split('\n').Where(line => line.StartsWith("ip=", StringComparison.Ordinal)).ToArray();
        return lines.Length == 1 && IPAddress.TryParse(lines[0][3..].TrimEnd('\r'), out var address)
            ? address.ToString() : null;
    }

    internal static IpObservation? ParseObservation(string text)
    {
        var ip = ParseTrace(text);
        if (ip == null) return null;
        var location = text.Split('\n').Where(line => line.StartsWith("loc=", StringComparison.Ordinal)).ToArray();
        string? country = null;
        if (location.Length == 1)
        {
            var code = location[0][4..].TrimEnd('\r');
            if (code.Length == 2 && code.All(c => c is >= 'A' and <= 'Z') && code != "XX")
            {
                try
                {
                    var region = new RegionInfo(code);
                    if (region.TwoLetterISORegionName == code && code != "IV") country = code;
                }
                catch (ArgumentException) { }
            }
        }
        return new(ip, country, DateTimeOffset.UtcNow);
    }
}
