using System.Net;
using System.Net.Http;
using System.Text;

namespace YaoVpn.App.Services;

public sealed record IpCheckResult(string? BeforeIp, string? CurrentIp)
{
    public string DisplayText => CurrentIp == null ? "현재 IP를 확인하지 못했습니다."
        : BeforeIp == null ? $"현재 경로 IP: {CurrentIp} · 직접 연결 IP 확인 불가"
        : $"직접 연결: {BeforeIp} → 현재 경로: {CurrentIp}\n" + (BeforeIp == CurrentIp
            ? "IP가 같습니다. 사이트 규칙과 연결 상태를 확인하세요."
            : "공인 IP 변경 확인 · 현재 사이트 규칙이 적용된 결과입니다.");
}

internal static class IpVerification
{
    public static async Task<string?> ReadAsync(CancellationToken cancellationToken, Uri? proxyAddress = null)
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
            using var response = await client.GetAsync("https://www.cloudflare.com/cdn-cgi/trace", HttpCompletionOption.ResponseHeadersRead, cancellationToken);
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
            return ParseTrace(text);
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
}
