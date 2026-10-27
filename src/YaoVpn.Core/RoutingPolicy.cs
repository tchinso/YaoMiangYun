using System.Globalization;
using System.Net;

namespace YaoVpn.Core;

/// <summary>User-owned suffix rules. No URLs, files, executable content, or remote rule sets.</summary>
public sealed record RoutingPolicy(string DefaultRoute, string[] VpnDomains, string[] DirectDomains)
{
    public const int MaximumRules = 64;
    public static RoutingPolicy FullTunnel => new("vpn", [], []);
    public static RoutingPolicy SelectedSites => new("direct", [], []);

    public static RoutingPolicy Validate(RoutingPolicy? policy)
    {
        policy ??= FullTunnel;
        if (policy.DefaultRoute is not ("vpn" or "direct") || policy.VpnDomains == null || policy.DirectDomains == null
            || policy.VpnDomains.Length + policy.DirectDomains.Length > MaximumRules)
            throw new FormatException("사이트 규칙은 최대 64개이며 기본 경로는 VPN 또는 일반 통신이어야 합니다.");
        var vpn = policy.VpnDomains.Select(NormalizeDomain).Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal).ToArray();
        var direct = policy.DirectDomains.Select(NormalizeDomain).Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal).ToArray();
        if (vpn.Intersect(direct, StringComparer.Ordinal).Any())
            throw new FormatException("같은 도메인을 VPN과 일반 통신에 동시에 지정할 수 없습니다.");
        return new(policy.DefaultRoute, vpn, direct);
    }

    public static string NormalizeDomain(string value)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Length > 253 || value.Any(c => char.IsControl(c) || char.IsWhiteSpace(c)))
            throw new FormatException("example.com 형태의 도메인만 입력해 주세요.");
        string domain;
        try { domain = new IdnMapping { UseStd3AsciiRules = true }.GetAscii(value.TrimEnd('.')).ToLowerInvariant(); }
        catch (ArgumentException) { throw new FormatException("올바른 도메인을 입력해 주세요."); }
        if (domain.Length is < 3 or > 253 || IPAddress.TryParse(domain, out _) || !domain.Contains('.')
            || domain.Split('.').Any(label => label.Length is < 1 or > 63 || label[0] == '-' || label[^1] == '-'
                || label.Any(c => !(c is >= 'a' and <= 'z' or >= '0' and <= '9' or '-'))))
            throw new FormatException("경로나 포트 없이 example.com 형태의 도메인만 입력해 주세요.");
        return domain;
    }
}
