using System.Text.RegularExpressions;

namespace YaoVpn.Core;

/// <summary>Display metadata is an untrusted provider label, never evidence of physical server location.</summary>
public sealed record ServerEntry(VpnNode Node, string GroupLabel, string? CountryCode, bool IsConnectable)
{
    public string DisplayName => Node.DisplayName;
    public override string ToString() => DisplayName;
}

public static class ServerCatalog
{
    private static readonly Regex Information = new(
        @"剩[余餘]|[剩余餘]流量|套餐|[到过過]期|流量[：:]|(?:remaining|quota|bandwidth|traffic)\s*[：:]|remaining.{0,30}(?:traffic|data|quota|bandwidth)|(?:traffic|data|quota|bandwidth).{0,30}(?:left|remaining)|\b(?:expire[sd]?|expiry|expiration)\b|남은\s*(?:사용량|데이터|용량|트래픽)|잔여\s*(?:사용량|데이터|용량|트래픽)|구독\s*만료",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(30));

    private static readonly (string Code, string[] Names)[] Countries =
    [
        ("JP", ["日本", "东京", "東京", "大阪", "일본", "도쿄", "오사카", "JAPAN", "JPN"]),
        ("CN", ["中国", "中國", "北京", "上海", "广州", "廣州", "중국", "CHINA", "CHN"]),
        ("HK", ["香港", "홍콩", "HONG KONG", "HONGKONG", "HKG"]),
        ("SG", ["新加坡", "新嘉坡", "싱가포르", "SINGAPORE", "SGP"]),
        ("TW", ["台湾", "台灣", "臺灣", "타이완", "대만", "TAIWAN", "TWN"]),
        ("US", ["美国", "美國", "미국", "UNITED STATES", "USA"]),
        ("KR", ["韩国", "韓國", "한국", "KOREA", "KOR"]),
        ("GB", ["英国", "英國", "영국", "UNITED KINGDOM", "BRITAIN", "UK", "GBR"]),
        ("DE", ["德国", "德國", "독일", "GERMANY", "DEU"]),
        ("AU", ["澳洲", "澳大利亚", "澳大利亞", "호주", "AUSTRALIA", "AUS"]),
        ("CA", ["加拿大", "캐나다", "CANADA", "CAN"]),
        ("FR", ["法国", "法國", "프랑스", "FRANCE", "FRA"]),
        ("NL", ["荷兰", "荷蘭", "네덜란드", "NETHERLANDS", "NLD"])
    ];

    public static bool IsInformation(string? displayName) => displayName != null && displayName.Length <= 160 && Information.IsMatch(displayName);

    public static string? GetCountryCode(VpnNode node) => GetCountryCode(node.DisplayName);

    public static string? GetCountryCode(string? displayName)
    {
        if (string.IsNullOrWhiteSpace(displayName) || displayName.Length > 160 || IsInformation(displayName)) return null;
        // Flags are the provider's clearest explicit label. Conflicting labels are
        // deliberately unknown rather than silently preferring Japan in "US / JP".
        var flags = Countries.Where(country => displayName.Contains(Flag(country.Code), StringComparison.Ordinal)).ToArray();
        if (flags.Length > 0) return flags.Length == 1 ? flags[0].Code : null;
        var matches = Countries.Where(country => HasToken(displayName, country.Code)
            || country.Names.Any(name => name.Any(c => c > 127) ? displayName.Contains(name, StringComparison.OrdinalIgnoreCase) : HasToken(displayName, name))).ToArray();
        return matches.Length == 1 ? matches[0].Code : null;
    }

    public static IReadOnlyList<ServerEntry> Create(IReadOnlyList<VpnNode> nodes)
    {
        ArgumentNullException.ThrowIfNull(nodes);
        var informationSeen = new HashSet<string>(StringComparer.Ordinal);
        return nodes.Select((node, index) =>
            {
                var info = IsInformation(node.DisplayName);
                var country = GetCountryCode(node);
                return (Entry: new ServerEntry(node, Group(country, info), country, !info), Index: index, Priority: Priority(country, info));
            })
            .Where(item => item.Entry.IsConnectable || informationSeen.Add(item.Entry.DisplayName))
            .OrderBy(item => item.Priority)
            .ThenBy(item => item.Entry.IsConnectable ? item.Entry.DisplayName : "", NaturalComparer.Instance)
            .ThenBy(item => item.Index)
            .Select(item => item.Entry).ToArray();
    }

    public static ServerEntry? SelectDefault(IReadOnlyList<ServerEntry> entries, string? previousId = null)
        => entries.FirstOrDefault(entry => entry.IsConnectable && entry.Node.Id == previousId)
            // Prefer the verified-compatible protocol families for the initial Japan
            // choice; provider display order itself remains unchanged.
            ?? entries.FirstOrDefault(entry => entry.IsConnectable && entry.CountryCode == "JP" && entry.Node.Protocol == "vless")
            ?? entries.FirstOrDefault(entry => entry.IsConnectable && entry.CountryCode == "JP" && entry.Node.Protocol == "hysteria2")
            ?? entries.FirstOrDefault(entry => entry.IsConnectable && entry.CountryCode == "JP")
            ?? entries.FirstOrDefault(entry => entry.IsConnectable);

    public static string CountryName(string? code) => code switch
    {
        "JP" => "일본", "CN" => "중국", "HK" => "홍콩", "SG" => "싱가포르", "TW" => "대만", "US" => "미국",
        "KR" => "한국", "GB" => "영국", "DE" => "독일", "AU" => "호주", "CA" => "캐나다", "FR" => "프랑스", "NL" => "네덜란드",
        null => "미확인", _ => code
    };

    private static int Priority(string? code, bool info) => info ? 0 : code switch { "JP" => 1, "CN" or "HK" => 2, "SG" => 3, _ => 4 };
    private static string Group(string? code, bool info) => info ? "남은 사용량 / 구독 안내" : Priority(code, false) switch
    { 1 => "일본", 2 => "중국 / 홍콩", 3 => "싱가포르", _ => "기타" };

    private static bool HasToken(string value, string token)
    {
        var start = 0;
        while ((start = value.IndexOf(token, start, StringComparison.OrdinalIgnoreCase)) >= 0)
        {
            var end = start + token.Length;
            if ((start == 0 || !char.IsAsciiLetter(value[start - 1])) && (end == value.Length || !char.IsAsciiLetter(value[end]))) return true;
            start = end;
        }
        return false;
    }

    private static string Flag(string code) => string.Concat(code.Select(c => char.ConvertFromUtf32(0x1f1e6 + c - 'A')));

    private sealed class NaturalComparer : IComparer<string>
    {
        internal static readonly NaturalComparer Instance = new();
        public int Compare(string? left, string? right)
        {
            left ??= ""; right ??= "";
            var a = 0; var b = 0;
            while (a < left.Length && b < right.Length)
            {
                if (char.IsAsciiDigit(left[a]) && char.IsAsciiDigit(right[b]))
                {
                    var aEnd = a; var bEnd = b;
                    while (aEnd < left.Length && char.IsAsciiDigit(left[aEnd])) aEnd++;
                    while (bEnd < right.Length && char.IsAsciiDigit(right[bEnd])) bEnd++;
                    while (a < aEnd - 1 && left[a] == '0') a++;
                    while (b < bEnd - 1 && right[b] == '0') b++;
                    var length = (aEnd - a).CompareTo(bEnd - b);
                    if (length != 0) return length;
                    var digits = string.Compare(left, a, right, b, aEnd - a, StringComparison.Ordinal);
                    if (digits != 0) return digits;
                    a = aEnd; b = bEnd;
                }
                else
                {
                    var character = char.ToUpperInvariant(left[a]).CompareTo(char.ToUpperInvariant(right[b]));
                    if (character != 0) return character;
                    a++; b++;
                }
            }
            return (left.Length - a).CompareTo(right.Length - b);
        }
    }
}
