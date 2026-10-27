using System.Security.Cryptography;

namespace YaoVpn.App.Services;

public static class BinaryTrust
{
    public const string Version = "1.14.4";
    // Replaced only after validating the pinned official release archive.
    public const string ExpectedSha256 = "8f30682ee198855440d2a7fe070d5d3653793b2d01bb8c85eea88f93bbe7c8b9";
    public static string CorePath => Path.Combine(AppContext.BaseDirectory, "core", "sing-box.exe");
    public static FileStream OpenVerifiedCore()
    {
        // Keep a non-write/non-delete shared handle alive until the child exits (prevents replacement after hash verification).
        var handle = new FileStream(CorePath, FileMode.Open, FileAccess.Read, FileShare.Read);
        try
        {
            if (!Convert.ToHexString(SHA256.HashData(handle)).Equals(ExpectedSha256, StringComparison.OrdinalIgnoreCase))
                throw new IOException("VPN 엔진 무결성 검사에 실패했습니다. 공식 빌드를 다시 준비해 주세요.");
            handle.Position = 0;
            return handle;
        }
        catch { handle.Dispose(); throw; }
    }
}
