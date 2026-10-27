using YaoVpn.App.Services;

namespace YaoVpn.Tests;

internal static class ProxySessionTests
{
    public static void Run()
    {
        var start = UserProxySession.CreateStartInfo("C:\\private\\config.json", "C:\\private");
        if (start.UseShellExecute || !start.CreateNoWindow || start.Verb.Length != 0 ||
            start.Environment["PATH"] != Environment.SystemDirectory || start.Environment.ContainsKey("HTTP_PROXY") ||
            start.Environment.ContainsKey("GODEBUG"))
            throw new InvalidOperationException("Ordinary-user proxy inherited unsafe execution options.");

        var applied = SystemProxyLease.ForPort(32123);
        if ((applied.Flags & 12) != 0 || (applied.Flags & 2) == 0 || applied.AutoConfigUrl != "" ||
            applied.ProxyServer != "http=127.0.0.1:32123;https=127.0.0.1:32123" ||
            !applied.ProxyBypass.Contains("localhost", StringComparison.Ordinal) ||
            !applied.ProxyBypass.Contains("172.16.*", StringComparison.Ordinal) || !applied.ProxyBypass.Contains("172.31.*", StringComparison.Ordinal) ||
            !applied.ProxyBypass.Contains("[::1]", StringComparison.Ordinal) || applied.ProxyBypass.Contains("<-loopback>", StringComparison.Ordinal))
            throw new InvalidOperationException("Proxy activation retained PAC/autodetection or exposed local origins.");

        var original = new SystemProxyLease.ProxyState(13, "proxy.example.com:8080", "<local>", "https://user.example.com/original.pac");
        var partial = original with { ProxyServer = applied.ProxyServer };
        if (!SystemProxyLease.IsPartialActivation(partial, original, applied) ||
            SystemProxyLease.IsPartialActivation(applied with { ProxyServer = "new-user-choice.example.com:8080" }, original, applied) ||
            SystemProxyLease.IsPartialActivation(applied with { AutoConfigUrl = "https://user.example.com/new.pac" }, original, applied))
            throw new InvalidOperationException("Proxy activation rollback could overwrite a newer user setting.");
        foreach (var changed in new[] { applied with { Flags = 1 }, applied with { ProxyServer = "other.example.com:80" },
            applied with { ProxyBypass = "user.example.com" }, applied with { AutoConfigUrl = "https://user.example.com/new.pac" } })
            if (SystemProxyLease.Equivalent(changed, applied)) throw new InvalidOperationException("Proxy recovery ignored a changed user setting.");
        foreach (var port in new[] { -1, 0, 65536 })
        {
            try { SystemProxyLease.ForPort(port); throw new InvalidOperationException("Invalid proxy port accepted."); }
            catch (ArgumentOutOfRangeException) { }
        }
        // Read-only native smoke check verifies our P/Invoke layout without changing Windows.
        var current = SystemProxyLease.ReadCurrent();
        if (!SystemProxyLease.Equivalent(current, current with { })) throw new InvalidOperationException("Proxy snapshot is not stable.");
    }
}
