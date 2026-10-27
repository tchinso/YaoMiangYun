using System.Diagnostics;
using YaoVpn.App.Services;

namespace YaoVpn.Tests;

internal static class ProxyRecoveryTests
{
    public static async Task RunAsync()
    {
        await UserProxySession.RecoverProxyAsync();
        var original = SystemProxyLease.ReadCurrent();
        var start = new ProcessStartInfo(Environment.ProcessPath ?? throw new IOException())
        {
            UseShellExecute = false, CreateNoWindow = true,
            RedirectStandardOutput = true, RedirectStandardError = true
        };
        if (Path.GetFileNameWithoutExtension(start.FileName).Equals("dotnet", StringComparison.OrdinalIgnoreCase))
            start.ArgumentList.Add(typeof(Program).Assembly.Location);
        start.ArgumentList.Add("--proxy-recovery-child");
        var priorDirectories = Directory.EnumerateDirectories(PrivateStorage.Root, "proxy-*").ToHashSet(StringComparer.OrdinalIgnoreCase);
        using var child = Process.Start(start) ?? throw new IOException("Recovery test owner did not start.");
        string? childDirectory = null;
        var ready = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var drains = Task.WhenAll(DrainAsync(child.StandardOutput, ready), DrainAsync(child.StandardError, ready));
        try
        {
            await Task.WhenAny(ready.Task, child.WaitForExitAsync()).WaitAsync(TimeSpan.FromSeconds(60));
            if (!ready.Task.IsCompletedSuccessfully || child.HasExited || SystemProxyLease.Equivalent(original, SystemProxyLease.ReadCurrent()))
                throw new Exception("Recovery test owner did not apply its proxy.");
            // The child owns the exclusive proxy lease here. Identify only its new
            // directory before killing it, never sweep previous/user session data.
            var created = Directory.EnumerateDirectories(PrivateStorage.Root, "proxy-*")
                .Where(path => !priorDirectories.Contains(path)).ToArray();
            if (created.Length == 1) childDirectory = created[0];
            // Simulate the GUI owner dying without running any of its finally blocks.
            child.Kill(entireProcessTree: false);
            await child.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(10));
            await UserProxySession.RecoverProxyAsync();
            if (!SystemProxyLease.Equivalent(original, SystemProxyLease.ReadCurrent()))
                throw new Exception("Next-start recovery did not restore the exact proxy snapshot.");
            Console.WriteLine("PASS: abrupt owner-process death leaves recoverable DPAPI state; next-start recovery restores exact settings");
        }
        finally
        {
            if (!child.HasExited) { child.Kill(entireProcessTree: true); await child.WaitForExitAsync(); }
            await drains.WaitAsync(TimeSpan.FromSeconds(10));
            await UserProxySession.RecoverProxyAsync();
            if (childDirectory != null && (File.GetAttributes(childDirectory) & FileAttributes.ReparsePoint) == 0)
            {
                File.Delete(Path.Combine(childDirectory, "config.json"));
                Directory.Delete(childDirectory, recursive: false);
            }
        }
    }

    private static async Task DrainAsync(StreamReader reader, TaskCompletionSource ready)
    {
        var buffer = new char[1024];
        var tail = "";
        int count;
        while ((count = await reader.ReadAsync(buffer)) > 0)
        {
            var text = tail + new string(buffer, 0, count);
            if (text.Contains("BROWSER_PROXY_READY:", StringComparison.Ordinal)) ready.TrySetResult();
            tail = text.Length > 80 ? text[^80..] : text;
        }
    }
}
