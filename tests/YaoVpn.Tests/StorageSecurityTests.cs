using YaoVpn.App.Services;

namespace YaoVpn.Tests;

internal static class StorageSecurityTests
{
    public static void Run()
    {
        var start = CoreProcess.CreateStartInfo("C:\\private\\config.json", "C:\\private");
        var allowedEnvironment = new HashSet<string>(new[] { "SystemRoot", "WINDIR", "PATH", "TEMP", "TMP", "NoDefaultCurrentDirectoryInExePath" }, StringComparer.OrdinalIgnoreCase);
        if (start.UseShellExecute || start.Environment.Keys.Any(key => !allowedEnvironment.Contains(key)) ||
            start.Environment["PATH"] != Environment.SystemDirectory || start.Environment["TEMP"] != "C:\\private")
            throw new InvalidOperationException("Core inherited unsafe process execution settings.");
        foreach (var name in new[] { "", ".", "..", "../outside.dpapi", "folder\\secret.dpapi", "C:\\secret.dpapi", "x:stream", "con.dpapi", "NUL", "COM1.dpapi", "LPT9", "trailing.", " space", new string('a', 129) })
        {
            Rejects<ArgumentException>(() => PrivateStorage.Save(name, "test"));
            Rejects<ArgumentException>(() => PrivateStorage.Load(name));
        }
        var nameForTest = "security-" + Guid.NewGuid().ToString("N") + ".dpapi";
        var path = Path.Combine(PrivateStorage.Root, nameForTest);
        PrivateStorage.SecureDirectory(PrivateStorage.Root);
        try
        {
            using (var oversized = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None))
                oversized.SetLength(4 * 1024 * 1024 + 1);
            Rejects<IOException>(() => PrivateStorage.Load(nameForTest));
            File.Delete(path);
            File.WriteAllBytes(path, []);
            Rejects<IOException>(() => PrivateStorage.Load(nameForTest));
            File.Delete(path);
            PrivateStorage.Save(nameForTest, "locked-roundtrip");
            // A writer that could change the length/content must be rejected before decryption.
            using var writer = new FileStream(path, FileMode.Open, FileAccess.Write, FileShare.ReadWrite);
            Rejects<IOException>(() => PrivateStorage.Load(nameForTest));
        }
        finally { File.Delete(path); }
    }

    private static void Rejects<T>(Action action) where T : Exception
    {
        try { action(); }
        catch (T) { return; }
        throw new InvalidOperationException("Storage boundary accepted an unsafe operation: " + typeof(T).Name);
    }
}
