using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;

namespace YaoVpn.App.Services;

public static class PrivateStorage
{
    private const int MaximumStoredBytes = 4 * 1024 * 1024;
    public static string Root => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "YaoVPN");

    public static void SecureDirectory(string path)
    {
        var directory = Directory.CreateDirectory(path);
        if ((directory.Attributes & FileAttributes.ReparsePoint) != 0) throw new IOException("Unsafe storage path.");
        var sid = WindowsIdentity.GetCurrent().User ?? throw new IOException("No user identity.");
        var acl = new DirectorySecurity();
        acl.SetAccessRuleProtection(true, false);
        foreach (var identity in new[] { sid, new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null), new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null) })
            acl.AddAccessRule(new FileSystemAccessRule(identity, FileSystemRights.FullControl,
                InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
        directory.SetAccessControl(acl);
    }

    public static void Save(string name, string value)
    {
        var path = StoragePath(name);
        SecureDirectory(Root);
        if (Encoding.UTF8.GetByteCount(value) > MaximumStoredBytes) throw new IOException("Stored data too large.");
        var clear = Encoding.UTF8.GetBytes(value);
        byte[]? encrypted = null;
        try
        {
            if (clear.Length > MaximumStoredBytes) throw new IOException("Stored data too large.");
            encrypted = Protect(clear, false);
            if (encrypted.Length > MaximumStoredBytes) throw new IOException("Stored data too large.");
            var temporary = Path.Combine(Root, Guid.NewGuid().ToString("N") + ".tmp");
            try
            {
                using (var output = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None))
                { output.Write(encrypted); output.Flush(true); }
                File.Move(temporary, path, true);
            }
            finally { if (File.Exists(temporary)) File.Delete(temporary); }
        }
        finally { CryptographicOperations.ZeroMemory(clear); if (encrypted != null) CryptographicOperations.ZeroMemory(encrypted); }
    }

    public static string? Load(string name)
    {
        var path = StoragePath(name);
        if (!File.Exists(path)) return null;
        if ((File.GetAttributes(Root) & FileAttributes.ReparsePoint) != 0 ||
            (File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
            throw new IOException("Unsafe storage path.");
        // Validate the same locked file that is read. A separate FileInfo check followed by
        // ReadAllBytes allowed replacement/growth between the size check and allocation.
        using var input = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        if (input.Length is <= 0 or > MaximumStoredBytes) throw new IOException("Stored data too large.");
        var encrypted = new byte[(int)input.Length];
        byte[]? decrypted = null;
        try
        {
            input.ReadExactly(encrypted);
            decrypted = Protect(encrypted, true);
            return new UTF8Encoding(false, true).GetString(decrypted);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(encrypted);
            if (decrypted != null) CryptographicOperations.ZeroMemory(decrypted);
        }
    }

    private static string StoragePath(string name)
    {
        // Storage keys are application-owned file names, never paths, devices or NTFS streams.
        if (string.IsNullOrWhiteSpace(name) || name.Length > 128 || name is "." or ".." ||
            name.Any(c => !char.IsAsciiLetterOrDigit(c) && c is not '.' and not '-' and not '_') ||
            name.EndsWith('.') || name.StartsWith('.'))
            throw new ArgumentException("Invalid storage name.", nameof(name));
        var stem = name.Split('.')[0];
        if (stem.Equals("CON", StringComparison.OrdinalIgnoreCase) || stem.Equals("PRN", StringComparison.OrdinalIgnoreCase) ||
            stem.Equals("AUX", StringComparison.OrdinalIgnoreCase) || stem.Equals("NUL", StringComparison.OrdinalIgnoreCase) ||
            (stem.Length == 4 && (stem.StartsWith("COM", StringComparison.OrdinalIgnoreCase) || stem.StartsWith("LPT", StringComparison.OrdinalIgnoreCase)) && stem[3] is >= '0' and <= '9'))
            throw new ArgumentException("Invalid storage name.", nameof(name));
        return Path.Combine(Root, name);
    }

    private static byte[] Protect(byte[] bytes, bool decrypt)
    {
        var input = new DataBlob { Size = bytes.Length, Data = Marshal.AllocHGlobal(bytes.Length) };
        Marshal.Copy(bytes, 0, input.Data, bytes.Length);
        DataBlob output = default;
        try
        {
            var success = decrypt
                ? CryptUnprotectData(ref input, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, 1, out output)
                : CryptProtectData(ref input, null, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, 1, out output);
            if (!success) throw new CryptographicException("Windows 계정 암호화에 실패했습니다.");
            var result = new byte[output.Size];
            Marshal.Copy(output.Data, result, 0, output.Size);
            return result;
        }
        finally
        {
            Marshal.Copy(new byte[bytes.Length], 0, input.Data, bytes.Length);
            Marshal.FreeHGlobal(input.Data);
            if (output.Data != IntPtr.Zero) { Marshal.Copy(new byte[output.Size], 0, output.Data, output.Size); LocalFree(output.Data); }
        }
    }

    [StructLayout(LayoutKind.Sequential)] private struct DataBlob { public int Size; public IntPtr Data; }
    [DllImport("crypt32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptProtectData(ref DataBlob input, string? description, IntPtr entropy, IntPtr reserved, IntPtr prompt, int flags, out DataBlob output);
    [DllImport("crypt32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptUnprotectData(ref DataBlob input, IntPtr description, IntPtr entropy, IntPtr reserved, IntPtr prompt, int flags, out DataBlob output);
    [DllImport("kernel32.dll")] private static extern IntPtr LocalFree(IntPtr pointer);
}
