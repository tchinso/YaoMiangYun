using System.Runtime.InteropServices;
using System.Text.Json;

namespace YaoVpn.App.Services;

/// <summary>A reversible current-user WinINET proxy change; never installs a PAC or touches WinHTTP.</summary>
internal sealed class SystemProxyLease : IDisposable
{
    private const string RecoveryName = "proxy-recovery.dpapi";
    private static readonly string LocalBypass = "<local>;localhost;*.localhost;127.*;10.*;192.168.*;169.254.*;"
        + string.Join(';', Enumerable.Range(16, 16).Select(part => "172." + part + ".*"))
        + ";[::1];[fc*];[fd*];[fe8*];[fe9*];[fea*];[feb*]";
    private readonly FileStream ownership;
    private readonly RecoveryRecord record;
    private readonly object sync = new();
    private bool disposed;

    internal sealed record ProxyState(uint Flags, string ProxyServer, string ProxyBypass, string AutoConfigUrl)
    {
        // Existing enterprise proxies/PAC URLs can themselves contain credentials.
        public override string ToString() => "Windows current-user proxy settings";
    }
    private sealed record RecoveryRecord(int Version, string Id, ProxyState Original, ProxyState Applied);

    private SystemProxyLease(FileStream ownership, RecoveryRecord record)
    { this.ownership = ownership; this.record = record; }

    public static SystemProxyLease Activate(int port)
    {
        if (port is < 1 or > 65535) throw new ArgumentOutOfRangeException(nameof(port));
        var ownership = AcquireOwnership();
        try
        {
            RecoverUnderLock();
            var original = ReadCurrent();
            var applied = ForPort(port);
            var record = new RecoveryRecord(1, Guid.NewGuid().ToString("N"), original, applied);
            // Persist before changing Windows: termination at any later point is recoverable.
            PrivateStorage.Save(RecoveryName, JsonSerializer.Serialize(record));
            try
            {
                SetCurrent(applied);
                if (!Equivalent(ReadCurrent(), applied)) throw new IOException("Windows proxy activation could not be verified.");
            }
            catch
            {
                Restore(record, allowPartialActivation: true);
                throw;
            }
            return new SystemProxyLease(ownership, record);
        }
        catch { ownership.Dispose(); throw; }
    }

    public static async Task RecoverAsync(CancellationToken cancellationToken = default)
    {
        for (var attempt = 0; ; attempt++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            FileStream ownership;
            try { ownership = await Task.Run(AcquireOwnership, cancellationToken).ConfigureAwait(false); }
            catch (IOException error) when (attempt < 20 && (error.HResult & 0xffff) is 32 or 33)
            {
                // Abrupt owner termination can precede completion of Windows handle/IO
                // cleanup. Retry only sharing/lock violations for at most two seconds;
                // an active owner remains protected and the final failure is reported.
                await Task.Delay(100, cancellationToken).ConfigureAwait(false);
                continue;
            }
            using (ownership)
                await Task.Run(() => { cancellationToken.ThrowIfCancellationRequested(); RecoverUnderLock(); }, cancellationToken).ConfigureAwait(false);
            return;
        }
    }

    private static FileStream AcquireOwnership()
    {
        PrivateStorage.SecureDirectory(PrivateStorage.Root);
        return new FileStream(Path.Combine(PrivateStorage.Root, "proxy-session.lock"), FileMode.OpenOrCreate,
            FileAccess.ReadWrite, FileShare.None);
    }

    private static void RecoverUnderLock()
    {
        var saved = PrivateStorage.Load(RecoveryName);
        if (saved == null) return;
        RecoveryRecord record;
        try { record = JsonSerializer.Deserialize<RecoveryRecord>(saved) ?? throw new JsonException(); }
        catch (JsonException) { throw new IOException("Saved proxy recovery data is invalid."); }
        if (record.Version != 1 || !Guid.TryParseExact(record.Id, "N", out _) || record.Original == null || record.Applied == null)
            throw new IOException("Saved proxy recovery data is invalid.");
        Validate(record.Original);
        Validate(record.Applied);
        // Recovery can only claim an exact loopback setting created by this application.
        if (!IsApplicationState(record.Applied)) throw new IOException("Saved proxy recovery data is invalid.");
        Restore(record);
    }

    private static void Restore(RecoveryRecord record, bool allowPartialActivation = false)
    {
        var saved = PrivateStorage.Load(RecoveryName);
        if (saved != null)
        {
            RecoveryRecord savedRecord;
            try { savedRecord = JsonSerializer.Deserialize<RecoveryRecord>(saved) ?? throw new JsonException(); }
            catch (JsonException) { throw new IOException("Saved proxy recovery data is invalid."); }
            if (savedRecord.Id != record.Id) throw new IOException("Another proxy recovery record is active.");
        }
        var current = ReadCurrent();
        if (Equivalent(current, record.Applied) || allowPartialActivation && IsPartialActivation(current, record.Original, record.Applied))
        {
            SetCurrent(record.Original);
            if (!Equivalent(ReadCurrent(), record.Original)) throw new IOException("Windows proxy restoration could not be verified.");
        }
        else NotifyProxyChange();
        // If the user changed any field while connected, retain their newer choice.
        // This exact app-owned file is the only recovery record ever removed.
        File.Delete(Path.Combine(PrivateStorage.Root, RecoveryName));
    }

    public void Dispose()
    {
        lock (sync)
        {
            if (disposed) return;
            // Retain the lock on failure so another lease cannot replace the recovery
            // record while OFF retries this lease's restoration.
            Restore(record);
            disposed = true;
            ownership.Dispose();
        }
    }

    internal static ProxyState ForPort(int port)
    {
        if (port is < 1 or > 65535) throw new ArgumentOutOfRangeException(nameof(port));
        return new(3, $"http=127.0.0.1:{port};https=127.0.0.1:{port}", LocalBypass, "");
    }

    internal static bool Equivalent(ProxyState left, ProxyState right) => left == right;

    internal static bool IsPartialActivation(ProxyState current, ProxyState original, ProxyState applied) =>
        (current.Flags == original.Flags || current.Flags == applied.Flags) &&
        (current.ProxyServer == original.ProxyServer || current.ProxyServer == applied.ProxyServer) &&
        (current.ProxyBypass == original.ProxyBypass || current.ProxyBypass == applied.ProxyBypass) &&
        (current.AutoConfigUrl == original.AutoConfigUrl || current.AutoConfigUrl == applied.AutoConfigUrl);

    private static bool IsApplicationState(ProxyState state)
    {
        if (state.Flags != 3 || state.ProxyBypass != LocalBypass || state.AutoConfigUrl != "") return false;
        const string prefix = "http=127.0.0.1:";
        if (!state.ProxyServer.StartsWith(prefix, StringComparison.Ordinal)) return false;
        var separator = state.ProxyServer.IndexOf(';');
        if (separator < prefix.Length || !int.TryParse(state.ProxyServer.AsSpan(prefix.Length, separator - prefix.Length),
            System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out var port) || port is < 1 or > 65535)
            return false;
        return state == ForPort(port);
    }

    internal static ProxyState ReadCurrent()
    {
        // Microsoft recommends FLAGS_UI for queries and FLAGS for restoration.
        try { return QueryCurrent(10); }
        catch (IOException) { return QueryCurrent(1); }
    }

    private static ProxyState QueryCurrent(uint flagsOption)
    {
        var size = Marshal.SizeOf<NativeOption>();
        var memory = Marshal.AllocHGlobal(size * 4);
        try
        {
            var ids = new[] { flagsOption, 2u, 3u, 4u };
            for (var i = 0; i < ids.Length; i++)
                Marshal.StructureToPtr(new NativeOption { Option = ids[i] }, memory + i * size, false);
            var list = new NativeOptionList { Size = (uint)Marshal.SizeOf<NativeOptionList>(), Count = 4, Options = memory };
            var length = list.Size;
            if (!InternetQueryOption(IntPtr.Zero, 75, ref list, ref length)) throw new IOException("Windows proxy settings could not be read.");
            var flags = Marshal.PtrToStructure<NativeOption>(memory).Value.Number;
            string ReadString(int index)
            {
                var pointer = Marshal.PtrToStructure<NativeOption>(memory + index * size).Value.Pointer;
                return pointer == IntPtr.Zero ? "" : Marshal.PtrToStringUni(pointer) ?? "";
            }
            var state = new ProxyState(flags, ReadString(1), ReadString(2), ReadString(3));
            Validate(state);
            return state;
        }
        finally
        {
            for (var i = 1; i < 4; i++)
            {
                var pointer = Marshal.PtrToStructure<NativeOption>(memory + i * size).Value.Pointer;
                if (pointer != IntPtr.Zero) GlobalFree(pointer);
            }
            Marshal.FreeHGlobal(memory);
        }
    }

    private static void SetCurrent(ProxyState state)
    {
        Validate(state);
        var strings = new[] { state.ProxyServer, state.ProxyBypass, state.AutoConfigUrl }.Select(Marshal.StringToHGlobalUni).ToArray();
        var size = Marshal.SizeOf<NativeOption>();
        var memory = Marshal.AllocHGlobal(size * 4);
        try
        {
            Marshal.StructureToPtr(new NativeOption { Option = 1, Value = new NativeValue { Number = state.Flags } }, memory, false);
            for (var i = 0; i < strings.Length; i++)
                Marshal.StructureToPtr(new NativeOption { Option = (uint)i + 2, Value = new NativeValue { Pointer = strings[i] } }, memory + (i + 1) * size, false);
            var list = new NativeOptionList { Size = (uint)Marshal.SizeOf<NativeOptionList>(), Count = 4, Options = memory };
            if (!InternetSetOptions(IntPtr.Zero, 75, ref list, list.Size)) throw new IOException("Windows proxy settings could not be changed.");
            NotifyProxyChange();
        }
        finally
        {
            foreach (var pointer in strings) Marshal.FreeHGlobal(pointer);
            Marshal.FreeHGlobal(memory);
        }
    }

    private static void NotifyProxyChange()
    {
        // 39 invalidates registry-backed settings, 95 notifies every WinINET instance
        // (NULL buffer), and 37 refreshes proxy data. A registry write alone can leave
        // existing browsers pointing at a listener which OFF has already stopped.
        var changed = InternetNotify(IntPtr.Zero, 39, IntPtr.Zero, 0);
        var proxyChanged = InternetNotify(IntPtr.Zero, 95, IntPtr.Zero, 0);
        var refreshed = InternetNotify(IntPtr.Zero, 37, IntPtr.Zero, 0);
        // WM_SETTINGCHANGE is the documented system-parameter notification. Hung or
        // higher-integrity peer windows must not prevent restoration of this user's settings.
        _ = SendMessageTimeout(new IntPtr(0xffff), 0x001a, UIntPtr.Zero, "Internet Settings", 0x0002 | 0x0020, 250, out _);
        if (!changed || !proxyChanged || !refreshed) throw new IOException("Windows proxy change notification failed.");
    }

    private static void Validate(ProxyState state)
    {
        if ((state.Flags & ~15u) != 0 || state.ProxyServer == null || state.ProxyBypass == null || state.AutoConfigUrl == null ||
            new[] { state.ProxyServer, state.ProxyBypass, state.AutoConfigUrl }.Any(value => value.Length > 32768 || value.Contains('\0')))
            throw new IOException("Windows proxy settings are unsupported.");
    }

    [StructLayout(LayoutKind.Explicit)]
    private struct NativeValue
    { [FieldOffset(0)] public uint Number; [FieldOffset(0)] public IntPtr Pointer; [FieldOffset(0)] public long FileTime; }
    [StructLayout(LayoutKind.Sequential)]
    private struct NativeOption { public uint Option; public NativeValue Value; }
    [StructLayout(LayoutKind.Sequential)]
    private struct NativeOptionList { public uint Size; public IntPtr Connection; public uint Count, Error; public IntPtr Options; }
    [DllImport("wininet.dll", EntryPoint = "InternetQueryOptionW", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)] private static extern bool InternetQueryOption(IntPtr internet, uint option, ref NativeOptionList buffer, ref uint size);
    [DllImport("wininet.dll", EntryPoint = "InternetSetOptionW", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)] private static extern bool InternetSetOptions(IntPtr internet, uint option, ref NativeOptionList buffer, uint size);
    [DllImport("wininet.dll", EntryPoint = "InternetSetOptionW", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)] private static extern bool InternetNotify(IntPtr internet, uint option, IntPtr buffer, uint size);
    [DllImport("kernel32.dll")] private static extern IntPtr GlobalFree(IntPtr memory);
    [DllImport("user32.dll", EntryPoint = "SendMessageTimeoutW", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr SendMessageTimeout(IntPtr window, uint message, UIntPtr wParam, string lParam, uint flags, uint timeout, out UIntPtr result);
}
