using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using Microsoft.Win32.SafeHandles;
using YaoVpn.Core;

namespace YaoVpn.App.Services;

/// <summary>Ordinary-user proxy for apps that honor the Windows user proxy; no TUN, service or driver.</summary>
public sealed class UserProxySession : IAsyncDisposable
{
    private readonly Process process;
    private readonly SafeFileHandle job;
    private readonly FileStream binaryLock;
    private readonly FileStream configLock;
    private readonly string directory;
    private readonly Task drains;
    private readonly TaskCompletionSource ready = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly TrafficLogParser parser = new();
    private readonly Action<TrafficRecord> traffic;
    private readonly object disposeSync = new();
    private Task? disposal;
    private bool resourcesReleased;
    private SystemProxyLease? lease;

    private UserProxySession(Process process, SafeFileHandle job, FileStream binaryLock, FileStream configLock,
        string directory, int port, Action<TrafficRecord> traffic)
    {
        this.process = process; this.job = job; this.binaryLock = binaryLock;
        this.configLock = configLock; this.directory = directory; this.traffic = traffic;
        ProxyAddress = new Uri("http://127.0.0.1:" + port.ToString(System.Globalization.CultureInfo.InvariantCulture));
        Exit = process.WaitForExitAsync();
        drains = Task.WhenAll(DrainAsync(process.StandardOutput), DrainAsync(process.StandardError));
    }

    public Uri ProxyAddress { get; }
    public Task Exit { get; }
    internal int CoreProcessId => process.Id;
    internal bool HasCurrentSystemProxy => lease?.IsCurrent == true;

    public static Task RecoverAsync(CancellationToken cancellationToken = default) => SystemProxyLease.RecoverAsync(cancellationToken);
    public static Task RecoverProxyAsync(CancellationToken cancellationToken = default) => RecoverAsync(cancellationToken);

    public static async Task<UserProxySession> StartAsync(VpnNode node, RoutingPolicy policy, Action<TrafficRecord> traffic, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(traffic);
        // Inherit an ordinary token only. Starting from a manually elevated UI must fail,
        // rather than silently turning the low-privilege option into an elevated parser.
        if (IsCurrentProcessElevated())
            throw new InvalidOperationException("관리자 권한 없는 모드는 앱을 일반 실행으로 다시 열어 주세요.");
        node = await EndpointResolver.ResolvePublicAsync(node, cancellationToken).ConfigureAwait(false);
        policy = RoutingPolicy.Validate(policy);
        PrivateStorage.SecureDirectory(PrivateStorage.Root);
        var directory = Path.Combine(PrivateStorage.Root, "proxy-" + Guid.NewGuid().ToString("N"));
        PrivateStorage.SecureDirectory(directory);
        FileStream? configLock = null;
        FileStream? binaryLock = null;
        SafeFileHandle? job = null;
        Process? process = null;
        UserProxySession? session = null;
        try
        {
            using var reservation = new TcpListener(IPAddress.Loopback, 0);
            reservation.Start();
            var port = ((IPEndPoint)reservation.LocalEndpoint).Port;
            var configPath = Path.Combine(directory, "config.json");
            configLock = new FileStream(configPath, FileMode.CreateNew, FileAccess.ReadWrite, FileShare.Read);
            await configLock.WriteAsync(Encoding.UTF8.GetBytes(ConfigBuilder.Build(node, false, port, policy)), cancellationToken).ConfigureAwait(false);
            await configLock.FlushAsync(cancellationToken).ConfigureAwait(false);
            binaryLock = BinaryTrust.OpenVerifiedCore();
            job = CreateJobObject(IntPtr.Zero, null);
            if (job.IsInvalid) throw new IOException("Proxy job creation failed.");
            var limits = new ExtendedLimits { BasicLimitInformation = new BasicLimits { LimitFlags = 0x2000 | 0x8, ActiveProcessLimit = 1 } };
            if (!SetInformationJobObject(job, 9, ref limits, (uint)Marshal.SizeOf<ExtendedLimits>())) throw new IOException("Proxy job setup failed.");
            var start = CreateStartInfo(configPath, directory);
            reservation.Stop();
            process = Process.Start(start) ?? throw new IOException("Proxy engine did not start.");
            if (!AssignProcessToJobObject(job, process.Handle)) throw new IOException("Proxy job assignment failed.");
            session = new UserProxySession(process, job, binaryLock, configLock, directory, port, traffic);
            using var startup = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            startup.CancelAfter(TimeSpan.FromSeconds(25));
            await Task.WhenAny(session.ready.Task, session.Exit).WaitAsync(startup.Token).ConfigureAwait(false);
            if (session.Exit.IsCompleted || !session.ready.Task.IsCompletedSuccessfully) throw new IOException("Proxy engine startup failed.");
            cancellationToken.ThrowIfCancellationRequested();
            session.lease = await Task.Run(() => SystemProxyLease.Activate(port), cancellationToken).ConfigureAwait(false);
            cancellationToken.ThrowIfCancellationRequested();
            if (session.Exit.IsCompleted) throw new IOException("Proxy engine terminated during activation.");
            return session;
        }
        catch
        {
            if (session != null)
            {
                try { await session.DisposeAsync().ConfigureAwait(false); }
                catch
                {
                    // Startup never handed this object to VpnService. Recovery must
                    // be able to acquire the persisted lease even if restoration failed.
                    session.lease?.ReleaseFailedStartupForRecovery();
                    session.lease = null;
                    throw;
                }
            }
            else
            {
                try
                {
                    if (process != null)
                    {
                        try { if (!process.HasExited) process.Kill(true); await process.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(8)).ConfigureAwait(false); }
                        catch (InvalidOperationException) { }
                        finally { process.Dispose(); }
                    }
                }
                finally
                {
                    job?.Dispose(); binaryLock?.Dispose(); configLock?.Dispose();
                    DeleteSessionFiles(directory);
                }
            }
            throw;
        }
    }

    internal static bool IsCurrentProcessElevated() =>
        new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator);

    internal static ProcessStartInfo CreateStartInfo(string configPath, string directory)
    {
        var start = CoreProcess.CreateStartInfo(configPath, directory);
        start.CreateNoWindow = true;
        // No console allocation or Ctrl+C broadcast: a proxy has no routes/driver to clean.
        // The mixed listener is loopback-only. WinINET cannot supply random credentials
        // silently, so another local Windows user can use this port while the app is ON.
        return start;
    }

    private async Task DrainAsync(StreamReader stream)
    {
        var buffer = new char[2048];
        var line = new StringBuilder(2048);
        var discard = false;
        var tail = "";
        try
        {
            int count;
            while ((count = await stream.ReadAsync(buffer).ConfigureAwait(false)) > 0)
            {
                var text = tail + new string(buffer, 0, count);
                if (text.Contains("sing-box started", StringComparison.Ordinal)) ready.TrySetResult();
                tail = text.Length > 80 ? text[^80..] : text;
                for (var i = 0; i < count; i++)
                {
                    if (buffer[i] == '\n')
                    {
                        if (!discard)
                        {
                            TrafficRecord? record;
                            lock (parser) record = parser.Parse(line.ToString().TrimEnd('\r'));
                            if (record != null) traffic(record);
                        }
                        line.Clear(); discard = false;
                    }
                    else if (!discard)
                    {
                        if (line.Length == 2048) { line.Clear(); discard = true; }
                        else line.Append(buffer[i]);
                    }
                }
            }
        }
        catch (Exception error) when (error is IOException or ObjectDisposedException) { }
    }

    public ValueTask DisposeAsync()
    {
        lock (disposeSync)
        {
            // Concurrent monitor/OFF calls share one task. Failed Windows restoration
            // can be retried by a later OFF rather than caching failure permanently.
            if (disposal == null || disposal.IsFaulted) disposal = DisposeCoreAsync();
            return new ValueTask(disposal);
        }
    }

    private async Task DisposeCoreAsync()
    {
        // Restore first so supported apps do not retain a dead localhost proxy.
        Exception? restoreFailure = null;
        try
        {
            var currentLease = lease;
            if (currentLease != null) await Task.Run(currentLease.Dispose).ConfigureAwait(false);
            lease = null;
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException) { restoreFailure = error; }
        if (!resourcesReleased)
        {
            try
            {
                // Every constructed session has already been assigned to this job.
                // Closing its KILL_ON_JOB_CLOSE handle also handles an exit/kill race.
                job.Dispose();
                await Exit.WaitAsync(TimeSpan.FromSeconds(8)).ConfigureAwait(false);
            }
            finally
            {
                job.Dispose();
                try { await drains.WaitAsync(TimeSpan.FromSeconds(5)).ConfigureAwait(false); }
                finally
                {
                    process.Dispose(); binaryLock.Dispose(); configLock.Dispose();
                    resourcesReleased = true;
                    DeleteSessionFiles(directory);
                }
            }
        }
        if (restoreFailure != null) throw new IOException("이전 Windows 프록시 설정을 복원하지 못했습니다. OFF를 다시 눌러 주세요.", restoreFailure);
    }

    private static void DeleteSessionFiles(string directory)
    {
        // Only the exact random session and known config created by this invocation.
        try { File.Delete(Path.Combine(directory, "config.json")); Directory.Delete(directory, false); }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException) { }
    }

    [StructLayout(LayoutKind.Sequential)] private struct BasicLimits
    { public long PerProcessUserTimeLimit, PerJobUserTimeLimit; public uint LimitFlags; public UIntPtr MinimumWorkingSetSize, MaximumWorkingSetSize; public uint ActiveProcessLimit; public UIntPtr Affinity; public uint PriorityClass, SchedulingClass; }
    [StructLayout(LayoutKind.Sequential)] private struct IoCounters
    { public ulong ReadOperationCount, WriteOperationCount, OtherOperationCount, ReadTransferCount, WriteTransferCount, OtherTransferCount; }
    [StructLayout(LayoutKind.Sequential)] private struct ExtendedLimits
    { public BasicLimits BasicLimitInformation; public IoCounters IoInfo; public UIntPtr ProcessMemoryLimit, JobMemoryLimit, PeakProcessMemoryUsed, PeakJobMemoryUsed; }
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern SafeFileHandle CreateJobObject(IntPtr attributes, string? name);
    [DllImport("kernel32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool SetInformationJobObject(SafeFileHandle job, int infoClass, ref ExtendedLimits limits, uint size);
    [DllImport("kernel32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool AssignProcessToJobObject(SafeFileHandle job, IntPtr process);
}
