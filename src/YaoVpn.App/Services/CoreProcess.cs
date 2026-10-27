using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace YaoVpn.App.Services;

internal sealed class CoreProcess : IAsyncDisposable
{
    private readonly Process process;
    private readonly SafeFileHandle job;
    private readonly Task drainOutput;
    private readonly Task drainError;
    private readonly TrafficLogParser trafficParser = new();
    private readonly Action<TrafficRecord>? traffic;
    private readonly TaskCompletionSource ready = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private static readonly ConsoleHandler Handler = _ => true;

    private CoreProcess(Process process, SafeFileHandle job, Action<TrafficRecord>? traffic)
    {
        this.process = process;
        this.job = job;
        this.traffic = traffic;
        drainOutput = DrainAsync(process.StandardOutput);
        drainError = DrainAsync(process.StandardError);
    }

    public Task Exit => process.WaitForExitAsync();
    public bool HasExited => process.HasExited;

    public static async Task<CoreProcess> StartAsync(string configPath, string directory, CancellationToken token, Action<TrafficRecord>? traffic = null)
    {
        // A private hidden console allows Go to receive Ctrl+C and restore routes/DNS on normal OFF.
        if (GetConsoleWindow() == IntPtr.Zero && !AllocConsole()) throw new IOException("Console setup failed.");
        ShowWindow(GetConsoleWindow(), 0);
        if (!SetConsoleCtrlHandler(Handler, true)) throw new IOException("Console control setup failed.");
        var job = CreateJobObject(IntPtr.Zero, null);
        if (job.IsInvalid) throw new IOException("Job creation failed.");
        // No child processes are needed by the pinned core: also cap the job at one
        // process so a compromised engine cannot spawn a shell from this job.
        var limits = new ExtendedLimits { BasicLimitInformation = new BasicLimits { LimitFlags = 0x2000 | 0x8, ActiveProcessLimit = 1 } };
        if (!SetInformationJobObject(job, 9, ref limits, (uint)Marshal.SizeOf<ExtendedLimits>()))
        { job.Dispose(); throw new IOException("Job setup failed."); }
        var start = CreateStartInfo(configPath, directory);
        Process? child = null;
        CoreProcess? instance = null;
        try
        {
            child = Process.Start(start) ?? throw new IOException("Core start failed.");
            if (!AssignProcessToJobObject(job, child.Handle)) throw new IOException("Core job assignment failed.");
            instance = new CoreProcess(child, job, traffic);
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(token);
            timeout.CancelAfter(TimeSpan.FromSeconds(25));
            await Task.WhenAny(instance.ready.Task, instance.Exit).WaitAsync(timeout.Token);
            if (child.HasExited || !instance.ready.Task.IsCompletedSuccessfully) throw new IOException("Core startup failed.");
            return instance;
        }
        catch
        {
            if (instance != null) await instance.DisposeAsync();
            else
            {
                if (child != null) { try { child.Kill(true); await child.WaitForExitAsync(); } catch (InvalidOperationException) { } child.Dispose(); }
                job.Dispose();
            }
            throw;
        }
    }

    internal static ProcessStartInfo CreateStartInfo(string configPath, string directory)
    {
        var start = new ProcessStartInfo(BinaryTrust.CorePath)
        {
            WorkingDirectory = directory, UseShellExecute = false, CreateNoWindow = false,
            RedirectStandardOutput = true, RedirectStandardError = true, RedirectStandardInput = true,
            WindowStyle = ProcessWindowStyle.Hidden
        };
        start.ArgumentList.Add("run"); start.ArgumentList.Add("-c"); start.ArgumentList.Add(configPath);
        start.ArgumentList.Add("-D"); start.ArgumentList.Add(directory);
        // The elevated network parser must not inherit proxy settings, Go TLS/debug
        // overrides or user-controlled executable search paths from the UI process.
        start.Environment.Clear();
        var windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        start.Environment["SystemRoot"] = windows;
        start.Environment["WINDIR"] = windows;
        start.Environment["PATH"] = Environment.SystemDirectory;
        start.Environment["TEMP"] = directory;
        start.Environment["TMP"] = directory;
        start.Environment["NoDefaultCurrentDirectoryInExePath"] = "1";
        return start;
    }

    private async Task DrainAsync(StreamReader reader)
    {
        // Fixed-size reads: untrusted peer errors cannot cause unbounded line buffering or credential logs.
        var chars = new char[2048];
        var tail = "";
        var line = new StringBuilder(2048);
        var discardLine = false;
        try
        {
            int count;
            while ((count = await reader.ReadAsync(chars)) > 0)
            {
                var text = tail + new string(chars, 0, count);
                if (text.Contains("sing-box started", StringComparison.Ordinal)) ready.TrySetResult();
                tail = text.Length > 80 ? text[^80..] : text;
                if (traffic != null)
                {
                    for (var i = 0; i < count; i++)
                    {
                        if (chars[i] == '\n')
                        {
                            if (!discardLine)
                            {
                                TrafficRecord? record;
                                lock (trafficParser) record = trafficParser.Parse(line.ToString().TrimEnd('\r'));
                                if (record != null) traffic(record);
                            }
                            line.Clear();
                            discardLine = false;
                        }
                        else if (!discardLine)
                        {
                            if (line.Length == 2048) { line.Clear(); discardLine = true; }
                            else line.Append(chars[i]);
                        }
                    }
                }
            }
        }
        catch (IOException) { }
        catch (ObjectDisposedException) { }
    }

    public async ValueTask DisposeAsync()
    {
        try
        {
            if (!process.HasExited)
            {
                GenerateConsoleCtrlEvent(0, 0);
                try { await process.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(8)); }
                catch (TimeoutException) { process.Kill(true); await process.WaitForExitAsync(); }
            }
        }
        finally
        {
            job.Dispose();
            try { await Task.WhenAll(drainOutput, drainError).WaitAsync(TimeSpan.FromSeconds(5)); }
            finally { process.Dispose(); }
        }
    }

    private delegate bool ConsoleHandler(uint controlType);
    [DllImport("kernel32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool AllocConsole();
    [DllImport("kernel32.dll")] private static extern IntPtr GetConsoleWindow();
    [DllImport("user32.dll")] private static extern bool ShowWindow(IntPtr hwnd, int command);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool SetConsoleCtrlHandler(ConsoleHandler handler, bool add);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool GenerateConsoleCtrlEvent(uint controlEvent, uint processGroupId);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern SafeFileHandle CreateJobObject(IntPtr securityAttributes, string? name);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool SetInformationJobObject(SafeFileHandle job, int informationClass, ref ExtendedLimits limits, uint size);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool AssignProcessToJobObject(SafeFileHandle job, IntPtr process);
    [StructLayout(LayoutKind.Sequential)] private struct BasicLimits
    { public long PerProcessUserTimeLimit, PerJobUserTimeLimit; public uint LimitFlags; public UIntPtr MinimumWorkingSetSize, MaximumWorkingSetSize; public uint ActiveProcessLimit; public UIntPtr Affinity; public uint PriorityClass, SchedulingClass; }
    [StructLayout(LayoutKind.Sequential)] private struct IoCounters
    { public ulong ReadOperationCount, WriteOperationCount, OtherOperationCount, ReadTransferCount, WriteTransferCount, OtherTransferCount; }
    [StructLayout(LayoutKind.Sequential)] private struct ExtendedLimits
    { public BasicLimits BasicLimitInformation; public IoCounters IoInfo; public UIntPtr ProcessMemoryLimit, JobMemoryLimit, PeakProcessMemoryUsed, PeakJobMemoryUsed; }
}
