using System.Reflection;
using System.Windows.Controls;
using System.Windows.Threading;
using YaoVpn.App;
using YaoVpn.App.Services;

namespace YaoVpn.Tests;

internal static class WindowLifecycleTests
{
    public static async Task RunAsync()
    {
        await RunOnStaAsync(async () =>
        {
            await WithWindowAsync(async (window, service, closed) =>
            {
                var mode = (ComboBox)window.FindName("ConnectionModeBox");
                var hint = (TextBlock)window.FindName("ConnectionModeHint");
                if (mode.SelectedIndex != 1 || !hint.Text.Contains("관리자 권한", StringComparison.Ordinal)
                    || !hint.Text.Contains("UDP", StringComparison.Ordinal))
                    throw new Exception("The initial window did not select TUN with its matching hint.");
                var cleanupAttempted = false;
                service.StatusChanged += status =>
                {
                    if (status.State == "DISCONNECTING") cleanupAttempted = true;
                };
                window.Close();
                if (closed.IsCompleted)
                    throw new Exception("The window closed recursively from its original Closing event.");
                await closed;
                if (!cleanupAttempted || service.Status.State != "OFF")
                    throw new Exception("An OFF window closed without completing service cleanup.");
            });
        });
        await RunOnStaAsync(async () =>
        {
            await WithWindowAsync(async (window, service, closed) =>
            {
                var attempts = 0;
                service.StatusChanged += status =>
                {
                    if (status.State != "DISCONNECTING") return;
                    attempts++;
                    throw new IOException("Simulated cleanup failure.");
                };
                window.Close();
                await closed;
                if (attempts != 1 || service.Status.State != "CLEANUP-REQUIRED")
                    throw new Exception("The cleanup-failure test did not exercise a failed VPN shutdown.");
            });
        });
        await RunOnStaAsync(async () =>
        {
            await WithWindowAsync(async (window, service, closed) =>
            {
                var gate = Field<SemaphoreSlim>(service, "gate");
                await gate.WaitAsync();
                var attempts = 0;
                service.StatusChanged += status =>
                {
                    if (status.State == "DISCONNECTING") attempts++;
                };
                try
                {
                    window.Close();
                    window.Close();
                    await Dispatcher.Yield(DispatcherPriority.Background);
                    if (closed.IsCompleted)
                        throw new Exception("Repeated close requests bypassed pending VPN cleanup.");
                }
                finally { gate.Release(); }
                await closed;
                if (attempts != 1)
                    throw new Exception("Repeated close requests started more than one cleanup.");
            });
        });
        await RunOnStaAsync(async () =>
        {
            await WithWindowAsync(async (window, service, closed) =>
            {
                var gate = Field<SemaphoreSlim>(service, "gate");
                await gate.WaitAsync();
                var cleanupAttempted = false;
                service.StatusChanged += status =>
                {
                    if (status.State == "DISCONNECTING") cleanupAttempted = true;
                };
                try
                {
                    window.Close();
                    await Task.Delay(50);
                    if (closed.IsCompleted || cleanupAttempted)
                        throw new Exception("The window did not wait for the current service operation.");
                }
                finally { gate.Release(); }
                await closed;
                if (!cleanupAttempted || service.Status.State != "OFF")
                    throw new Exception("Deferred VPN cleanup did not finish before the window closed.");
            });
        });
        Console.WriteLine("PASS: TUN startup selection, OFF window shutdown, failed cleanup exit, repeated close, pending-operation cleanup");
    }

    private static async Task WithWindowAsync(Func<MainWindow, VpnService, Task, Task> test)
    {
        // Do not Show: Loaded recovers the real user's proxy and reads their subscription.
        var window = new MainWindow();
        var service = Field<VpnService>(window, "_service");
        var closed = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var closeCount = 0;
        window.Closed += (_, _) => { closeCount++; closed.TrySetResult(); };
        try
        {
            await test(window, service, closed.Task);
            if (closeCount != 1) throw new Exception("The main window did not close exactly once.");
        }
        finally
        {
            if (!closed.Task.IsCompleted)
            {
                typeof(MainWindow).GetField("_allowClose", BindingFlags.Instance | BindingFlags.NonPublic)!
                    .SetValue(window, true);
                window.Close();
            }
        }
    }

    private static async Task RunOnStaAsync(Func<Task> test)
    {
        var completion = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var thread = new Thread(() =>
        {
            var dispatcher = Dispatcher.CurrentDispatcher;
            SynchronizationContext.SetSynchronizationContext(new DispatcherSynchronizationContext(dispatcher));
            dispatcher.BeginInvoke(new Action(async () =>
            {
                try { await test(); completion.TrySetResult(); }
                catch (Exception error) { completion.TrySetException(error); }
                finally { dispatcher.BeginInvokeShutdown(DispatcherPriority.Send); }
            }));
            Dispatcher.Run();
        }) { IsBackground = true, Name = "Window lifecycle regression test" };
        thread.SetApartmentState(ApartmentState.STA);
        thread.Start();
        // A blocked Closing handler or modal error must fail the suite, not hang it.
        await completion.Task.WaitAsync(TimeSpan.FromSeconds(15));
    }

    private static T Field<T>(object instance, string name) =>
        (T)(instance.GetType().GetField(name, BindingFlags.Instance | BindingFlags.NonPublic)?.GetValue(instance)
            ?? throw new Exception($"Missing lifecycle test field: {name}."));
}
