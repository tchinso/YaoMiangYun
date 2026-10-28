using System.Collections;
using System.Reflection;
using System.Windows;
using System.Windows.Threading;
using YaoVpn.App;
using YaoVpn.App.Services;

namespace YaoVpn.Tests;

internal static class TrayLifecycleTests
{
    public static async Task RunAsync()
    {
        var completion = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var thread = new Thread(() =>
        {
            var dispatcher = Dispatcher.CurrentDispatcher;
            SynchronizationContext.SetSynchronizationContext(new DispatcherSynchronizationContext(dispatcher));
            dispatcher.BeginInvoke(new Action(async () =>
            {
                try
                {
                    await CheckWindowAsync();
                    completion.TrySetResult();
                }
                catch (Exception error)
                {
                    completion.TrySetException(error is TargetInvocationException { InnerException: { } inner } ? inner : error);
                }
                finally { dispatcher.BeginInvokeShutdown(DispatcherPriority.Send); }
            }));
            Dispatcher.Run();
        }) { IsBackground = true, Name = "Tray lifecycle regression test" };
        thread.SetApartmentState(ApartmentState.STA);
        thread.Start();
        await completion.Task.WaitAsync(TimeSpan.FromSeconds(15));
        Console.WriteLine("PASS: minimize to tray, menu/double-click restore, maximized restore, tray exit and icon cleanup");
    }

    private static async Task CheckWindowAsync()
    {
        var window = new MainWindow();
        // Exercise a real HWND without recovering the user's proxy or reading saved credentials.
        var loaded = typeof(MainWindow).GetMethod("Window_Loaded", BindingFlags.Instance | BindingFlags.NonPublic)!
            .CreateDelegate<RoutedEventHandler>(window);
        window.Loaded -= loaded;
        var tray = Field<SystemTrayIcon>(window, "_trayIcon");
        var notifyIcon = Field<object>(tray, "notifyIcon");
        var menu = Field<object>(tray, "menu");
        var service = Field<VpnService>(window, "_service");
        var closed = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        window.Closed += (_, _) => closed.TrySetResult();
        try
        {
            window.Show();
            await Dispatcher.Yield(DispatcherPriority.ApplicationIdle);
            if (!window.IsVisible || tray.Visible)
                throw new Exception("A newly opened window had an unexpected tray state.");

            foreach (var state in new[] { WindowState.Normal, WindowState.Maximized })
            {
                window.WindowState = state;
                await Dispatcher.Yield(DispatcherPriority.ApplicationIdle);
                window.WindowState = WindowState.Minimized;
                await Dispatcher.Yield(DispatcherPriority.ApplicationIdle);
                if (window.IsVisible || !tray.Visible || closed.Task.IsCompleted)
                    throw new Exception("Minimizing did not hide the window and expose its tray icon.");
                if (service.Status.State != "OFF")
                    throw new Exception("Minimizing unexpectedly started VPN cleanup.");

                if (state == WindowState.Normal) ClickMenuItem(menu, "열기");
                else notifyIcon.GetType().GetMethod("OnDoubleClick", BindingFlags.Instance | BindingFlags.NonPublic)!
                    .Invoke(notifyIcon, [EventArgs.Empty]);
                await Dispatcher.Yield(DispatcherPriority.ApplicationIdle);
                if (!window.IsVisible || window.WindowState != state || tray.Visible)
                    throw new Exception("Tray restore did not restore the previous window state and hide its icon.");
            }

            window.WindowState = WindowState.Minimized;
            await Dispatcher.Yield(DispatcherPriority.ApplicationIdle);
            var cleanupAttempted = false;
            service.StatusChanged += status =>
            {
                if (status.State == "DISCONNECTING") cleanupAttempted = true;
            };
            ClickMenuItem(menu, "종료");
            await closed.Task;
            if (!cleanupAttempted || service.Status.State != "OFF" || tray.Visible)
                throw new Exception("Tray exit did not clean up VPN state, close the window, and remove its icon.");
        }
        finally
        {
            if (!closed.Task.IsCompleted)
            {
                typeof(MainWindow).GetField("_allowClose", BindingFlags.Instance | BindingFlags.NonPublic)!
                    .SetValue(window, true);
                window.Close();
                await service.DisposeAsync();
            }
        }
    }

    private static void ClickMenuItem(object menu, string text)
    {
        var items = (IEnumerable)menu.GetType().GetProperty("Items")!.GetValue(menu)!;
        var item = items.Cast<object>().Single(candidate =>
            string.Equals(candidate.GetType().GetProperty("Text")!.GetValue(candidate), text));
        item.GetType().GetMethod("PerformClick", Type.EmptyTypes)!.Invoke(item, null);
    }

    private static T Field<T>(object instance, string name) =>
        (T)(instance.GetType().GetField(name, BindingFlags.Instance | BindingFlags.NonPublic)?.GetValue(instance)
            ?? throw new Exception($"Missing tray test field: {name}."));
}
