using System.Reflection;
using System.Collections.ObjectModel;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Threading;
using YaoVpn.App;
using YaoVpn.App.Services;
using YaoVpn.Core;

namespace YaoVpn.Tests;

internal static class WindowLifecycleTests
{
    public static async Task RunAsync()
    {
        await RunOnStaAsync(async () =>
        {
            await using var service = new VpnService();
            var policyProperty = typeof(VpnService).GetProperty(nameof(VpnService.CurrentRoutingPolicy))!;
            policyProperty.SetValue(service, new RoutingPolicy("direct", ["keep.example"], ["move.example", "stay.example"]));
            var traffic = new ObservableCollection<TrafficRecord>();
            void Log(string host) => traffic.Add(new(DateTimeOffset.Now, host, 443, "TCP", "direct"));
            Log("move.example");
            Log("new.example");
            Log("new.example");
            Log("192.0.2.1");
            Log("2001:db8::1");
            var saves = 0;
            var pending = new TaskCompletionSource<bool>();
            var window = new TrafficRulesWindow(service, traffic, async policy =>
            {
                saves++;
                await pending.Task;
                policyProperty.SetValue(service, policy);
                return true;
            }, traffic.Clear);
            try
            {
                var add = (Button)window.FindName("AddAllTrafficVpnButton");
                var removeAll = (Button)window.FindName("RemoveAllRulesButton");
                add.RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
                if (add.IsEnabled || removeAll.IsEnabled || window.PendingSave == null)
                    throw new Exception("Bulk actions did not lock while saving.");
                var save = window.PendingSave;
                pending.SetResult(true);
                await save;
                var policy = service.CurrentRoutingPolicy;
                if (saves != 1 || policy.DefaultRoute != "direct"
                    || !policy.VpnDomains.SequenceEqual(new[] { "keep.example", "move.example", "new.example" })
                    || !policy.DirectDomains.SequenceEqual(new[] { "stay.example" }))
                    throw new Exception("Bulk VPN rules did not merge, deduplicate, exclude IPs, or preserve unrelated rules.");
                if (!add.IsEnabled || !removeAll.IsEnabled)
                    throw new Exception("Bulk actions remained locked after saving.");
                ((Button)window.FindName("ClearTrafficButton")).RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
                add.RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
                if (saves != 1 || traffic.Count != 0)
                    throw new Exception("Cleared traffic was reused for bulk rules.");
                for (var i = 0; i < RoutingPolicy.MaximumRules; i++) Log($"site{i}.example");
                add.RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
                if (saves != 2 || service.CurrentRoutingPolicy.VpnDomains.Length != RoutingPolicy.MaximumRules
                    || service.CurrentRoutingPolicy.DirectDomains.Length != 0
                    || service.CurrentRoutingPolicy.VpnDomains.Contains("keep.example")
                    || service.CurrentRoutingPolicy.RuleOrder[0] != "site0.example")
                    throw new Exception("Bulk rules did not evict older rules across both routes.");
                ((TextBox)window.FindName("DomainBox")).Text = "manual.example";
                ((Button)window.FindName("DirectRuleButton")).RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
                if (saves != 3 || service.CurrentRoutingPolicy.VpnDomains.Contains("site0.example")
                    || !service.CurrentRoutingPolicy.DirectDomains.SequenceEqual(new[] { "manual.example" }))
                    throw new Exception("Manual rule addition did not evict the oldest bulk rule.");
                window.SetOwnerState(true, false, service.Status);
                if (add.IsEnabled || removeAll.IsEnabled)
                    throw new Exception("Bulk actions were enabled while the owner was busy.");
            }
            finally { window.CloseWithOwner(); }
        });
        Console.WriteLine("PASS: bulk VPN rule merge, IP exclusion, save locking, cleared logs, oldest-rule eviction for bulk and manual additions");
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
