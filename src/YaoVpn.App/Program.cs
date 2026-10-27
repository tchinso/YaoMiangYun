using System.Security.Principal;
using System.Windows;
using YaoVpn.App.Services;

namespace YaoVpn.App;

public static class Program
{
    [STAThread]
    public static int Main(string[] args)
    {
        if (args is ["--broker", var pipeName, var parent] && pipeName.StartsWith("YaoVPN-", StringComparison.Ordinal)
            && Guid.TryParseExact(pipeName[7..], "N", out _) && int.TryParse(parent, out var parentPid) && parentPid > 0)
        {
            if (!new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator)) return 2;
            return Broker.RunAsync(pipeName, parentPid).GetAwaiter().GetResult();
        }
        if (args.Length != 0) return 2;
        using var mutex = new Mutex(true, "Local\\YaoVPN.UI", out var first);
        if (!first)
        {
            MessageBox.Show("Yao VPN이 이미 실행 중입니다. 열려 있는 창을 확인해 주세요.", "Yao VPN");
            return 0;
        }
        var app = new Application { ShutdownMode = ShutdownMode.OnMainWindowClose };
        app.DispatcherUnhandledException += (_, e) =>
        {
            // Never show provider data, credential-bearing exception text, or raw core logs.
            MessageBox.Show("작업을 완료하지 못했습니다. 앱을 닫은 뒤 다시 실행해 주세요.", "Yao VPN");
            e.Handled = true;
        };
        app.Run(new MainWindow());
        return 0;
    }
}
