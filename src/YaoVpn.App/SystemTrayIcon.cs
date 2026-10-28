using System.Windows;
using Forms = System.Windows.Forms;

namespace YaoVpn.App;

internal sealed class SystemTrayIcon : IDisposable
{
    private readonly System.Drawing.Icon icon;
    private readonly Forms.ContextMenuStrip menu;
    private readonly Forms.NotifyIcon notifyIcon;

    public SystemTrayIcon(Action open, Action exit)
    {
        using var resource = (Application.GetResourceStream(new Uri("/YaoVPN;component/Assets/AppIcon.ico", UriKind.Relative))
            ?? throw new IOException("Application icon unavailable.")).Stream;
        using var sourceIcon = new System.Drawing.Icon(resource);
        icon = (System.Drawing.Icon)sourceIcon.Clone();
        menu = new Forms.ContextMenuStrip();
        menu.Items.Add("열기", null, (_, _) => open());
        menu.Items.Add(new Forms.ToolStripSeparator());
        menu.Items.Add("종료", null, (_, _) => exit());
        notifyIcon = new Forms.NotifyIcon { Icon = icon, Text = "Yao VPN", ContextMenuStrip = menu };
        notifyIcon.DoubleClick += (_, _) => open();
    }

    public bool Visible
    {
        get => notifyIcon.Visible;
        set => notifyIcon.Visible = value;
    }

    public void Dispose()
    {
        notifyIcon.Visible = false;
        notifyIcon.Dispose();
        menu.Dispose();
        icon.Dispose();
    }
}
