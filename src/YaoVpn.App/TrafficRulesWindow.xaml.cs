using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Windows;
using System.Windows.Controls;
using YaoVpn.App.Services;
using YaoVpn.Core;

namespace YaoVpn.App;

/// <summary>Presentation only. The owner serializes every service operation and owns the log timer.</summary>
public partial class TrafficRulesWindow : Window
{
    private readonly VpnService service;
    private readonly Func<RoutingPolicy, Task<bool>> savePolicy;
    private readonly Action clearTraffic;
    private bool loadingPolicy;
    private bool saving;
    private bool ownerBusy;
    private bool ownerClosing;
    private bool allowClose;
    private Task? pendingSave;
    private sealed record DomainRule(string Domain, string Route)
    {
        public string Label => Domain + (Route == "vpn" ? "  → VPN" : "  → 일반 통신");
    }

    public TrafficRulesWindow(VpnService service, ObservableCollection<TrafficRecord> traffic,
        Func<RoutingPolicy, Task<bool>> savePolicy, Action clearTraffic)
    {
        this.service = service;
        this.savePolicy = savePolicy;
        this.clearTraffic = clearTraffic;
        InitializeComponent();
        TrafficList.ItemsSource = traffic;
        RefreshPolicy();
    }

    public Task? PendingSave => pendingSave;

    public void SetOwnerState(bool busy, bool closing, VpnStatus status)
    {
        ownerBusy = busy;
        ownerClosing = closing;
        ConnectionStateText.Text = closing ? "앱을 종료하고 연결 설정을 복원하고 있습니다."
            : status.State == "CLEANUP-REQUIRED" ? "연결 정리가 필요합니다. 기본 창에서 OFF를 눌러 주세요."
            : status.IsConnected ? "VPN 연결 중 · 여기서 저장한 규칙은 OFF → ON 후 적용됩니다."
            : "VPN 꺼짐 · 규칙은 다음 연결부터 적용됩니다.";
        UpdateControls();
    }

    public void RefreshPolicy()
    {
        loadingPolicy = true;
        try
        {
            var policy = service.CurrentRoutingPolicy;
            var selectedDomain = (RuleList.SelectedItem as DomainRule)?.Domain;
            RoutingModeBox.SelectedIndex = policy.DefaultRoute == "vpn" ? 0 : 1;
            var rules = policy.VpnDomains.Select(domain => new DomainRule(domain, "vpn"))
                .Concat(policy.DirectDomains.Select(domain => new DomainRule(domain, "direct")))
                .OrderBy(rule => rule.Domain, StringComparer.Ordinal).ToArray();
            RuleList.ItemsSource = rules;
            RuleList.SelectedItem = rules.FirstOrDefault(rule => rule.Domain == selectedDomain);
        }
        finally { loadingPolicy = false; }
    }

    private async void RoutingModeBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (loadingPolicy || !CanEdit || RoutingModeBox.SelectedIndex < 0) return;
        await SaveAsync(service.CurrentRoutingPolicy with { DefaultRoute = RoutingModeBox.SelectedIndex == 1 ? "direct" : "vpn" });
    }

    private async void VpnRuleButton_Click(object sender, RoutedEventArgs e) => await AddDomainAsync("vpn");
    private async void DirectRuleButton_Click(object sender, RoutedEventArgs e) => await AddDomainAsync("direct");

    private async Task AddDomainAsync(string route)
    {
        if (!CanEdit) return;
        string domain;
        try { domain = RoutingPolicy.NormalizeDomain(DomainBox.Text.Trim()); }
        catch (FormatException error) { RoutingHint.Text = error.Message; DomainBox.Focus(); return; }
        var current = service.CurrentRoutingPolicy;
        var vpn = current.VpnDomains.Where(value => value != domain).ToList();
        var direct = current.DirectDomains.Where(value => value != domain).ToList();
        (route == "vpn" ? vpn : direct).Add(domain);
        await SaveAsync(new(current.DefaultRoute, vpn.ToArray(), direct.ToArray()));
    }

    private async void RemoveRuleButton_Click(object sender, RoutedEventArgs e)
    {
        if (!CanEdit || RuleList.SelectedItem is not DomainRule selected) return;
        var current = service.CurrentRoutingPolicy;
        await SaveAsync(new(current.DefaultRoute, current.VpnDomains.Where(value => value != selected.Domain).ToArray(),
            current.DirectDomains.Where(value => value != selected.Domain).ToArray()));
    }

    private async Task SaveAsync(RoutingPolicy policy)
    {
        if (!CanEdit) return;
        try { policy = RoutingPolicy.Validate(policy); }
        catch (FormatException error) { RoutingHint.Text = error.Message; RefreshPolicy(); return; }
        saving = true;
        UpdateControls();
        var task = SaveCoreAsync(policy);
        pendingSave = task;
        try { await task; }
        finally
        {
            if (ReferenceEquals(pendingSave, task)) pendingSave = null;
            saving = false;
            if (!allowClose) UpdateControls();
        }
    }

    private async Task SaveCoreAsync(RoutingPolicy policy)
    {
        try
        {
            var saved = await savePolicy(policy);
            if (ownerClosing || allowClose) return;
            RefreshPolicy();
            RoutingHint.Text = !saved ? "규칙을 저장하지 못했습니다. 잠시 후 다시 시도해 주세요."
                : service.Status.IsConnected ? "저장했습니다. OFF → ON 후 적용됩니다."
                : "저장했습니다. 다음 VPN 연결부터 적용됩니다.";
        }
        catch (OperationCanceledException) { if (!ownerClosing) RoutingHint.Text = "규칙 저장을 취소했습니다."; }
        catch { if (!ownerClosing) RoutingHint.Text = "사이트 규칙을 저장하지 못했습니다."; }
    }

    private void TrafficList_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (TrafficList.SelectedItem is TrafficRecord { IsDomain: true } record) DomainBox.Text = record.Host;
    }

    private void ClearTrafficButton_Click(object sender, RoutedEventArgs e)
    {
        if (!ownerClosing) clearTraffic();
    }

    private bool CanEdit => !ownerBusy && !ownerClosing && !saving && !allowClose;

    private void UpdateControls()
    {
        RoutingModeBox.IsEnabled = CanEdit;
        DomainBox.IsEnabled = CanEdit;
        VpnRuleButton.IsEnabled = CanEdit;
        DirectRuleButton.IsEnabled = CanEdit;
        RemoveRuleButton.IsEnabled = CanEdit;
        ClearTrafficButton.IsEnabled = !ownerClosing;
    }

    private void HideButton_Click(object sender, RoutedEventArgs e) => Hide();

    private void Window_Closing(object? sender, CancelEventArgs e)
    {
        if (allowClose) return;
        e.Cancel = true;
        Hide();
    }

    public void CloseWithOwner()
    {
        ownerClosing = true;
        allowClose = true;
        Close();
    }
}
