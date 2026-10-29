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
            RoutingModeBox.SelectedIndex = policy.DefaultRoute switch { "auto" => 0, "vpn" => 1, _ => 2 };
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
        await SaveAsync(service.CurrentRoutingPolicy with
        {
            DefaultRoute = RoutingModeBox.SelectedIndex switch { 0 => "auto", 1 => "vpn", _ => "direct" }
        });
    }

    private async void VpnRuleButton_Click(object sender, RoutedEventArgs e) => await AddDomainAsync("vpn");
    private async void DirectRuleButton_Click(object sender, RoutedEventArgs e) => await AddDomainAsync("direct");

    private async Task AddDomainAsync(string route)
    {
        if (!CanEdit) return;
        string domain;
        try { domain = RoutingPolicy.NormalizeDomain(DomainBox.Text.Trim()); }
        catch (FormatException error) { RoutingHint.Text = error.Message; DomainBox.Focus(); return; }
        await SaveAsync(service.CurrentRoutingPolicy.AddDomains([domain], route));
    }

    private async void RemoveRuleButton_Click(object sender, RoutedEventArgs e)
    {
        if (!CanEdit || RuleList.SelectedItem is not DomainRule selected) return;
        var current = service.CurrentRoutingPolicy;
        await SaveAsync(current with
        {
            VpnDomains = current.VpnDomains.Where(value => value != selected.Domain).ToArray(),
            DirectDomains = current.DirectDomains.Where(value => value != selected.Domain).ToArray()
        });
    }

    private async void RemoveAllRulesButton_Click(object sender, RoutedEventArgs e)
    {
        if (!CanEdit) return;
        var current = service.CurrentRoutingPolicy;
        if (current.VpnDomains.Length + current.DirectDomains.Length == 0)
        {
            RoutingHint.Text = "삭제할 사이트 규칙이 없습니다.";
            return;
        }
        if (MessageBox.Show(this,
            "저장된 모든 사이트 규칙을 정말 삭제하시겠습니까? 이 작업은 되돌릴 수 없습니다.\n\n나머지 사이트의 기본 통신 경로는 유지되며, 삭제는 다음 VPN 연결부터 적용됩니다.",
            "모든 규칙 삭제", MessageBoxButton.YesNo, MessageBoxImage.Warning, MessageBoxResult.No) != MessageBoxResult.Yes)
            return;
        await SaveAsync(service.CurrentRoutingPolicy with { VpnDomains = [], DirectDomains = [] });
    }

    private async void AddAllTrafficVpnButton_Click(object sender, RoutedEventArgs e)
    {
        if (!CanEdit) return;
        var domains = TrafficList.Items.Cast<TrafficRecord>().Where(record => record.IsDomain)
            .OrderBy(record => record.Timestamp)
            .Select(record => string.Join('.', record.Host.Split('.').TakeLast(3)))
            .Distinct(StringComparer.Ordinal).ToArray();
        if (domains.Length == 0)
        {
            RoutingHint.Text = "통신 로그에 추가할 도메인이 없습니다. IP 주소는 사이트 규칙에 추가하지 않습니다.";
            return;
        }
        await SaveAsync(service.CurrentRoutingPolicy.AddDomains(domains, "vpn"));
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
        RemoveAllRulesButton.IsEnabled = CanEdit;
        AddAllTrafficVpnButton.IsEnabled = CanEdit;
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
