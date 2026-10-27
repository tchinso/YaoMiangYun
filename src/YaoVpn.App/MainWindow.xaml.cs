using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Threading;
using YaoVpn.App.Services;
using YaoVpn.Core;

namespace YaoVpn.App;

public partial class MainWindow : Window
{
    private readonly VpnService _service;
    private VpnStatus _status;
    private CancellationTokenSource? _operationCancellation;
    private Task? _activeTask;
    private Task? _stopTask;
    private bool _working;
    private bool _powerRequested;
    private bool _stopping;
    private bool _needsDisconnect;
    private bool _closing;
    private bool _allowClose;
    private string? _errorMessage;
    private readonly ObservableCollection<TrafficRecord> _traffic = [];
    private readonly DispatcherTimer _trafficTimer;
    private TrafficRulesWindow? _rulesWindow;

    public MainWindow()
    {
        InitializeComponent();
        _service = new VpnService();
        _status = _service.Status;
        _service.StatusChanged += Service_StatusChanged;
        _trafficTimer = new DispatcherTimer(TimeSpan.FromMilliseconds(500), DispatcherPriority.Background,
            (_, _) => FlushTraffic(), Dispatcher);
        UpdateControls();
    }

    private async void Window_Loaded(object sender, RoutedEventArgs e)
    {
        var recovered = await RunOperationAsync(cancellationToken => _service.RecoverProxyAsync(cancellationToken),
            "이전 프록시 설정 복원을 확인하지 못했습니다. OFF를 눌러 다시 복원해 주세요.");
        // A second operation must not erase a recovery error or present ready-to-connect.
        if (!recovered || _closing) return;
        await RunOperationAsync(async cancellationToken =>
        {
            await _service.LoadRoutingPolicyAsync(cancellationToken);
            _rulesWindow?.RefreshPolicy();
            var result = await _service.LoadSavedAsync(cancellationToken);
            if (_closing) return;
            SubscriptionBox.Password = _service.SavedUrl ?? string.Empty;
            if (result is not null) SetServers(result);
        }, "저장된 구독을 불러오지 못했습니다. 구독 주소를 다시 입력해 주세요.");
    }

    private void RulesWindowButton_Click(object sender, RoutedEventArgs e)
    {
        if (_closing) return;
        if (_rulesWindow == null)
        {
            var window = new TrafficRulesWindow(_service, _traffic, SavePolicyAsync, ClearTraffic) { Owner = this };
            window.Closed += (_, _) => { if (ReferenceEquals(_rulesWindow, window)) _rulesWindow = null; };
            _rulesWindow = window;
        }
        _rulesWindow.RefreshPolicy();
        _rulesWindow.SetOwnerState(_working || _stopping || _needsDisconnect || _status.IsBusy, _closing, _status);
        _rulesWindow.Show();
        if (_rulesWindow.WindowState == WindowState.Minimized) _rulesWindow.WindowState = WindowState.Normal;
        _rulesWindow.Activate();
    }

    private Task<bool> SavePolicyAsync(RoutingPolicy policy)
    {
        if (_needsDisconnect || _stopping) return Task.FromResult(false);
        return RunOperationAsync(async cancellationToken =>
        {
            await _service.SaveRoutingPolicyAsync(RoutingPolicy.Validate(policy), cancellationToken);
        }, "사이트 규칙을 저장하지 못했습니다.");
    }

    private void ClearTraffic()
    {
        if (_closing) return;
        _service.ClearTraffic();
        _traffic.Clear();
    }

    private async void RefreshButton_Click(object sender, RoutedEventArgs e)
    {
        if (_working || _stopping || _closing || _status.IsConnected || _needsDisconnect) return;
        var url = SubscriptionBox.Password.Trim();
        if (string.IsNullOrWhiteSpace(url))
        {
            _errorMessage = "먼저 구독 주소를 입력해 주세요.";
            UpdateControls();
            SubscriptionBox.Focus();
            return;
        }
        await RunOperationAsync(async cancellationToken =>
        {
            var result = await _service.LoadSubscriptionAsync(url, cancellationToken);
            if (!_closing) SetServers(result);
        }, "구독을 불러오지 못했습니다. 구독 주소·만료 여부·네트워크 상태를 확인해 주세요.");
    }

    private async void PowerButton_Click(object sender, RoutedEventArgs e)
    {
        if (_closing || _stopping) return;
        if (_powerRequested || _status.IsConnected || _needsDisconnect)
        {
            _stopTask = StopConnectionAsync();
            try { await _stopTask; }
            finally { _stopTask = null; }
            return;
        }
        if (_working || ServerBox.SelectedItem is not ServerEntry { IsConnectable: true } entry) return;
        _powerRequested = true;
        TestResultText.Text = "실제 VPN 연결을 확인하고 있어요…";
        IpResultText.Text = "연결 후 실제 VPN IP·국가를 자동 확인합니다.";
        var mode = ConnectionModeBox.SelectedIndex == 1 ? ConnectionMode.SystemTun : ConnectionMode.AppProxy;
        await RunOperationAsync(async cancellationToken =>
        {
            await _service.ConnectAsync(entry.Node, mode, cancellationToken);
            if (!_service.Status.IsConnected || _closing) return;
            TestResultText.Text = "VPN HTTPS 연결 확인 완료";
            await UpdateIpResultAsync(cancellationToken);
        }, "VPN 연결을 완료하지 못했습니다. 다른 서버를 선택하거나 네트워크 상태를 확인해 주세요.");
        if (!_status.IsConnected) _powerRequested = false;
        UpdateControls();
    }

    private void ConnectionModeBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (ConnectionModeHint == null) return;
        ConnectionModeHint.Text = ConnectionModeBox.SelectedIndex == 1
            ? "전체 시스템 IPv4·IPv6/UDP 적용 · 관리자 권한 필요"
            : "프록시 사용 앱의 TCP만 적용 · UDP/게임은 일반 통신";
    }

    private async void TestButton_Click(object sender, RoutedEventArgs e)
    {
        if (_working || _stopping || _closing || !_status.IsConnected) return;
        TestResultText.Text = "VPN HTTPS 응답을 확인하고 있어요…";
        await RunOperationAsync(async cancellationToken =>
        {
            var succeeded = await _service.ProbeAsync(cancellationToken);
            if (!_closing) TestResultText.Text = succeeded ? "VPN HTTPS 연결 확인 완료" : "VPN HTTPS 응답을 확인하지 못했어요";
        }, "연결 테스트를 완료하지 못했습니다. 잠시 후 다시 시도해 주세요.");
    }

    private async void IpButton_Click(object sender, RoutedEventArgs e)
    {
        if (_working || _stopping || _closing || !_status.IsConnected) return;
        await RunOperationAsync(UpdateIpResultAsync, "VPN 출구 확인을 완료하지 못했습니다.");
    }

    private async Task UpdateIpResultAsync(CancellationToken cancellationToken)
    {
        IpResultText.Text = "HTTPS로 실제 VPN 출구·국가를 확인하고 있어요…";
        try
        {
            var result = await _service.CheckIpAsync(cancellationToken);
            if (!_closing && _service.Status.IsConnected)
            {
                IpResultText.Text = result.DisplayText;
                IpResultText.Foreground = new SolidColorBrush(result.HasCountryMismatch
                    ? Color.FromRgb(0xFF, 0xBD, 0xA6) : Color.FromRgb(0xC7, 0xD3, 0xE2));
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch
        {
            if (!_closing) IpResultText.Text = "VPN 연결은 유지되지만 출구 국가를 확인하지 못했습니다. 국가 확인을 다시 눌러 주세요.";
        }
    }

    private void FlushTraffic()
    {
        if (_closing) return;
        foreach (var record in _service.DrainTraffic())
        {
            _traffic.Insert(0, record);
            if (_traffic.Count > 300) _traffic.RemoveAt(_traffic.Count - 1);
        }
    }

    private void ServerBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (_service is null) return;
        if (ServerBox.SelectedItem is ServerEntry entry)
            ServerRegionText.Text = entry.IsConnectable
                ? $"공급자 표시: {ServerCatalog.CountryName(entry.CountryCode)} · {entry.Node.Protocol.ToUpperInvariant()}"
                : "남은 사용량·구독 정보입니다. 연결 대상으로 선택할 수 없습니다.";
        else ServerRegionText.Text = "연결할 서버를 선택하세요.";
        UpdateControls();
    }

    private void SetServers(SubscriptionResult result)
    {
        var previousId = (ServerBox.SelectedItem as ServerEntry)?.Node.Id;
        var entries = ServerCatalog.Create(result.Nodes);
        ServerBox.ItemsSource = entries;
        ServerBox.SelectedItem = ServerCatalog.SelectDefault(entries, previousId);
        var count = entries.Count(entry => entry.IsConnectable);
        ServerHint.Text = count == 0 ? "연결 가능한 서버가 없습니다. 구독을 확인해 주세요."
            : $"연결 가능 {count}개 · 일본 우선 정렬";
        if (result.RejectedCount > 0) ServerHint.Text += $" · 보안 조건 미충족 / 미지원 {result.RejectedCount}개 제외";
        TestResultText.Text = "연결 후 확인할 수 있어요";
        IpResultText.Text = "연결 후 실제 VPN IP·국가를 자동 확인합니다.";
    }

    private async Task<bool> RunOperationAsync(Func<CancellationToken, Task> action, string failureMessage)
    {
        if (_working || _closing || _stopping) return false;
        _working = true;
        _errorMessage = null;
        using var cancellation = new CancellationTokenSource();
        _operationCancellation = cancellation;
        UpdateControls();
        try
        {
            _activeTask = action(cancellation.Token);
            await _activeTask;
            return true;
        }
        catch (OperationCanceledException) when (cancellation.IsCancellationRequested) { return false; }
        catch
        {
            if (!_closing && !_stopping) _errorMessage = failureMessage;
            return false;
        }
        finally
        {
            _activeTask = null;
            _operationCancellation = null;
            _working = false;
            _status = _service.Status;
            if (!_status.IsConnected && !_status.IsBusy) _powerRequested = false;
            if (!_closing) UpdateControls();
        }
    }

    private async Task StopConnectionAsync()
    {
        if (_stopping) return;
        _stopping = true;
        _powerRequested = false;
        _errorMessage = null;
        _operationCancellation?.Cancel();
        UpdateControls();
        try
        {
            if (_activeTask is { } pendingOperation) { try { await pendingOperation; } catch { } }
            await _service.DisconnectAsync();
            _needsDisconnect = false;
            TestResultText.Text = "연결 후 확인할 수 있어요";
            IpResultText.Text = "연결 종료됨 · 다시 연결하면 실제 VPN 출구를 확인합니다.";
        }
        catch
        {
            _needsDisconnect = true;
            if (!_closing) _errorMessage = "VPN 종료를 확인하지 못했습니다. 다시 OFF를 눌러 주세요.";
        }
        finally { _stopping = false; _status = _service.Status; if (!_closing) UpdateControls(); }
    }

    private void Service_StatusChanged(VpnStatus status)
    {
        if (_closing) return;
        if (!Dispatcher.CheckAccess())
        {
            if (!Dispatcher.HasShutdownStarted) Dispatcher.BeginInvoke(new Action(() => ApplyStatus(status)));
            return;
        }
        ApplyStatus(status);
    }

    private void ApplyStatus(VpnStatus status)
    {
        if (_closing) return;
        _status = status;
        if (status.State == "CLEANUP-REQUIRED") _needsDisconnect = true;
        else if (!status.IsBusy && !status.IsConnected) _needsDisconnect = false;
        if (!status.IsConnected && !status.IsBusy && !_working)
        {
            _powerRequested = false;
            IpResultText.Text = "VPN 연결이 꺼져 있습니다. 출구 정보는 연결 후 다시 확인합니다.";
        }
        UpdateControls();
    }

    private void UpdateControls()
    {
        var connected = _status.IsConnected;
        var busy = _working || _status.IsBusy || _stopping || _needsDisconnect;
        var connectionActive = connected || _powerRequested || _needsDisconnect;
        var mint = new SolidColorBrush(Color.FromRgb(0x69, 0xE3, 0xC2));
        var muted = new SolidColorBrush(Color.FromRgb(0x91, 0xA1, 0xB7));
        var iconBrush = connected ? mint : new SolidColorBrush(Color.FromRgb(0xA7, 0xB8, 0xCD));
        PowerButton.IsEnabled = !_closing && !_stopping && (connectionActive || (!busy && ServerBox.SelectedItem is ServerEntry { IsConnectable: true }));
        PowerButton.Background = new SolidColorBrush(connected ? Color.FromRgb(0x17, 0x3B, 0x38) : Color.FromRgb(0x1A, 0x2B, 0x40));
        PowerButton.BorderBrush = connected ? mint : new SolidColorBrush(Color.FromRgb(0x41, 0x53, 0x6A));
        PowerArc.Stroke = iconBrush; PowerLine.Stroke = iconBrush; PowerText.Foreground = iconBrush;
        PowerText.Text = _stopping ? "종료 중" : _needsDisconnect ? "종료" : connected ? "ON" : _powerRequested ? "연결 중" : "OFF";
        System.Windows.Automation.AutomationProperties.SetName(PowerButton, connectionActive ? "VPN 끄기" : "VPN 켜기");
        PowerButton.ToolTip = connected || _needsDisconnect ? "VPN 연결 종료" : _powerRequested ? "연결 취소" : "선택한 서버로 VPN 연결";
        StatusDot.Fill = connected ? mint : muted; StatusLabel.Foreground = connected ? mint : muted;
        StatusLabel.Text = _stopping ? "연결 종료 중" : _needsDisconnect ? "종료 확인 필요" : connected ? "VPN 연결됨" : _powerRequested ? "VPN 연결 중" : "VPN 꺼짐";
        ConnectionTitle.Text = _stopping ? "연결을 정리하고 있어요" : _needsDisconnect ? "연결 종료를 확인해 주세요" : connected ? "VPN에 연결되어 있어요" : _powerRequested ? "서버에 연결하고 있어요" : "연결할 준비가 되었어요";
        MessageText.Text = _errorMessage ?? (_stopping ? "잠시만 기다려 주세요. 이전 네트워크 설정으로 돌아갑니다." : _status.Message);
        MessageText.Foreground = _errorMessage is null ? muted : new SolidColorBrush(Color.FromRgb(0xFF, 0xBD, 0xA6));
        ServerBox.IsEnabled = !connected && !busy && !_closing;
        ConnectionModeBox.IsEnabled = !connected && !busy && !_closing;
        SubscriptionBox.IsEnabled = !connected && !busy && !_closing;
        RefreshButton.IsEnabled = !connected && !busy && !_closing;
        RefreshButton.Content = _working && !_powerRequested && !connected ? "불러오는 중…" : "불러오기";
        TestButton.IsEnabled = connected && !busy && !_closing;
        IpButton.IsEnabled = connected && !busy && !_closing;
        RulesWindowButton.IsEnabled = !_closing;
        _rulesWindow?.SetOwnerState(busy, _closing, _status);
    }

    private void SecurityButton_Click(object sender, RoutedEventArgs e)
    {
        MessageBox.Show(this, "공급자의 앱·스크립트·루트 인증서를 설치하지 않고 HTTPS 인증서를 검증합니다.\n\n" +
            "비관리자 모드도 파일 접근을 격리하는 샌드박스는 아니며, 코어·Windows의 취약점을 완전히 배제할 수 없습니다.\n" +
            "HTTP 통신은 공급자가 읽거나 바꿀 수 있습니다. 영구 킬 스위치는 없으며, 연결 종료 후 일반 통신으로 돌아갑니다.", "Yao VPN · 보안 안내", MessageBoxButton.OK, MessageBoxImage.Information);
    }

    private async void Window_Closing(object? sender, CancelEventArgs e)
    {
        if (_allowClose) return;
        e.Cancel = true;
        if (_closing) return;
        _closing = true;
        _trafficTimer.Stop();
        _operationCancellation?.Cancel();
        _service.StatusChanged -= Service_StatusChanged;
        UpdateControls();
        try
        {
            if (_activeTask is { } active) { try { await active; } catch { } }
            if (_rulesWindow?.PendingSave is { } save) { try { await save; } catch { } }
            if (_stopTask is { } stop) { try { await stop; } catch { } }
            await _service.DisposeAsync();
        }
        catch
        {
            _closing = false;
            _trafficTimer.Start();
            _needsDisconnect = true;
            _service.StatusChanged += Service_StatusChanged;
            _status = _service.Status;
            _errorMessage = "VPN 종료를 확인하지 못했습니다. OFF를 다시 누른 뒤 앱을 종료해 주세요.";
            UpdateControls();
            MessageBox.Show(this, "VPN 종료를 확인하지 못해 앱을 열어 두었습니다. OFF를 다시 눌러 종료를 시도해 주세요.", "Yao VPN", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }
        // OFF cleanup can complete synchronously. Never close this window or its
        // owned window recursively from the original Closing event. UI teardown
        // also stays outside the network-cleanup catch so a UI failure cannot be
        // misreported as a tunnel/proxy restoration failure.
        _allowClose = true;
        _ = Dispatcher.BeginInvoke(new Action(() =>
        {
            _rulesWindow?.CloseWithOwner();
            _rulesWindow = null;
            Close();
        }), DispatcherPriority.Normal);
    }
}
