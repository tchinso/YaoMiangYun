using System.ComponentModel;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
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

    public MainWindow()
    {
        InitializeComponent();
        _service = new VpnService();
        _status = _service.Status;
        _service.StatusChanged += Service_StatusChanged;
        UpdateControls();
    }

    private async void Window_Loaded(object sender, RoutedEventArgs e)
    {
        await RunOperationAsync(async cancellationToken =>
        {
            var result = await _service.LoadSavedAsync(cancellationToken);
            if (_closing) return;
            SubscriptionBox.Password = _service.SavedUrl ?? string.Empty;
            if (result is not null) SetServers(result);
        }, "저장된 구독을 불러오지 못했습니다. 구독 주소를 다시 입력해 주세요.");
    }

    private async void RefreshButton_Click(object sender, RoutedEventArgs e)
    {
        if (_working || _stopping || _closing || _status.IsConnected) return;
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
        }, "구독을 불러오지 못했습니다. HTTPS 주소와 네트워크 상태를 확인해 주세요.");
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

        if (_working || ServerBox.SelectedItem is not VpnNode node) return;
        _powerRequested = true;
        TestResultText.Text = "연결 후 확인할 수 있어요";
        await RunOperationAsync(cancellationToken => _service.ConnectAsync(node, cancellationToken),
            "VPN 연결을 완료하지 못했습니다. 다른 서버를 선택하거나 네트워크 상태를 확인해 주세요.");
        if (!_status.IsConnected) _powerRequested = false;
        UpdateControls();
    }

    private async void TestButton_Click(object sender, RoutedEventArgs e)
    {
        if (_working || _stopping || _closing || !_status.IsConnected) return;
        TestResultText.Text = "응답을 확인하고 있어요…";
        await RunOperationAsync(async cancellationToken =>
        {
            var succeeded = await _service.ProbeAsync(cancellationToken);
            if (!_closing)
                TestResultText.Text = succeeded ? "인터넷 응답 확인 완료" : "인터넷 응답을 확인하지 못했어요";
        }, "연결 테스트를 완료하지 못했습니다. 잠시 후 다시 시도해 주세요.");
    }

    private void ServerBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        // Selection changes can fire before the constructor has created the service.
        if (_service is not null) UpdateControls();
    }

    private void SetServers(SubscriptionResult result)
    {
        var previousId = (ServerBox.SelectedItem as VpnNode)?.Id;
        ServerBox.ItemsSource = result.Nodes;
        ServerBox.SelectedItem = result.Nodes.FirstOrDefault(node => node.Id == previousId)
                                 ?? result.Nodes.FirstOrDefault();
        ServerHint.Text = result.Nodes.Count == 0
            ? "연결 가능한 서버가 없습니다. 구독을 확인해 주세요."
            : $"사용 가능한 서버 {result.Nodes.Count}개";
        if (result.RejectedCount > 0)
            ServerHint.Text += $" · 보안 조건 미충족 / 미지원 {result.RejectedCount}개 제외";
        TestResultText.Text = "연결 후 확인할 수 있어요";
    }

    private async Task RunOperationAsync(Func<CancellationToken, Task> action, string failureMessage)
    {
        if (_working || _closing) return;
        _working = true;
        _errorMessage = null;
        using var cancellation = new CancellationTokenSource();
        _operationCancellation = cancellation;
        UpdateControls();
        try
        {
            _activeTask = action(cancellation.Token);
            await _activeTask;
        }
        catch (OperationCanceledException) when (cancellation.IsCancellationRequested)
        {
            // Turning OFF or closing the window intentionally cancels the current operation.
        }
        catch (Exception)
        {
            if (!_closing && !_stopping) _errorMessage = failureMessage;
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
            // Complete the cancelled operation before disconnecting to avoid overlapping service calls.
            var pendingOperation = _activeTask;
            if (pendingOperation is not null)
            {
                try { await pendingOperation; }
                catch (Exception) { /* The owning operation reports failures. */ }
            }
            await _service.DisconnectAsync();
            _needsDisconnect = false;
            TestResultText.Text = "연결 후 확인할 수 있어요";
        }
        catch (Exception)
        {
            _needsDisconnect = true;
            if (!_closing) _errorMessage = "VPN 종료를 확인하지 못했습니다. 다시 OFF를 눌러 주세요.";
        }
        finally
        {
            _stopping = false;
            _status = _service.Status;
            if (!_closing) UpdateControls();
        }
    }

    private void Service_StatusChanged(VpnStatus status)
    {
        if (_closing) return;
        if (!Dispatcher.CheckAccess())
        {
            if (!Dispatcher.HasShutdownStarted)
                Dispatcher.BeginInvoke(new Action(() => ApplyStatus(status)));
            return;
        }
        ApplyStatus(status);
    }

    private void ApplyStatus(VpnStatus status)
    {
        if (_closing) return;
        _status = status;
        if (!status.IsConnected && !status.IsBusy && !_working) _powerRequested = false;
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

        PowerButton.IsEnabled = !_closing && !_stopping && (connectionActive || (!busy && ServerBox.SelectedItem is VpnNode));
        PowerButton.Background = new SolidColorBrush(connected ? Color.FromRgb(0x17, 0x3B, 0x38) : Color.FromRgb(0x1A, 0x2B, 0x40));
        PowerButton.BorderBrush = connected ? mint : new SolidColorBrush(Color.FromRgb(0x41, 0x53, 0x6A));
        PowerArc.Stroke = iconBrush;
        PowerLine.Stroke = iconBrush;
        PowerText.Foreground = iconBrush;
        PowerText.Text = _stopping ? "종료 중" : _needsDisconnect ? "종료" : connected ? "ON" : _powerRequested ? "연결 중" : "OFF";
        System.Windows.Automation.AutomationProperties.SetName(PowerButton, connectionActive ? "VPN 끄기" : "VPN 켜기");
        PowerButton.ToolTip = connected || _needsDisconnect ? "VPN 연결 종료" : _powerRequested ? "연결 취소" : "선택한 서버로 VPN 연결";
        StatusDot.Fill = connected ? mint : muted;
        StatusLabel.Foreground = connected ? mint : muted;
        StatusLabel.Text = _stopping ? "연결 종료 중" : _needsDisconnect ? "종료 확인 필요" : connected ? "VPN 연결됨" : _powerRequested ? "VPN 연결 중" : "VPN 꺼짐";
        ConnectionTitle.Text = _stopping ? "연결을 정리하고 있어요" : _needsDisconnect ? "연결 종료를 확인해 주세요" : connected ? "VPN에 연결되어 있어요" : _powerRequested ? "서버에 연결하고 있어요" : "연결할 준비가 되었어요";
        MessageText.Text = _errorMessage ?? (_stopping ? "잠시만 기다려 주세요. 일반 인터넷 연결로 돌아갑니다."
            : !string.IsNullOrWhiteSpace(_status.Message) ? _status.Message
            : "구독 주소를 입력해 서버를 불러오세요.");
        MessageText.Foreground = _errorMessage is null ? muted : new SolidColorBrush(Color.FromRgb(0xFF, 0xBD, 0xA6));
        ServerBox.IsEnabled = !connected && !busy && !_closing;
        SubscriptionBox.IsEnabled = !connected && !busy && !_closing;
        RefreshButton.IsEnabled = !connected && !busy && !_closing;
        RefreshButton.Content = _working && !_powerRequested && !connected ? "구독을 불러오는 중…" : "구독 불러오기 / 새로고침";
        TestButton.IsEnabled = connected && !busy && !_closing;
    }

    private async void Window_Closing(object? sender, CancelEventArgs e)
    {
        if (_allowClose) return;
        e.Cancel = true;
        if (_closing) return;
        _closing = true;
        _operationCancellation?.Cancel();
        _service.StatusChanged -= Service_StatusChanged;
        UpdateControls();
        var cleanupSucceeded = false;
        try
        {
            var pendingOperation = _activeTask;
            if (pendingOperation is not null)
            {
                try { await pendingOperation; }
                catch (Exception) { /* Closing still needs to release the service. */ }
            }
            var pendingStop = _stopTask;
            if (pendingStop is not null)
            {
                try { await pendingStop; }
                catch (Exception) { /* Dispose is still required if disconnection failed. */ }
            }
            await _service.DisconnectAsync();
            await _service.DisposeAsync();
            cleanupSucceeded = true;
        }
        catch (Exception)
        {
            _closing = false;
            _needsDisconnect = true;
            _service.StatusChanged += Service_StatusChanged;
            _status = _service.Status;
            _errorMessage = "VPN 종료를 확인하지 못했습니다. OFF를 다시 누른 뒤 앱을 종료해 주세요.";
            UpdateControls();
            MessageBox.Show(this, "VPN 종료를 확인하지 못해 앱을 열어 두었습니다. OFF를 다시 눌러 종료를 시도해 주세요.",
                "Yao VPN", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
        finally
        {
            if (cleanupSucceeded)
            {
                _allowClose = true;
                Close();
            }
        }
    }
}
