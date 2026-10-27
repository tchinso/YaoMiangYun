using System.ComponentModel;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.IO.Pipes;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
using YaoVpn.Core;

namespace YaoVpn.App.Services;

public sealed record VpnStatus(string State, string Message, bool IsConnected, bool IsBusy);
public enum ConnectionMode { AppProxy, SystemTun }

public sealed class VpnService : IAsyncDisposable
{
    private readonly string applicationExecutable;
    public VpnService() : this(Environment.ProcessPath ?? throw new IOException("Application path unavailable.")) { }
    internal VpnService(string applicationExecutable) { this.applicationExecutable = Path.GetFullPath(applicationExecutable); }
    private readonly SemaphoreSlim gate = new(1, 1);
    private NamedPipeServerStream? pipe;
    private Process? broker;
    private Task? monitor;
    private UserProxySession? proxySession;
    private bool proxyRecoveryRequired;
    private volatile bool stopping;
    private string? terminalMessage;
    private readonly ConcurrentQueue<TrafficRecord> traffic = new();
    private string? beforeIp;
    public event Action<VpnStatus>? StatusChanged;
    public VpnStatus Status { get; private set; } = new("OFF", "VPN이 꺼져 있습니다.", false, false);
    public string? SavedUrl { get; private set; }
    public RoutingPolicy CurrentRoutingPolicy { get; private set; } = RoutingPolicy.SelectedSites;
    public ConnectionMode? ActiveMode { get; private set; }
    private sealed record SavedSubscription(string Url, string Json);

    public async Task LoadRoutingPolicyAsync(CancellationToken cancellationToken = default)
    {
        await gate.WaitAsync(cancellationToken);
        try
        {
            var saved = await Task.Run(() => PrivateStorage.Load("routing.dpapi"), cancellationToken);
            CurrentRoutingPolicy = saved == null ? RoutingPolicy.SelectedSites
                : RoutingPolicy.Validate(JsonSerializer.Deserialize<RoutingPolicy>(saved) ?? throw new FormatException());
        }
        catch (Exception e) when (e is FormatException or JsonException or IOException or System.Security.Cryptography.CryptographicException)
        { throw new InvalidOperationException("저장된 사이트 규칙을 읽지 못했습니다. 규칙을 다시 저장해 주세요."); }
        finally { gate.Release(); }
    }

    public async Task SaveRoutingPolicyAsync(RoutingPolicy policy, CancellationToken cancellationToken = default)
    {
        policy = RoutingPolicy.Validate(policy);
        await gate.WaitAsync(cancellationToken);
        try
        {
            await Task.Run(() => PrivateStorage.Save("routing.dpapi", JsonSerializer.Serialize(policy)), cancellationToken);
            CurrentRoutingPolicy = policy;
        }
        finally { gate.Release(); }
    }

    public IReadOnlyList<TrafficRecord> DrainTraffic()
    {
        var result = new List<TrafficRecord>();
        while (result.Count < 100 && traffic.TryDequeue(out var record)) result.Add(record);
        return result;
    }

    public void ClearTraffic() { while (traffic.TryDequeue(out _)) { } }

    public async Task<IpCheckResult> CheckIpAsync(CancellationToken cancellationToken = default)
    {
        var session = pipe;
        var proxy = proxySession;
        if ((session == null && proxy == null) || !Status.IsConnected) return new(beforeIp, null);
        var address = await IpVerification.ReadAsync(cancellationToken, proxy?.ProxyAddress);
        return new(beforeIp, ReferenceEquals(pipe, session) && ReferenceEquals(proxySession, proxy)
            && Status.IsConnected ? address : null);
    }

    public async Task RecoverProxyAsync(CancellationToken cancellationToken = default)
    {
        await gate.WaitAsync(cancellationToken);
        try { await UserProxySession.RecoverProxyAsync(cancellationToken); proxyRecoveryRequired = false; }
        catch { proxyRecoveryRequired = true; Set("CLEANUP-REQUIRED", "이전 프록시 설정 복원을 확인하지 못했습니다. OFF를 눌러 다시 복원하세요."); throw; }
        finally { gate.Release(); }
    }

    private void Set(string state, string message, bool connected = false, bool busy = false)
    { Status = new(state, message, connected, busy); StatusChanged?.Invoke(Status); }

    public async Task<SubscriptionResult?> LoadSavedAsync(CancellationToken cancellationToken = default)
    {
        await gate.WaitAsync(cancellationToken);
        try
        {
            var saved = await Task.Run(() => PrivateStorage.Load("subscription.dpapi"), cancellationToken);
            if (saved == null) return null;
            var data = JsonSerializer.Deserialize<SavedSubscription>(saved) ?? throw new FormatException();
            var result = SubscriptionParser.Parse(data.Json);
            SavedUrl = data.Url;
            return result;
        }
        catch { throw new InvalidOperationException("저장된 구독을 읽지 못했습니다. 구독 주소를 다시 불러와 주세요."); }
        finally { gate.Release(); }
    }

    public async Task<SubscriptionResult> LoadSubscriptionAsync(string url, CancellationToken cancellationToken = default)
    {
        await gate.WaitAsync(cancellationToken);
        try
        {
            if (pipe != null || proxySession != null) throw new InvalidOperationException("VPN을 끈 뒤 구독을 갱신해 주세요.");
            if (!Uri.TryCreate(url.Trim(), UriKind.Absolute, out var uri) || uri.Scheme != "https" || uri.UserInfo.Length != 0 || uri.Fragment.Length != 0 || uri.IsLoopback || url.Length > 4096)
                throw new InvalidOperationException("올바른 HTTPS 구독 주소를 입력해 주세요.");
            Set("OFF", "구독의 연결 정보를 확인하고 있습니다.", busy: true);
            using var handler = EndpointResolver.CreateSubscriptionHandler();
            using var client = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(25) };
            client.DefaultRequestHeaders.UserAgent.ParseAdd("sing-box/" + BinaryTrust.Version);
            using var response = await client.GetAsync(uri, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
            if (!response.IsSuccessStatusCode) throw new IOException("Subscription HTTP failure.");
            if (response.Content.Headers.ContentLength > 2 * 1024 * 1024) throw new IOException("Response too large.");
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeout.CancelAfter(TimeSpan.FromSeconds(25));
            await using var stream = await response.Content.ReadAsStreamAsync(timeout.Token);
            using var output = new MemoryStream();
            var buffer = new byte[8192];
            int count;
            while ((count = await stream.ReadAsync(buffer, timeout.Token)) != 0)
            {
                if (output.Length + count > 2 * 1024 * 1024) throw new IOException("Response too large.");
                output.Write(buffer, 0, count);
            }
            var json = new UTF8Encoding(false, true).GetString(output.ToArray());
            var result = SubscriptionParser.Parse(json);
            await Task.Run(() => PrivateStorage.Save("subscription.dpapi", JsonSerializer.Serialize(new SavedSubscription(uri.AbsoluteUri, json))), cancellationToken);
            SavedUrl = uri.AbsoluteUri;
            Set("OFF", $"서버 {result.Nodes.Count}개를 불러왔습니다. 연결할 서버를 선택해 주세요.");
            return result;
        }
        catch (InvalidOperationException) { Set("OFF", "구독을 불러오지 못했습니다."); throw; }
        catch { Set("OFF", "구독을 불러오지 못했습니다."); throw new InvalidOperationException("구독을 읽지 못했습니다. 주소·만료 여부·인터넷 연결을 확인해 주세요. HTTPS sing-box 형식만 지원합니다."); }
        finally { gate.Release(); }
    }

    public Task ConnectAsync(VpnNode node, CancellationToken cancellationToken = default)
        => ConnectAsync(node, ConnectionMode.AppProxy, CurrentRoutingPolicy, cancellationToken);

    public Task ConnectAsync(VpnNode node, ConnectionMode mode, CancellationToken cancellationToken = default)
        => ConnectAsync(node, mode, CurrentRoutingPolicy, cancellationToken);

    public async Task ConnectAsync(VpnNode node, ConnectionMode mode, RoutingPolicy policy, CancellationToken cancellationToken = default)
    {
        if (!Enum.IsDefined(mode)) throw new ArgumentOutOfRangeException(nameof(mode));
        policy = RoutingPolicy.Validate(policy);
        await gate.WaitAsync(cancellationToken);
        var failureStage = "ipc";
        try
        {
            if (Status.IsConnected) return;
            if (broker != null || pipe != null || proxySession != null || monitor != null || Status.State == "CLEANUP-REQUIRED")
                await StopInternalAsync();
            node = SubscriptionParser.Revalidate(node);
            using (BinaryTrust.OpenVerifiedCore()) { }
            ActiveMode = mode;
            Set("CONNECTING", mode == ConnectionMode.AppProxy
                ? "관리자 권한 없이 앱 프록시를 준비합니다."
                : "Windows 관리자 권한을 승인하면 전체 시스템 TUN을 연결합니다.", busy: true);
            beforeIp = await IpVerification.ReadAsync(cancellationToken);
            stopping = false;
            terminalMessage = null;
            if (mode == ConnectionMode.AppProxy)
            {
                failureStage = "proxy";
                proxyRecoveryRequired = true;
                proxySession = await UserProxySession.StartAsync(node, policy, QueueTraffic, cancellationToken);
                var currentProxy = proxySession;
                monitor = MonitorProxyAsync(currentProxy);
                Set("CONNECTING", "앱 프록시를 만들었습니다. VPN HTTPS 연결을 확인합니다.", busy: true);
                failureStage = "https";
                if (!await ProbeAsync(cancellationToken) || !ReferenceEquals(proxySession, currentProxy)
                    || currentProxy.Exit.IsCompleted || monitor.IsCompleted || terminalMessage != null) throw new IOException();
                Set("ON", policy.DefaultRoute == "vpn"
                    ? "앱 프록시 ON · 시스템 프록시 사용 앱의 TCP 통신 · 기본 VPN"
                    : "앱 프록시 ON · 지정한 사이트만 VPN · 나머지는 일반 통신", true);
                return;
            }
            var name = "YaoVPN-" + Guid.NewGuid().ToString("N");
            pipe = new NamedPipeServerStream(name, PipeDirection.InOut, 1, PipeTransmissionMode.Byte, PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly);
            var start = new ProcessStartInfo(applicationExecutable)
            { UseShellExecute = true, Verb = "runas", WindowStyle = ProcessWindowStyle.Hidden };
            start.ArgumentList.Add("--broker"); start.ArgumentList.Add(name);
            start.ArgumentList.Add(Environment.ProcessId.ToString(System.Globalization.CultureInfo.InvariantCulture));
            broker = Process.Start(start) ?? throw new IOException();
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeout.CancelAfter(TimeSpan.FromSeconds(90));
            await pipe.WaitForConnectionAsync(timeout.Token);
            if (!GetNamedPipeClientProcessId(pipe.SafePipeHandle, out var clientPid) || clientPid != broker.Id)
                throw new IOException("Unexpected broker identity.");
            await PipeProtocol.WriteAsync(pipe, new("connect", node, Policy: policy), timeout.Token);
            var reply = await PipeProtocol.ReadAsync(pipe, timeout.Token);
            if (reply.Kind != "started")
            {
                failureStage = reply.Kind is "failed-ipc" or "failed-storage" or "failed-core" or "failed-routes" ? reply.Kind : "core";
                throw new IOException();
            }
            failureStage = "https";
            // Drain metadata immediately: a busy core must not fill the broker's pipe
            // while this independent VPN-only HTTPS probe is still in progress.
            var session = pipe;
            monitor = MonitorAsync(session);
            Set("CONNECTING", "터널을 만들었습니다. HTTPS 연결을 확인합니다.", busy: true);
            if (!await ProbeAsync(timeout.Token) || broker.HasExited || !TunnelHealth.HasRoutes()
                || !ReferenceEquals(pipe, session) || terminalMessage != null || monitor.IsCompleted) throw new IOException();
            Set("ON", policy.DefaultRoute == "vpn"
                ? "VPN 연결됨 · 기본 VPN / 지정한 일반 통신 예외 적용"
                : "VPN 연결됨 · 지정한 사이트만 VPN / 기본 일반 통신", true);
        }
        catch (Win32Exception e) when (e.NativeErrorCode == 1223)
        {
            await CleanupFailedConnectionAsync("관리자 권한 요청이 취소되었습니다.");
            throw new InvalidOperationException("VPN 연결에는 Windows 관리자 권한 승인이 필요합니다.");
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            await CleanupFailedConnectionAsync("연결을 취소했습니다.");
            throw;
        }
        catch
        {
            await CleanupFailedConnectionAsync("연결하지 못했습니다. 다른 서버를 선택해 주세요.");
            throw new InvalidOperationException("VPN 연결을 확인하지 못했습니다. 다른 서버로 시도해 주세요. 엔진 파일이나 권한도 확인해 주세요. (" + failureStage + ")");
        }
        finally { gate.Release(); }
    }

    private async Task CleanupFailedConnectionAsync(string message)
    {
        try { await StopInternalAsync(); Set("OFF", message); }
        catch { Set("CLEANUP-REQUIRED", "연결 설정 복원을 확인하지 못했습니다. OFF를 눌러 다시 복원하세요."); throw; }
    }

    private void QueueTraffic(TrafficRecord record)
    {
        var validated = TrafficRecord.Validate(record);
        if (stopping || validated == null) return;
        traffic.Enqueue(validated);
        while (traffic.Count > 300) traffic.TryDequeue(out _);
    }

    private async Task MonitorProxyAsync(UserProxySession session)
    {
        try
        {
            await session.Exit;
            if (stopping) return;
            terminalMessage = "proxy-exited";
            Set("DISCONNECTING", "앱 프록시가 종료되어 이전 프록시 설정을 복원하고 있습니다.", busy: true);
            await session.DisposeAsync();
            proxyRecoveryRequired = false;
            if (ReferenceEquals(proxySession, session)) proxySession = null;
            if (!stopping) Set("OFF", "앱 프록시가 종료되어 이전 프록시 설정을 복원했습니다.");
        }
        catch
        {
            if (!stopping) Set("CLEANUP-REQUIRED", "앱 프록시 종료 후 설정 복원을 확인하지 못했습니다. OFF를 눌러 다시 복원하세요.");
        }
    }

    private async Task MonitorAsync(NamedPipeServerStream session)
    {
        try
        {
            while (true)
            {
                var message = await PipeProtocol.ReadAsync(session);
                if (message.Kind == "traffic")
                {
                    var record = TrafficRecord.Validate(message.Traffic);
                    if (record != null) QueueTraffic(record);
                    continue;
                }
                terminalMessage = message.Kind;
                if (!stopping)
                    ReportTunEnded();
                break;
            }
        }
        catch (Exception e) when (e is IOException or ObjectDisposedException)
        { if (!stopping) ReportTunEnded(); }
        finally
        {
            if (!stopping) { session.Dispose(); if (ReferenceEquals(pipe, session)) pipe = null; }
        }
    }

    private void ReportTunEnded()
    {
        if (TunnelHealth.IsUp())
            Set("CLEANUP-REQUIRED", "터널 종료를 확인하지 못했습니다. OFF를 눌러 정리를 다시 확인하세요.");
        else
        {
            terminalMessage = null;
            Set("OFF", "VPN이 종료되었습니다. 일반 인터넷 연결로 돌아갑니다.");
        }
    }

    public async Task DisconnectAsync()
    {
        await gate.WaitAsync();
        try { Set("DISCONNECTING", "VPN을 끄고 네트워크를 복원합니다.", busy: true); await StopInternalAsync(); Set("OFF", "VPN이 꺼져 있습니다. 이전 네트워크 설정을 복원했습니다."); }
        catch { Set("CLEANUP-REQUIRED", "연결 설정 복원을 확인하지 못했습니다. OFF를 눌러 다시 복원하세요."); throw; }
        finally { gate.Release(); }
    }

    private async Task StopInternalAsync()
    {
        stopping = true;
        var proxy = proxySession;
        if (proxy != null)
        {
            await proxy.DisposeAsync();
            proxyRecoveryRequired = false;
            if (ReferenceEquals(proxySession, proxy)) proxySession = null;
        }
        else if (ActiveMode == ConnectionMode.AppProxy || proxyRecoveryRequired)
        {
            await UserProxySession.RecoverProxyAsync();
            proxyRecoveryRequired = false;
        }
        var session = pipe;
        if (session != null)
        {
            try
            {
                if (session.IsConnected)
                {
                    using var stopTimeout = new CancellationTokenSource(TimeSpan.FromSeconds(3));
                    await PipeProtocol.WriteAsync(session, new("stop"), stopTimeout.Token);
                }
            }
            catch (Exception e) when (e is IOException or ObjectDisposedException or OperationCanceledException) { }
            // EOF also instructs the broker to stop if sending fails.
            if (monitor == null) session.Dispose();
        }
        if (broker != null)
        {
            try { await broker.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(15)); }
            catch (TimeoutException)
            {
                session?.Dispose();
                try { await broker.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(12)); }
                catch (TimeoutException) { throw new InvalidOperationException("VPN 종료 확인에 실패했습니다. 앱을 유지하고 Windows 네트워크 상태를 확인해 주세요."); }
            }
            finally { if (broker.HasExited) { broker.Dispose(); broker = null; } }
        }
        session?.Dispose(); pipe = null;
        if (monitor != null) { await monitor; monitor = null; }
        if (TunnelHealth.IsUp())
            throw new InvalidOperationException("터널 종료를 확인하지 못했습니다. OFF를 다시 누르거나 Windows 네트워크 상태를 확인해 주세요.");
        terminalMessage = null;
        ActiveMode = null;
    }

    public async Task<bool> ProbeAsync(CancellationToken cancellationToken = default)
    {
        var session = pipe;
        var proxy = proxySession;
        if (session == null && proxy == null) return false;
        var proxyAddress = proxy?.ProxyAddress;
        using var handler = new HttpClientHandler
        {
            UseProxy = proxyAddress != null,
            Proxy = proxyAddress == null ? null : new WebProxy(proxyAddress) { BypassProxyOnLocal = false },
            AllowAutoRedirect = false
        };
        using var client = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(10) };
        // ConfigBuilder reserves this exact hostname for vpn + secure-dns before
        // user suffix rules, including when the user's default route is direct.
        try
        {
            using var response = await client.GetAsync("https://" + ConfigBuilder.VpnHealthHost + "/generate_204", HttpCompletionOption.ResponseHeadersRead, cancellationToken);
            return response.StatusCode == HttpStatusCode.NoContent && ReferenceEquals(pipe, session)
                && ReferenceEquals(proxySession, proxy) && (proxy == null || !proxy.Exit.IsCompleted);
        }
        catch (Exception e) when (e is HttpRequestException or TaskCanceledException) { cancellationToken.ThrowIfCancellationRequested(); return false; }
    }

    public async ValueTask DisposeAsync() { await DisconnectAsync(); gate.Dispose(); }

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetNamedPipeClientProcessId(SafePipeHandle pipe, out uint processId);
}
