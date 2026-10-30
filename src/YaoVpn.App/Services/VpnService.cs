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
    private readonly object disposeSync = new();
    private Task? disposal;
    private volatile bool disposalInProgress;
    private volatile bool disposed;
    private NamedPipeServerStream? pipe;
    private Process? broker;
    private Task? monitor;
    private UserProxySession? proxySession;
    private bool proxyRecoveryRequired;
    private volatile bool stopping;
    private string? terminalMessage;
    private readonly ConcurrentQueue<TrafficRecord> traffic = new();
    private string? beforeIp;
    private RoutingPolicy? activePolicy;
    public event Action<VpnStatus>? StatusChanged;
    public VpnStatus Status { get; private set; } = new("OFF", "VPN이 꺼져 있습니다.", false, false);
    public string? SavedUrl { get; private set; }
    public RoutingPolicy CurrentRoutingPolicy { get; private set; } = RoutingPolicy.Automatic;
    public ConnectionMode? ActiveMode { get; private set; }
    public string? ActiveServerId { get; private set; }
    public string? ActiveServerName { get; private set; }
    public string? AdvertisedCountryCode { get; private set; }
    private sealed record SavedSubscription(string Url, string Json);

    private async Task EnterAsync(CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(disposed || disposalInProgress, this);
        await gate.WaitAsync(cancellationToken);
        if (disposed || disposalInProgress)
        {
            gate.Release();
            throw new ObjectDisposedException(nameof(VpnService));
        }
    }

    public async Task LoadRoutingPolicyAsync(CancellationToken cancellationToken = default)
    {
        await EnterAsync(cancellationToken);
        try
        {
            var saved = await Task.Run(() => PrivateStorage.Load("routing.dpapi"), cancellationToken);
            CurrentRoutingPolicy = ReadSavedRoutingPolicy(saved);
        }
        catch (Exception e) when (e is FormatException or JsonException or IOException or System.Security.Cryptography.CryptographicException)
        { throw new InvalidOperationException("저장된 사이트 규칙을 읽지 못했습니다. 규칙을 다시 저장해 주세요."); }
        finally { gate.Release(); }
    }

    internal static RoutingPolicy ReadSavedRoutingPolicy(string? saved)
    {
        if (saved == null) return RoutingPolicy.Automatic;
        using var document = JsonDocument.Parse(saved);
        var policy = RoutingPolicy.Validate(JsonSerializer.Deserialize<RoutingPolicy>(saved) ?? throw new FormatException());
        // Introduce the new default once for pre-automatic settings, preserving every saved domain.
        return document.RootElement.TryGetProperty(nameof(RoutingPolicy.PolicyVersion), out _)
            ? policy : policy with { DefaultRoute = "auto" };
    }

    public async Task SaveRoutingPolicyAsync(RoutingPolicy policy, CancellationToken cancellationToken = default)
    {
        policy = RoutingPolicy.Validate(policy);
        await EnterAsync(cancellationToken);
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
        ObjectDisposedException.ThrowIf(disposed || disposalInProgress, this);
        var session = pipe;
        var proxy = proxySession;
        var serverId = ActiveServerId;
        var serverName = ActiveServerName;
        var country = AdvertisedCountryCode;
        if ((session == null && proxy == null) || !Status.IsConnected) return new(beforeIp, null);
        var currentPath = IpVerification.ReadAsync(cancellationToken, proxy?.ProxyAddress);
        var vpnPath = IpVerification.ReadVpnAsync(cancellationToken, proxy?.ProxyAddress);
        await Task.WhenAll(currentPath, vpnPath);
        if (!ReferenceEquals(pipe, session) || !ReferenceEquals(proxySession, proxy) || ActiveServerId != serverId
            || ActiveServerName != serverName || !Status.IsConnected || disposed || stopping) return new(beforeIp, null);
        return new(beforeIp, await currentPath)
        {
            VpnEgress = await vpnPath,
            AdvertisedCountryCode = country,
            SelectedServerName = serverName
        };
    }

    public async Task RecoverProxyAsync(CancellationToken cancellationToken = default)
    {
        await EnterAsync(cancellationToken);
        try { await UserProxySession.RecoverProxyAsync(cancellationToken); proxyRecoveryRequired = false; }
        catch { proxyRecoveryRequired = true; Set("CLEANUP-REQUIRED", "이전 프록시 설정 복원을 확인하지 못했습니다. OFF를 눌러 다시 복원하세요."); throw; }
        finally { gate.Release(); }
    }

    private void Set(string state, string message, bool connected = false, bool busy = false)
    { Status = new(state, message, connected, busy); StatusChanged?.Invoke(Status); }

    public async Task<SubscriptionResult?> LoadSavedAsync(CancellationToken cancellationToken = default)
    {
        await EnterAsync(cancellationToken);
        try
        {
            var saved = await Task.Run(() => PrivateStorage.Load("subscription.dpapi"), cancellationToken);
            if (saved == null) return null;
            var data = JsonSerializer.Deserialize<SavedSubscription>(saved) ?? throw new FormatException();
            var result = SubscriptionParser.Parse(data.Json);
            SavedUrl = data.Url;
            return result;
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch { throw new InvalidOperationException("저장된 구독을 읽지 못했습니다. 구독 주소를 다시 불러와 주세요."); }
        finally { gate.Release(); }
    }

    public async Task<SubscriptionResult> LoadSubscriptionAsync(string url, CancellationToken cancellationToken = default)
    {
        await EnterAsync(cancellationToken);
        if (pipe != null || proxySession != null || broker != null || proxyRecoveryRequired || Status.State == "CLEANUP-REQUIRED")
        {
            gate.Release();
            throw new InvalidOperationException("VPN 연결과 설정 복원을 마친 뒤 구독을 갱신해 주세요.");
        }
        try
        {
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
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        { Set("OFF", "구독 갱신을 취소했습니다."); throw; }
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
        node = SubscriptionParser.Revalidate(node);
        if (ServerCatalog.IsInformation(node.DisplayName))
            throw new InvalidOperationException("사용량·만료 안내 대신 실제 연결 서버를 선택해 주세요.");
        await EnterAsync(cancellationToken);
        if (Status.IsConnected)
        {
            try
            {
                if (!MatchesActiveConnection(node, mode, policy))
                    throw new InvalidOperationException("다른 서버나 연결 방식으로 바꾸려면 먼저 OFF로 종료해 주세요.");
                return;
            }
            finally { gate.Release(); }
        }
        var failureStage = "ipc";
        try
        {
            if (broker != null || pipe != null || proxySession != null || monitor != null || Status.State == "CLEANUP-REQUIRED")
                await StopInternalAsync();
            using (BinaryTrust.OpenVerifiedCore()) { }
            ActiveMode = mode;
            ActiveServerId = node.Id;
            ActiveServerName = node.DisplayName;
            AdvertisedCountryCode = ServerCatalog.GetCountryCode(node.DisplayName);
            activePolicy = policy;
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
                Set("ON", policy.DefaultRoute == "auto" ? "앱 프록시 ON · 자동 판단 · 최초 2분 전체 VPN → 학습·저장 도메인만 VPN" : policy.DefaultRoute == "vpn"
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
            Set("ON", policy.DefaultRoute == "auto" ? "VPN 연결됨 · 자동 판단 · 최초 2분 전체 VPN → 학습·저장 도메인만 VPN" : policy.DefaultRoute == "vpn"
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

    private bool MatchesActiveConnection(VpnNode node, ConnectionMode mode, RoutingPolicy policy) =>
        ActiveServerId == node.Id && ActiveServerName == node.DisplayName && ActiveMode == mode && activePolicy != null
        && activePolicy.DefaultRoute == policy.DefaultRoute
        && activePolicy.VpnDomains.SequenceEqual(policy.VpnDomains, StringComparer.Ordinal)
        && activePolicy.DirectDomains.SequenceEqual(policy.DirectDomains, StringComparer.Ordinal);

    private void ClearActiveConnection()
    {
        ActiveMode = null;
        ActiveServerId = null;
        ActiveServerName = null;
        AdvertisedCountryCode = null;
        activePolicy = null;
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
            var replaced = false;
            while (!session.Exit.IsCompleted && !stopping)
            {
                await Task.WhenAny(session.Exit, Task.Delay(TimeSpan.FromSeconds(2))).ConfigureAwait(false);
                if (stopping) return;
                if (!session.Exit.IsCompleted && !session.HasCurrentSystemProxy) { replaced = true; break; }
            }
            if (stopping) return;
            terminalMessage = replaced ? "proxy-replaced" : "proxy-exited";
            Set("DISCONNECTING", "앱 프록시가 종료되어 이전 프록시 설정을 복원하고 있습니다.", busy: true);
            await session.DisposeAsync();
            proxyRecoveryRequired = false;
            if (ReferenceEquals(proxySession, session)) proxySession = null;
            if (!stopping)
            {
                ClearActiveConnection();
                Set("OFF", replaced ? "Windows 프록시 설정이 바뀌어 연결을 종료했습니다. 새 설정은 유지했습니다."
                    : "앱 프록시가 종료되어 이전 프록시 설정을 복원했습니다.");
            }
        }
        catch
        {
            // A Windows settings read can itself fail while the engine is still alive.
            // Stop the exact session before reporting a recoverable cleanup state.
            var cleaned = false;
            try { await session.DisposeAsync(); cleaned = true; } catch { }
            if (cleaned)
            {
                proxyRecoveryRequired = false;
                if (ReferenceEquals(proxySession, session)) proxySession = null;
                if (!stopping)
                {
                    ClearActiveConnection();
                    Set("OFF", "Windows 프록시 상태를 확인하지 못해 연결을 종료하고 이전 설정을 복원했습니다.");
                }
            }
            else if (!stopping) Set("CLEANUP-REQUIRED", "앱 프록시 종료 후 설정 복원을 확인하지 못했습니다. OFF를 눌러 다시 복원하세요.");
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
            ClearActiveConnection();
            Set("OFF", "VPN이 종료되었습니다. 일반 인터넷 연결로 돌아갑니다.");
        }
    }

    public async Task DisconnectAsync()
    {
        if (disposed) return;
        await gate.WaitAsync();
        try { if (disposed) return; Set("DISCONNECTING", "VPN을 끄고 네트워크를 복원합니다.", busy: true); await StopInternalAsync(); Set("OFF", "VPN이 꺼져 있습니다. 이전 네트워크 설정을 복원했습니다."); }
        catch { Set("CLEANUP-REQUIRED", "연결 설정 복원을 확인하지 못했습니다. OFF를 눌러 다시 복원하세요."); throw; }
        finally { gate.Release(); }
    }

    private async Task StopInternalAsync()
    {
        stopping = true;
        var requiresTunCleanup = ActiveMode == ConnectionMode.SystemTun || broker != null || pipe != null;
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
        if (requiresTunCleanup && TunnelHealth.IsUp())
            throw new InvalidOperationException("터널 종료를 확인하지 못했습니다. OFF를 다시 누르거나 Windows 네트워크 상태를 확인해 주세요.");
        terminalMessage = null;
        ClearActiveConnection();
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

    public ValueTask DisposeAsync()
    {
        lock (disposeSync)
        {
            if (disposal == null || disposal.IsFaulted)
            {
                disposalInProgress = true;
                disposal = DisposeCoreAsync();
            }
            return new ValueTask(disposal);
        }
    }

    private async Task DisposeCoreAsync()
    {
        await gate.WaitAsync();
        try
        {
            Set("DISCONNECTING", "VPN을 끄고 네트워크를 복원합니다.", busy: true);
            await StopInternalAsync();
            disposed = true;
            Set("OFF", "VPN이 꺼져 있습니다. 이전 네트워크 설정을 복원했습니다.");
        }
        catch
        {
            Set("CLEANUP-REQUIRED", "연결 설정 복원을 확인하지 못했습니다. OFF를 눌러 다시 복원하세요.");
            throw;
        }
        finally
        {
            disposalInProgress = false;
            // Pending callers must be released to observe the disposed state; disposing
            // SemaphoreSlim while they wait can otherwise leave their tasks stranded.
            gate.Release();
        }
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetNamedPipeClientProcessId(SafePipeHandle pipe, out uint processId);
}
