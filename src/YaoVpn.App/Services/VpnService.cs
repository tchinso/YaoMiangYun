using System.ComponentModel;
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

public sealed class VpnService : IAsyncDisposable
{
    private readonly string applicationExecutable;
    public VpnService() : this(Environment.ProcessPath ?? throw new IOException("Application path unavailable.")) { }
    internal VpnService(string applicationExecutable) { this.applicationExecutable = Path.GetFullPath(applicationExecutable); }
    private readonly SemaphoreSlim gate = new(1, 1);
    private NamedPipeServerStream? pipe;
    private Process? broker;
    private Task? monitor;
    private bool stopping;
    private string? terminalMessage;
    public event Action<VpnStatus>? StatusChanged;
    public VpnStatus Status { get; private set; } = new("OFF", "VPN이 꺼져 있습니다.", false, false);
    public string? SavedUrl { get; private set; }
    private sealed record SavedSubscription(string Url, string Json);

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
            if (pipe != null) throw new InvalidOperationException("VPN을 끈 뒤 구독을 갱신해 주세요.");
            if (!Uri.TryCreate(url.Trim(), UriKind.Absolute, out var uri) || uri.Scheme != "https" || uri.UserInfo.Length != 0 || uri.Fragment.Length != 0 || uri.IsLoopback || url.Length > 4096)
                throw new InvalidOperationException("올바른 HTTPS 구독 주소를 입력해 주세요.");
            Set("OFF", "구독의 연결 정보를 확인하고 있습니다.", busy: true);
            using var handler = new HttpClientHandler { AllowAutoRedirect = false, AutomaticDecompression = DecompressionMethods.GZip | DecompressionMethods.Deflate, UseProxy = false };
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

    public async Task ConnectAsync(VpnNode node, CancellationToken cancellationToken = default)
    {
        await gate.WaitAsync(cancellationToken);
        var failureStage = "ipc";
        try
        {
            if (pipe != null) return;
            if (broker != null) await StopInternalAsync();
            node = SubscriptionParser.Revalidate(node);
            using (BinaryTrust.OpenVerifiedCore()) { }
            Set("CONNECTING", "Windows 관리자 권한을 승인하면 VPN을 연결합니다.", busy: true);
            stopping = false;
            terminalMessage = null;
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
            await PipeProtocol.WriteAsync(pipe, new("connect", node), timeout.Token);
            var reply = await PipeProtocol.ReadAsync(pipe, timeout.Token);
            if (reply.Kind != "started")
            {
                failureStage = reply.Kind is "failed-ipc" or "failed-storage" or "failed-core" or "failed-routes" ? reply.Kind : "core";
                throw new IOException();
            }
            failureStage = "https";
            Set("CONNECTING", "터널을 만들었습니다. HTTPS 연결을 확인합니다.", busy: true);
            if (!await ProbeAsync(timeout.Token) || broker.HasExited || !TunnelHealth.HasRoutes()) throw new IOException();
            Set("ON", "VPN 연결됨 · IPv4 / IPv6 전체 터널", true);
            monitor = MonitorAsync(pipe);
        }
        catch (Win32Exception e) when (e.NativeErrorCode == 1223)
        {
            await StopInternalAsync(); Set("OFF", "관리자 권한 요청이 취소되었습니다.");
            throw new InvalidOperationException("VPN 연결에는 Windows 관리자 권한 승인이 필요합니다.");
        }
        catch
        {
            await StopInternalAsync(); Set("OFF", "연결하지 못했습니다. 다른 서버를 선택해 주세요.");
            throw new InvalidOperationException("VPN 연결을 확인하지 못했습니다. 다른 서버로 시도해 주세요. 엔진 파일이나 권한도 확인해 주세요. (" + failureStage + ")");
        }
        finally { gate.Release(); }
    }

    private async Task MonitorAsync(NamedPipeServerStream session)
    {
        try
        {
            var message = await PipeProtocol.ReadAsync(session);
            terminalMessage = message.Kind;
            if (!stopping)
                Set("OFF", message.Kind == "cleanup-warning" ? "터널 정리를 확인하지 못했습니다. Windows 네트워크 상태를 확인해 주세요." : "VPN이 종료되었습니다. 일반 인터넷 연결로 돌아갑니다.");
        }
        catch (Exception e) when (e is IOException or ObjectDisposedException)
        { if (!stopping) Set("OFF", "VPN 연결이 종료되었습니다. 일반 인터넷 연결로 돌아갑니다."); }
        finally
        {
            if (!stopping) { session.Dispose(); if (ReferenceEquals(pipe, session)) pipe = null; }
        }
    }

    public async Task DisconnectAsync()
    {
        await gate.WaitAsync();
        try { Set("DISCONNECTING", "VPN을 끄고 네트워크를 복원합니다.", busy: true); await StopInternalAsync(); Set("OFF", "VPN이 꺼져 있습니다. 일반 인터넷을 사용합니다."); }
        finally { gate.Release(); }
    }

    private async Task StopInternalAsync()
    {
        stopping = true;
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
        if (terminalMessage == "cleanup-warning" || TunnelHealth.IsUp())
            throw new InvalidOperationException("터널 종료를 확인하지 못했습니다. OFF를 다시 누르거나 Windows 네트워크 상태를 확인해 주세요.");
    }

    public async Task<bool> ProbeAsync(CancellationToken cancellationToken = default)
    {
        using var handler = new HttpClientHandler { UseProxy = false, AllowAutoRedirect = false };
        using var client = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(10) };
        foreach (var endpoint in new[] { "https://www.gstatic.com/generate_204", "https://cp.cloudflare.com/generate_204" })
        {
            try { using var response = await client.GetAsync(endpoint, HttpCompletionOption.ResponseHeadersRead, cancellationToken); if (response.StatusCode == HttpStatusCode.NoContent) return true; }
            catch (Exception e) when (e is HttpRequestException or TaskCanceledException) { }
        }
        return false;
    }

    public async ValueTask DisposeAsync() { await DisconnectAsync(); gate.Dispose(); }

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetNamedPipeClientProcessId(SafePipeHandle pipe, out uint processId);
}
