using System.Diagnostics;
using System.Text;
using System.Text.Json;
using YaoVpn.Core;

namespace YaoVpn.App.Services;

/// <summary>One connection's learning window, independent of the bounded UI traffic log.</summary>
internal sealed class AutomaticRoutingSession : IAsyncDisposable
{
    internal static readonly TimeSpan LearningDuration = TimeSpan.FromMinutes(10);
    internal const int MaximumLearnedDomains = 16384;
    // A tautology also matches IP-only connections and DNS queries without IP metadata.
    internal const string LearningRules = """{"version":3,"rules":[{"type":"logical","mode":"or","rules":[{"domain_regex":["^"]},{"domain_regex":["^"],"invert":true}]}]}""";
    private readonly object sync = new();
    private readonly HashSet<string> domains;
    private readonly string path;
    private readonly TimeSpan duration;
    private readonly CancellationTokenSource lifetime = new();
    private readonly TaskCompletionSource failure = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private FileStream? fileLock;
    private Task? transition;
    private Task? disposal;
    private long started;
    private bool frozen;

    private AutomaticRoutingSession(string directory, RoutingPolicy policy, TimeSpan duration)
    {
        this.duration = duration;
        path = Path.Combine(directory, ConfigBuilder.AutomaticRuleFile);
        domains = policy.VpnDomains.Concat(policy.DirectDomains).ToHashSet(StringComparer.Ordinal);
        fileLock = new FileStream(path, FileMode.CreateNew, FileAccess.ReadWrite, FileShare.Read);
        try
        {
            fileLock.Write(Encoding.UTF8.GetBytes(LearningRules));
            fileLock.Flush(true);
            fileLock.Dispose();
            fileLock = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        }
        catch { fileLock.Dispose(); throw; }
    }

    internal static AutomaticRoutingSession? Create(string directory, RoutingPolicy policy, TimeSpan? duration = null) =>
        policy.DefaultRoute == "auto" ? new(directory, RoutingPolicy.Validate(policy), duration ?? LearningDuration) : null;

    // A failed update ends the owning connection, rather than silently claiming split routing.
    internal Task Failure => failure.Task;
    internal Task Completion => transition ?? Task.CompletedTask;

    internal void Start()
    {
        lock (sync)
        {
            if (transition != null) throw new InvalidOperationException("Learning already started.");
            started = Stopwatch.GetTimestamp();
            transition = TransitionAsync();
        }
    }

    internal void Observe(TrafficRecord record)
    {
        var valid = TrafficRecord.Validate(record);
        if (valid is not { IsDomain: true }) return;
        lock (sync)
        {
            if (frozen || lifetime.IsCancellationRequested || (started != 0 && Stopwatch.GetElapsedTime(started) >= duration)) return;
            // Preserve the complete observed hostname; the three-label option belongs only to the manual bulk button.
            if (domains.Count >= MaximumLearnedDomains && !domains.Contains(valid.Host))
            {
                frozen = true;
                failure.TrySetResult();
                return;
            }
            domains.Add(valid.Host);
        }
    }

    private async Task TransitionAsync()
    {
        try
        {
            await Task.Delay(duration, lifetime.Token).ConfigureAwait(false);
            string[] snapshot;
            lock (sync)
            {
                if (frozen) return;
                frozen = true;
                snapshot = domains.Order(StringComparer.Ordinal).ToArray();
            }
            var rules = snapshot.Length == 0 ? Array.Empty<object>() : new object[] { new { domain_suffix = snapshot } };
            var bytes = JsonSerializer.SerializeToUtf8Bytes(new { version = 3, rules });
            var temporary = path + ".next";
            try
            {
                // Publish a complete source file in one rename; the core never reads a partial JSON document.
                using var next = new FileStream(temporary, FileMode.CreateNew, FileAccess.ReadWrite, FileShare.Read | FileShare.Delete);
                await next.WriteAsync(bytes, lifetime.Token).ConfigureAwait(false);
                next.Flush(true);
                lifetime.Token.ThrowIfCancellationRequested();
                fileLock?.Dispose();
                fileLock = null;
                File.Move(temporary, path, true);
                next.Dispose();
                fileLock = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
            }
            finally { File.Delete(temporary); }
        }
        catch (OperationCanceledException) when (lifetime.IsCancellationRequested) { }
        catch { failure.TrySetResult(); }
    }

    public ValueTask DisposeAsync()
    {
        lock (sync) return new ValueTask(disposal ??= DisposeCoreAsync());
    }

    private async Task DisposeCoreAsync()
    {
        lifetime.Cancel();
        if (transition != null) await transition.ConfigureAwait(false);
        lock (sync) { frozen = true; domains.Clear(); }
        fileLock?.Dispose();
        fileLock = null;
        // The owning session deletes this known file after the core exits.
        lifetime.Dispose();
    }
}
