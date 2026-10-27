namespace YaoVpn.Core;

/// <summary>A sanitized connection. OutboundJson is sensitive and must only be stored encrypted.</summary>
public sealed record VpnNode(string Id, string DisplayName, string Protocol, string Server, int Port, string OutboundJson)
{
    // The synthesized record representation would include passwords and UUIDs.
    public override string ToString() => DisplayName;
}

public sealed record SubscriptionResult(IReadOnlyList<VpnNode> Nodes, int RejectedCount);
