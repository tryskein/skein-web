using Metricy.Annotations;
using Prometheus;
using PromMetrics = Prometheus.Metrics;

namespace SkeinWeb.Hubs;

/// <summary>
/// Custom Prometheus metrics of the SignalR hub and its delivery machinery
/// (spec sk-622.21).
/// </summary>
public static class HubMetrics
{
    /// <summary>Rejected project declarations, by reason.</summary>
    [MetricInfo(
        description: "Counts project ids rejected by the hub methods DeclareProjects / DeclareAllVisible, by reason. One increment per rejected id (a refused DeclareAllVisible counts one).",
        calculation: "Incremented in SkeinHub.DeclareProjects and SkeinHub.DeclareAllVisible for every entry written to DeclareResult.rejected, before the result is returned to the browser.")]
    [MetricLabel("reason", "Rejection reason: no_access, limit, rate, invalid")]
    public static readonly Counter DeclarationsRejected = PromMetrics.CreateCounter(
        "skein_web_hub_declarations_rejected_total",
        "Project ids rejected by hub declarations, by reason",
        new CounterConfiguration { LabelNames = new[] { "reason" } });

    /// <summary>Project events forwarded to browsers, by entity type.</summary>
    [MetricInfo(
        description: "Counts project events the NATS bridge forwarded to browsers as compact envelopes. One increment per event (not per receiving connection: delivery goes to the SignalR group project:{pid}).",
        calculation: "Incremented in NatsBridge.ForwardProjectEvent after the group send completes; per-field child events and project reminder.* events are not forwarded and not counted.")]
    [MetricLabel("entity", "Entity type of the event: issue, project, comment, dep, attachment, component")]
    public static readonly Counter ProjectEventsForwarded = PromMetrics.CreateCounter(
        "skein_web_bridge_project_events_forwarded_total",
        "Project events forwarded to browsers, by entity type",
        new CounterConfiguration { LabelNames = new[] { "entity" } });

    /// <summary>Personal signals absorbed into an already open per-connection window.</summary>
    [MetricInfo(
        description: "Counts personal signals (skein.user.{uid}.signal) that did not produce a frame of their own because the receiving connection already had an open coalescing window; their areas were merged into that window's single frame. One increment per (signal, connection) pair, on each replica holding a connection of the user.",
        calculation: "Incremented in PersonalSignalCoalescer.SignalConnection when a signal arrives for a connection whose COUNTS_SIGNAL_WINDOW_MS window is open.")]
    public static readonly Counter PersonalSignalsCoalesced = PromMetrics.CreateCounter(
        "skein_web_personal_signals_coalesced_total",
        "Personal signals merged into an open per-connection window");

    /// <summary>Project-delivery group memberships revoked from hub connections, by trigger.</summary>
    [MetricInfo(
        description: "Counts project-delivery group memberships (project:{pid}) taken away from hub connections of this replica because access was lost or could not be confirmed. One increment per group left.",
        calculation: "Incremented in AccessRecheckService (re-check answer narrower than the groups held, or fail-closed after 60 s without a successful check) and in AccessControlSubscriber on user.deactivated and on access_changed (groups of the lost projects, left at once).")]
    [MetricLabel("reason", "What revoked it: event (a control event — access_changed, membership, role, deactivation, and the re-checks they trigger), recheck (periodic or post-reconnect re-check, fail-closed included)")]
    public static readonly Counter AccessRevoked = PromMetrics.CreateCounter(
        "skein_web_hub_access_revoked_total",
        "Project-delivery group memberships revoked from hub connections, by trigger",
        new CounterConfiguration { LabelNames = new[] { "reason" } });

    /// <summary>Bridge sends to SignalR that failed and were dropped.</summary>
    [MetricInfo(
        description: "Counts SignalR sends of the NATS bridge (project events to groups, user events to a user and to admins:internal, reminder frames) that failed — typically while the Redis backplane is unreachable — and were dropped. Their addressees get a resync frame when the backplane is restored.",
        calculation: "Incremented in TransportHealthMonitor.RecordFailedGroupSend / RecordFailedUserSend, called by NatsBridge once per failed send.")]
    public static readonly Counter BridgeSendsFailed = PromMetrics.CreateCounter(
        "skein_web_bridge_sends_dropped_total",
        "SignalR sends of the NATS bridge that failed and were dropped");
}
