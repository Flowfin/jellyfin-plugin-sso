// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Globalization;

namespace Jellyfin.Plugin.SSO_Auth.Api.Metrics;

/// <summary>
/// The counters the plugin publishes, and the only way a call site reaches one (#1139). One named method per
/// counter, so the metric names and the label names are decided here rather than spelled at each call site,
/// where two of them would eventually disagree.
/// </summary>
/// <remarks>
/// <para>
/// A LABEL CANNOT CARRY A USERNAME, A SUBJECT OR A CLAIM VALUE, AND THAT IS THE SIGNATURE'S DOING RATHER
/// THAN A RULE SOMEBODY REMEMBERS. Every breakdown except the provider takes a value constrained to
/// <see cref="Enum"/>, so an identity string does not compile at the call site. The provider name is the one
/// string label and it is configuration an administrator typed, never request input.
/// </para>
/// <para>
/// This module imports no other, and that is why the enum parameters are generic. The refusal reasons live in
/// the session tier and the throttle classes in the shared tier, both of which sit above this one; naming
/// either type here would turn the import into a cycle. What is asked of the value is that it be an enum,
/// which is the property the cardinality bound rests on, and the callers passing the right ones is pinned by
/// <c>SsoMetricsTests</c>.
/// </para>
/// </remarks>
internal static class SsoMetrics
{
    /// <summary>Logins that minted a session, by provider.</summary>
    internal const string LoginSuccessTotal = "sso_login_success_total";

    /// <summary>Login attempts the plugin refused, by the public reason the caller was given.</summary>
    internal const string LoginFailureTotal = "sso_login_failure_total";

    /// <summary>Accounts an SSO login brought into existence or took over, by which of the two it was.</summary>
    internal const string AccountProvisionedTotal = "sso_account_provisioned_total";

    /// <summary>Failed server-to-provider fetches, by which fetch it was.</summary>
    internal const string ProviderFetchErrorTotal = "sso_provider_fetch_error_total";

    /// <summary>Requests the rate limiter refused, by endpoint class.</summary>
    internal const string RequestThrottledTotal = "sso_request_throttled_total";

    /// <summary>Increments dropped because they named a series beyond the store's cap.</summary>
    internal const string SeriesRefusedTotal = "sso_metrics_series_refused_total";

    /// <summary>Records a login that completed and minted a session.</summary>
    /// <param name="provider">The provider name as configured; blank is recorded as <c>unnamed</c> rather than as an empty label.</param>
    internal static void LoginSucceeded(string? provider) =>
        SsoMetricsStore.Increment(new SsoMetricSeries(LoginSuccessTotal, "provider", Named(provider)));

    /// <summary>Records a login attempt the plugin refused.</summary>
    /// <typeparam name="TReason">The refusal vocabulary; an enum, so no identity string can reach the label.</typeparam>
    /// <param name="reason">The reason the caller was given.</param>
    internal static void LoginFailed<TReason>(TReason reason)
        where TReason : struct, Enum =>
        SsoMetricsStore.Increment(new SsoMetricSeries(LoginFailureTotal, "reason", reason.ToString()));

    /// <summary>
    /// Records a login refused for want of permission rather than for a stated public reason. Its own method
    /// rather than a member of the reason vocabulary: the denial is decided a tier above the reasons and
    /// belongs to no protocol, and widening that closed enum for a label would change what every other
    /// consumer of it has to handle.
    /// </summary>
    internal static void LoginDenied() =>
        SsoMetricsStore.Increment(new SsoMetricSeries(LoginFailureTotal, "reason", "Denied"));

    /// <summary>Records an account an SSO login created or adopted.</summary>
    /// <param name="outcome">Which of the two happened.</param>
    internal static void AccountProvisioned(ProvisioningOutcome outcome) =>
        SsoMetricsStore.Increment(new SsoMetricSeries(AccountProvisionedTotal, "outcome", outcome.ToString()));

    /// <summary>Records a server-to-provider fetch that failed.</summary>
    /// <param name="stage">Which fetch failed.</param>
    internal static void ProviderFetchFailed(ProviderFetchStage stage) =>
        SsoMetricsStore.Increment(new SsoMetricSeries(ProviderFetchErrorTotal, "stage", stage.ToString()));

    /// <summary>
    /// Records a request the rate limiter refused. The one label here that is a string rather than an enum,
    /// because the endpoint-class vocabulary is named constants and not an enum - a shape a conformance test
    /// already holds in place, by refusing a raw literal at the gate's call sites for a stronger reason than
    /// this one: a typo there silently mints a separate, empty rate-limit bucket.
    /// </summary>
    /// <param name="endpointClass">The class of endpoint that was throttled; one of the named rate-limit class constants, never request input.</param>
    internal static void RequestThrottled(string endpointClass) =>
        SsoMetricsStore.Increment(new SsoMetricSeries(RequestThrottledTotal, "class", Named(endpointClass)));

    // A provider with no name is a configuration nothing else in the plugin accepts either, but a counter
    // that answered it with an empty label would render a line a scraper reads as a different metric. It is
    // named instead, so the series is visible rather than malformed.
    private static string Named(string? provider) =>
        string.IsNullOrWhiteSpace(provider)
            ? "unnamed"
            : provider.ToString(CultureInfo.InvariantCulture);
}
