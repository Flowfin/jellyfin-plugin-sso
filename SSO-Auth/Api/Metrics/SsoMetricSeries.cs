// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

namespace Jellyfin.Plugin.SSO_Auth.Api.Metrics;

/// <summary>
/// One counter series: a metric name and at most one label (#1139). The whole identity of a counter, so the
/// store keys on this and the exposition renders from it without a second vocabulary in between.
/// </summary>
/// <remarks>
/// <para>
/// ONE LABEL, NOT AN ARBITRARY SET, and that is a cardinality decision rather than a simplification. Every
/// counter this plugin publishes is broken down by exactly one thing - the provider, the refusal reason, the
/// endpoint class - and the series count is the product of the label dimensions. A second dimension would
/// multiply the series a caller can cause the plugin to hold, for a breakdown nobody asked for, and the
/// question "how many series can this reach" would stop having a small answer.
/// </para>
/// <para>
/// The label VALUE is never taken from request input. It comes from the configured provider set or from a
/// closed vocabulary, which is what keeps the count bounded by the deployment rather than by a caller.
/// <see cref="SsoMetricsStore"/> holds the backstop for the case that rule is ever broken.
/// </para>
/// <para>
/// No ordering is defined on the type. The one place that needs an order is
/// <see cref="SsoMetricsStore.Snapshot"/>, which states it in the sort rather than hiding it behind a
/// comparison operator nobody reading a counter would think to look for.
/// </para>
/// </remarks>
/// <param name="Metric">The metric name, e.g. <c>sso_login_failure_total</c>.</param>
/// <param name="Label">The label name, or the empty string for a counter with no breakdown.</param>
/// <param name="Value">The label value; the empty string when <paramref name="Label"/> is empty.</param>
internal readonly record struct SsoMetricSeries(string Metric, string Label, string Value);
