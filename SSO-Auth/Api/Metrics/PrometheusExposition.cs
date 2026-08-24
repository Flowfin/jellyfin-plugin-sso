// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System.Collections.Generic;
using System.Globalization;
using System.Text;

namespace Jellyfin.Plugin.SSO_Auth.Api.Metrics;

/// <summary>
/// Renders the counters as Prometheus text exposition (#1139), which is the one format the endpoint speaks.
/// </summary>
/// <remarks>
/// <para>
/// TEXT DIRECTLY, RATHER THAN THROUGH AN EXPORTER, and the reason is that the endpoint has to be able to
/// READ the values. <c>System.Diagnostics.Metrics.Counter&lt;T&gt;</c> is write-only: recovering a total from
/// one needs a <c>MeterListener</c>, which is a second aggregation of the same increments and a second thing
/// to keep in step with the first. What a meter would have bought - attaching an exporter later without
/// touching the call sites - is bought here by the call sites going through <see cref="SsoMetrics"/>: a
/// meter added inside those methods reaches every site at once. No new package is taken on.
/// </para>
/// <para>
/// A label value is escaped rather than trusted. Every value the plugin passes today is an enum name or a
/// configured provider name, and a provider name is validated on the way in - but the escape is what makes
/// that a property of this file instead of a property of every current call site, so a name with a quote or a
/// newline in it cannot forge a line in somebody's scrape.
/// </para>
/// </remarks>
internal static class PrometheusExposition
{
    /// <summary>The content type a Prometheus scraper expects, version included.</summary>
    internal const string ContentType = "text/plain; version=0.0.4; charset=utf-8";

    /// <summary>
    /// Renders one snapshot. Every counter the plugin knows about is emitted even at zero, because a series
    /// that appears only once it is non-zero cannot be alerted on with a rate rule until the thing being
    /// alerted on has already happened.
    /// </summary>
    /// <param name="snapshot">The counters, as <see cref="SsoMetricsStore.Snapshot"/> returns them.</param>
    /// <param name="refusedSeries">How many increments the store's cap dropped.</param>
    /// <returns>The exposition text, newline-terminated.</returns>
    internal static string Render(IReadOnlyList<(SsoMetricSeries Series, long Value)> snapshot, long refusedSeries)
    {
        var text = new StringBuilder();
        var openMetric = string.Empty;

        foreach (var (series, value) in snapshot)
        {
            if (!string.Equals(openMetric, series.Metric, System.StringComparison.Ordinal))
            {
                AppendHeader(text, series.Metric);
                openMetric = series.Metric;
            }

            text.Append(series.Metric);
            if (series.Label.Length > 0)
            {
                text.Append('{').Append(series.Label).Append("=\"").Append(Escape(series.Value)).Append("\"}");
            }

            text.Append(' ').Append(value.ToString(CultureInfo.InvariantCulture)).Append('\n');
        }

        // Always last and always present, including at zero: a scrape missing a breakdown has to say so on
        // the same scrape, or the gap is indistinguishable from nothing having happened.
        AppendHeader(text, SsoMetrics.SeriesRefusedTotal);
        text.Append(SsoMetrics.SeriesRefusedTotal)
            .Append(' ')
            .Append(refusedSeries.ToString(CultureInfo.InvariantCulture))
            .Append('\n');

        return text.ToString();
    }

    private static void AppendHeader(StringBuilder text, string metric) =>
        text.Append("# HELP ").Append(metric).Append(' ').Append(Help(metric)).Append('\n')
            .Append("# TYPE ").Append(metric).Append(" counter\n");

    private static string Help(string metric) => metric switch
    {
        SsoMetrics.LoginSuccessTotal => "SSO logins that minted a session, by provider.",
        SsoMetrics.LoginFailureTotal => "SSO login attempts refused, by the reason given to the caller.",
        SsoMetrics.AccountProvisionedTotal => "Jellyfin accounts an SSO login created or adopted.",
        SsoMetrics.ProviderFetchErrorTotal => "Failed server-to-provider fetches, by which fetch failed.",
        SsoMetrics.RequestThrottledTotal => "Requests the SSO rate limiter refused, by endpoint class.",
        SsoMetrics.SeriesRefusedTotal => "Counter increments dropped because they named a series beyond the cap.",
        _ => "An SSO counter.",
    };

    // The three characters the text format gives meaning to inside a quoted label value. Backslash first,
    // or the escape this method just wrote would be escaped again by the next replacement.
    private static string Escape(string value) =>
        value.Replace("\\", "\\\\", System.StringComparison.Ordinal)
            .Replace("\"", "\\\"", System.StringComparison.Ordinal)
            .Replace("\n", "\\n", System.StringComparison.Ordinal);
}
