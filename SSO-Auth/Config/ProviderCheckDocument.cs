// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System.Collections.Generic;

namespace Jellyfin.Plugin.SSO_Auth.Config;

/// <summary>
/// What one aggregate configuration check answers (#1084): every configured OpenID and SAML provider, and
/// for each of them whether a login against it would fail today and why.
/// </summary>
/// <remarks>
/// <para>
/// ADVISORY ONLY. Building this report reads the configuration and writes nothing: no provider field, no
/// toggle, no persisted byte. Nothing here blocks a save, and an administrator who disagrees with a row can
/// save the provider anyway - the save path keeps its own fail-closed refusal, which is where a bad value is
/// actually stopped.
/// </para>
/// <para>
/// NO FIELD VALUE ON THE WIRE. A row carries the provider's name, which of its REQUIRED settings are empty
/// by property name, and the refusal message the save path itself would produce. The refusal messages are
/// the admin-facing ones <see cref="ProviderConfigValidator"/> already shows on a rejected save, so nothing
/// reaches this report that an administrator does not already read on the settings page, and no secret is
/// among them.
/// </para>
/// <para>
/// REACHABILITY IS NOT PART OF THIS ANSWER, and the consumer must say so rather than leaving it out. Probing
/// every provider from here would spend one shared throttle budget - both Test routes pass
/// <c>SsoRateLimitClass.Test</c>, so a fan-out over many providers empties the bucket and the 429s that
/// follow would name working providers as broken, worst on exactly the installations with the most providers
/// to check. So a row says whether the configuration is complete and valid; whether the identity provider
/// answers is what the per-provider Test Connection is for.
/// </para>
/// </remarks>
public class ProviderCheckDocument
{
    /// <summary>
    /// Gets one row per configured provider, OpenID first and SAML after it, each in the order the
    /// configuration holds them. An installation with no provider configured gets an empty list, which is a
    /// report rather than an error.
    /// </summary>
    public IReadOnlyList<ProviderCheckResult> Providers { get; init; } = new List<ProviderCheckResult>();
}

/// <summary>
/// One provider's row in <see cref="ProviderCheckDocument"/>.
/// </summary>
public class ProviderCheckResult
{
    /// <summary>
    /// Gets the protocol label, "OpenID" or "SAML", spelled as
    /// <see cref="ProviderConfigValidator"/> spells it in the refusal messages so a row and its reason
    /// cannot disagree about which provider they are describing.
    /// </summary>
    public string Protocol { get; init; } = string.Empty;

    /// <summary>
    /// Gets the provider name, keyed as it is in <see cref="PluginConfiguration.OidConfigs"/> or
    /// <see cref="PluginConfiguration.SamlConfigs"/> so a consumer can match a row to a card without a
    /// second lookup.
    /// </summary>
    public string Provider { get; init; } = string.Empty;

    /// <summary>
    /// Gets a value indicating whether a login against this provider would get past the configuration:
    /// every required setting filled in, and nothing the save path would refuse.
    /// </summary>
    /// <remarks>
    /// Deliberately independent of <see cref="Enabled"/>. A provider an administrator turned off is not
    /// misconfigured, and reporting it as needing attention would train them to ignore the report.
    /// </remarks>
    public bool Ready { get; init; }

    /// <summary>
    /// Gets a value indicating whether the provider is switched on and therefore offered at the login page.
    /// </summary>
    public bool Enabled { get; init; }

    /// <summary>
    /// Gets the required settings that are empty, by PROPERTY name - which is also the id the settings page
    /// gives that field, so a consumer resolves each one to the form's own localized label instead of
    /// carrying a second copy of every label to drift against.
    /// </summary>
    public IReadOnlyList<string> MissingFields { get; init; } = new List<string>();

    /// <summary>
    /// Gets the message the save path would refuse this provider with, or null where it would refuse
    /// nothing. One message rather than a list: the save is refused on the first invalid rule found, so a
    /// second one here would claim a completeness the refusal itself does not have.
    /// </summary>
    public string? Problem { get; init; }
}
