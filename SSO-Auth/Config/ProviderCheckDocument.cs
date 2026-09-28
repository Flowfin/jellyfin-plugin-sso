// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System.Collections.Generic;

namespace Jellyfin.Plugin.SSO_Auth.Config;

/// <summary>What one aggregate configuration check answers: every configured provider, and whether a login against it would fail today and why (#1084).</summary>
/// <remarks>
/// Advisory only and no field value on the wire; reachability is the per-provider Test Connection's question. See
/// <see href="https://github.com/Flowfin/jellyfin-plugin-sso/wiki/Hardening-and-Options-Reference#configuration-check-admin"/>.
/// </remarks>
public class ProviderCheckDocument
{
    /// <summary>Gets one row per configured provider, OpenID first, in configuration order.</summary>
    public IReadOnlyList<ProviderCheckResult> Providers { get; init; } = new List<ProviderCheckResult>();

    /// <summary>Gets a value indicating whether the stored configuration could not be read at start, so the rows describe a default one (#1543).</summary>
    /// <remarks>No path on the wire: where the unreadable file was kept is in the server log.</remarks>
    public bool ConfigurationUnreadable { get; init; }
}

/// <summary>One provider's row in <see cref="ProviderCheckDocument"/>.</summary>
public class ProviderCheckResult
{
    /// <summary>Gets the protocol label, spelled as the refusal messages spell it.</summary>
    public string Protocol { get; init; } = string.Empty;

    /// <summary>Gets the provider name, keyed as it is in the configuration.</summary>
    public string Provider { get; init; } = string.Empty;

    /// <summary>Gets a value indicating whether a login against this provider would get past the configuration.</summary>
    /// <remarks>Independent of <see cref="Enabled"/>: a provider an administrator turned off is not misconfigured.</remarks>
    public bool Ready { get; init; }

    /// <summary>Gets a value indicating whether the provider is switched on.</summary>
    public bool Enabled { get; init; }

    /// <summary>Gets the required settings that are empty, by property name, which is also the settings page's field id.</summary>
    public IReadOnlyList<string> MissingFields { get; init; } = new List<string>();

    /// <summary>Gets the message the save path would refuse this provider with, or null; one message, because the save refuses on the first rule.</summary>
    public string? Problem { get; init; }
}
