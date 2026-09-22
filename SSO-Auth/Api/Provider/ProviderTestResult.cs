// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Collections.Generic;

namespace Jellyfin.Plugin.SSO_Auth.Api.Provider;

/// <summary>
/// The admin-facing result of a provider Test-connection probe (#163): whether the probe passed, the catalogue
/// key of its verdict, and the non-secret facts it observed (issuer, endpoints, JWKS reachability, or the SAML
/// certificate's public facts). It carries KEYS rather than sentences (#1728), so the settings page renders it
/// through the localization catalogue in the administrator's language. It NEVER carries a secret - no
/// <c>OidSecret</c>, no signing-key/DEK material - and a verdict names what to check, never a sensitive value.
/// Serialized to the admin UI as JSON; the page renders every field with <c>textContent</c>/<c>createElement</c>
/// so a reflected provider value cannot inject markup.
/// </summary>
/// <param name="Ok">Whether the probe's core check passed (discovery readable, or the SAML certificate parses).</param>
/// <param name="Key">The catalogue key of the verdict, one of <see cref="ProviderTestKeys"/>.</param>
/// <param name="Facts">The non-secret fact lines describing what the probe observed.</param>
internal sealed record ProviderTestResult(bool Ok, string Key, IReadOnlyList<ProviderTestFact> Facts)
{
    /// <summary>A failed probe whose verdict names what to check, with no facts.</summary>
    /// <param name="key">The catalogue key of the failure verdict.</param>
    /// <returns>A failed result.</returns>
    internal static ProviderTestResult Failure(string key) =>
        Failure(key, Array.Empty<ProviderTestFact>());

    /// <summary>A failed probe whose verdict needs the values it names to be acted on (#1837).</summary>
    /// <param name="key">The catalogue key of the failure verdict.</param>
    /// <param name="facts">The non-secret fact lines the verdict refers to.</param>
    /// <returns>A failed result.</returns>
    internal static ProviderTestResult Failure(string key, IReadOnlyList<ProviderTestFact> facts) =>
        new(false, key, facts);

    /// <summary>A passing probe carrying the non-secret facts the administrator can confirm the config against.</summary>
    /// <param name="key">The catalogue key of the success verdict.</param>
    /// <param name="facts">The non-secret fact lines.</param>
    /// <returns>A passing result.</returns>
    internal static ProviderTestResult Success(string key, IReadOnlyList<ProviderTestFact> facts) =>
        new(true, key, facts);
}
