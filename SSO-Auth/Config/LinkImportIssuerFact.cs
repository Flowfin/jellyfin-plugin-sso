// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

namespace Jellyfin.Plugin.SSO_Auth.Config;

/// <summary>
/// What one OpenID provider on this instance is configured to issue, as the link import (#1518) reads it
/// before deciding whether a backup file's issuer may be written. Three states, and they are three because
/// two of them must not collapse: an issuer that was read, a read that failed with a reason an
/// administrator can act on, and a provider nothing was looked up for.
/// </summary>
/// <remarks>
/// The distinction that matters is between <c>Unreadable</c> and the default. A failed read is a fact about
/// tonight - the identity provider is down, the endpoint is wrong - and the operator can retry. The default
/// is the absence of any lookup at all, which is what a caller supplying no facts hands in, and it refuses
/// an issuer-carrying entry for the same reason a failed read does: nothing compared it to anything, which
/// is exactly the state #1518 exists to stop being written into a link table.
/// </remarks>
/// <param name="Issuer">The issuer the provider's discovery document declares, or null when none was read.</param>
/// <param name="Unreadable">
/// Why the provider's issuer could not be read, in a sentence safe to hand an administrator, or null when
/// the read succeeded or was never attempted.
/// </param>
internal readonly record struct LinkImportIssuerFact(string? Issuer, string? Unreadable)
{
    /// <summary>A successful read.</summary>
    /// <param name="issuer">The issuer the provider's discovery document declares.</param>
    /// <returns>A fact carrying that issuer.</returns>
    internal static LinkImportIssuerFact Read(string issuer) => new(issuer, null);

    /// <summary>A read that failed, carrying the cause an administrator is shown.</summary>
    /// <param name="cause">Why the read failed. Never a secret and never a raw library error.</param>
    /// <returns>A fact carrying that cause and no issuer.</returns>
    internal static LinkImportIssuerFact Failed(string cause) => new(null, cause);
}
