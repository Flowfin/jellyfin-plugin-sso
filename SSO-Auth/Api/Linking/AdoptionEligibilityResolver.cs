// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

namespace Jellyfin.Plugin.SSO_Auth.Api.Linking;

/// <summary>
/// The outcome of the adoption-eligibility gate: whether a name-matched pre-existing account may be
/// adopted, or the specific reason it is refused. Closed by convention (the caller throws on an
/// unhandled arm), so a new reason forces a new mapping rather than a silent fall-through.
/// </summary>
internal enum AdoptionVerdict
{
    /// <summary>The pre-existing account may be adopted.</summary>
    Allow,

    /// <summary>Refused: the target account is privileged (administrator) and must be linked explicitly.</summary>
    RefusePrivileged,

    /// <summary>Refused: the provider requires a verified email for adoption and the login carried none (absent or false).</summary>
    RefuseUnverifiedEmail,
}

/// <summary>
/// What the login can prove for a same-named adoption: whether the provider requires a verified email
/// before adopting, and the <c>email_verified</c> claim the login actually carried (null when the claim
/// is absent). SAML has no <c>email_verified</c> concept, so it always passes <see cref="None"/>.
/// </summary>
/// <param name="RequireVerifiedEmail">Whether the provider gates adoption on a verified email.</param>
/// <param name="EmailVerified">The login's <c>email_verified</c> claim: true, false, or null when absent.</param>
internal readonly record struct AdoptionGate(bool RequireVerifiedEmail, bool? EmailVerified)
{
    /// <summary>Gets the no-op gate: no verified-email requirement and no claim (the SAML and default posture).</summary>
    internal static AdoptionGate None => new AdoptionGate(false, null);
}

/// <summary>Decides whether an SSO login may adopt the pre-existing, unlinked Jellyfin account that merely shares its name (#218).</summary>
/// <remarks>
/// Adoption keys on the mutable display name, so on its own it trusts the identity provider to make usernames
/// unique. Two fail-closed gates raise that bar: an administrator account is never adopted by name and must be
/// linked explicitly, and under <c>RequireVerifiedEmailForAdoption</c> the login must carry
/// <c>email_verified == true</c>, off by default so an existing deployment is not locked out on upgrade. Pure,
/// so the caller supplies the target's admin flag and maps a refusal to <see cref="AccountLinkForbiddenException"/>:
/// <see href="https://github.com/Flowfin/jellyfin-plugin-sso/wiki/Security-Model#identity-binding-anti-account-takeover"/>.
/// </remarks>
internal static class AdoptionEligibilityResolver
{
    /// <summary>
    /// Decides whether the name-matched account may be adopted.
    /// </summary>
    /// <param name="targetIsAdministrator">Whether the account about to be adopted holds administrator rights.</param>
    /// <param name="gate">What the login can prove (the verified-email requirement and the asserted claim).</param>
    /// <returns>The adoption verdict.</returns>
    internal static AdoptionVerdict Resolve(bool targetIsAdministrator, AdoptionGate gate)
    {
        if (targetIsAdministrator)
        {
            return AdoptionVerdict.RefusePrivileged;
        }

        if (gate.RequireVerifiedEmail && gate.EmailVerified != true)
        {
            return AdoptionVerdict.RefuseUnverifiedEmail;
        }

        return AdoptionVerdict.Allow;
    }
}
