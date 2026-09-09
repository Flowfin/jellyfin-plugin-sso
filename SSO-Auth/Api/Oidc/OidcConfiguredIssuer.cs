// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using Duende.IdentityModel.Client;
using Duende.IdentityModel.OidcClient;
using Jellyfin.Plugin.SSO_Auth.Config;

namespace Jellyfin.Plugin.SSO_Auth.Api.Oidc;

/// <summary>
/// Answers whether an issuer offered from OUTSIDE a login - today only by the account-link import (#1518) -
/// is one the provider as configured could actually issue, so a binding is never stored that no login could
/// ever satisfy.
/// </summary>
/// <remarks>
/// <para>
/// The stored binding is the id_token's <c>iss</c>. Two library rules chain into what a provider is
/// configured to issue, and this type runs the SAME two rather than a second copy of them: the id_token is
/// validated with <c>ValidIssuer</c> set to the discovery document's issuer
/// (<c>OidcSignatureKeys.BuildValidationParameters</c>), and the discovery document's issuer is itself
/// validated against the configured authority by <c>DiscoveryPolicy.AuthorityValidationStrategy</c>, which
/// is where the trailing-slash tolerance lives. So the issuer a login can ever stamp is one that is
/// authority-valid against <see cref="OidConfig.OidEndpoint"/>, and an entry offering any other value binds
/// a link whose every future login is refused for a mismatch.
/// </para>
/// <para>
/// The escape hatch is honoured rather than overridden. <c>DoNotValidateIssuerName</c> exists for providers
/// whose issuer legitimately differs from their discovery location - templated and multi-tenant setups - and
/// it relaxes the issuer match on the login path and in the id_token parameters alike. Where it is on, the
/// configuration states no expectation, so there is nothing here to compare against and the entry is
/// accepted exactly as it was before. That is a disclosed hole and not an oversight: an operator who turned
/// the issuer-name check off has turned it off everywhere, and refusing here would lock those providers out
/// of the import with no value they could offer to satisfy it.
/// </para>
/// </remarks>
internal static class OidcConfiguredIssuer
{
    // The offered issuer is echoed back to whoever posted the file, so it is bounded here as well as
    // sanitized wherever it is logged. A refusal has to be readable in a dashboard toast, and the value is
    // the caller's own text rather than the plugin's.
    private const int MaxEchoedIssuerChars = 200;

    // The same marker the discovery reader bounds a provider error with, so a truncated value reads the
    // same wherever the plugin produces one.
    private const string TruncationMarker = "[truncated]";

    /// <summary>
    /// Reports why <paramref name="issuer"/> may not be stored as the binding for a link on
    /// <paramref name="config"/>, or <see langword="null"/> when it may.
    /// </summary>
    /// <param name="config">The OpenID provider the link belongs to.</param>
    /// <param name="issuer">The issuer offered for the link. Blank is not this method's subject and is accepted; a caller that treats an absent issuer as "leave the binding alone" asks before it gets here.</param>
    /// <returns>A reason naming both issuers, or <see langword="null"/> when the value is one the provider could issue.</returns>
    internal static string? Refuse(OidConfig config, string? issuer)
    {
        ArgumentNullException.ThrowIfNull(config);

        if (string.IsNullOrWhiteSpace(issuer))
        {
            return null;
        }

        // The policy is BUILT from the provider rather than assumed, and it is the same builder the login
        // and the admin probe use, so this check cannot drift onto a weaker or a stricter rule than the one
        // discovery will actually apply. It carries DoNotValidateIssuerName as ValidateIssuerName, and it
        // carries whichever comparison strategy the plugin configures - today the library default, where
        // the trailing-slash tolerance lives.
        OidcClientOptions options;
        string authority;
        try
        {
            options = OidcDiscoveryOptions.Build(config);

            // ParseUrl is the normalisation the discovery read applies before validating - it strips a
            // /.well-known/openid-configuration suffix and the trailing slash - and its result is what the
            // library assigns to Policy.Authority. Running it here means an endpoint written either way
            // expects the same issuer, instead of this check disagreeing with the login over a slash.
            authority = DiscoveryEndpoint.ParseUrl(options.Authority).Authority;
        }
        catch (Exception ex) when (ex is UriFormatException or ArgumentException or InvalidOperationException)
        {
            // Fail closed. A provider whose endpoint is not a usable URL can complete no login at all, so no
            // reading of its configuration makes any issuer the right one to store against it.
            return $"the OpenID endpoint configured for this provider is not a usable URL, so nothing says what it issues; the entry offers '{Echo(issuer)}'";
        }

        var policy = options.Policy.Discovery;
        if (!policy.ValidateIssuerName || policy.AuthorityValidationStrategy.IsIssuerNameValid(issuer, authority).Success)
        {
            return null;
        }

        return $"the entry's issuer '{Echo(issuer)}' is not what this provider is configured to issue ('{Echo(authority)}'), so every login on the restored link would be refused for a mismatch; re-point the provider or re-key the link deliberately";
    }

    private static string Echo(string value) =>
        value.Length > MaxEchoedIssuerChars
            ? string.Concat(value.AsSpan(0, MaxEchoedIssuerChars), TruncationMarker)
            : value;
}
