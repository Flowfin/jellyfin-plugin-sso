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
/// Under <c>DoNotValidateIssuerName</c> the answer is YES for every value, and that is an entailment rather
/// than a relaxation. The toggle sets <c>ValidateIssuer</c> to false in the id_token parameters
/// (<c>OidcSignatureKeys.BuildValidationParameters</c>), so a login on that provider accepts a JWKS-signed
/// token carrying ANY <c>iss</c> and can therefore stamp any issuer at all. A check asking whether a login
/// could stamp this value has exactly one honest answer there, and it is not a hole this type is choosing
/// to leave open.
/// </para>
/// <para>
/// WHAT THAT DOES NOT MAKE SAFE, and the operator documentation says it in the same breath: the binding
/// comparison itself is unconditional. <c>CanonicalLinkService.ClassifyIssuer</c> never reads the toggle, so
/// a stored issuer that a later id_token does not match refuses that link forever on such a provider too.
/// Turning the toggle on to get past this refusal converts a loud one into a silent permanent lockout AND
/// switches issuer validation off on the login path, which is why no page here offers it as a way through.
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

            var policy = options.Policy.Discovery;

            // ParseUrl is the normalisation the discovery read applies before validating - it strips a
            // /.well-known/openid-configuration suffix and the trailing slash - and its result is what the
            // library assigns to Policy.Authority. Running it here means an endpoint written either way
            // expects the same issuer, instead of this check disagreeing with the login over a slash. The
            // discovery path travels with it because the login derives it the same way: nothing configures a
            // custom path today, and passing it makes the claim above structural rather than incidental.
            authority = DiscoveryEndpoint.ParseUrl(options.Authority, policy.DiscoveryDocumentPath).Authority;

            // The strategy call is INSIDE this try on purpose. ParseUrl can hand back an authority that is not
            // a URL - an endpoint of the shape "http://a.well-known/openid-configuration" yields "http://" -
            // and a strategy that parses its arguments throws on that. A refusal that turns into a 500 out of
            // MutateConfiguration would answer "cannot tell" with a crash instead of with no.
            if (!policy.ValidateIssuerName
                || (policy.AuthorityValidationStrategy is { } strategy
                    && strategy.IsIssuerNameValid(issuer, authority).Success))
            {
                return null;
            }
        }
        catch (Exception ex) when (ex is UriFormatException or ArgumentException or InvalidOperationException)
        {
            // Fail closed. A provider whose endpoint is not a usable URL can complete no login at all, so no
            // reading of its configuration makes any issuer the right one to store against it.
            return $"the OpenID endpoint configured for this provider is not a usable URL, so nothing says what it issues; the entry offers '{Echo(issuer)}'";
        }

        return $"the entry's issuer '{Echo(issuer)}' is not what this provider is configured to issue ('{Echo(authority)}'), so every login on the restored link would be refused for a mismatch; remove the Issuer field from these entries to restore the links unbound and let the first login bind them, or fix the provider before importing - do NOT change OidEndpoint after a restore, which clears the link table";
    }

    // The caller's value is stripped of line endings and has its record-marker bracket substituted before
    // the plugin's own truncation marker is joined to it (#1566): the marker opens with the very bracket the
    // substitution removes, so sanitizing the joined text would rewrite the marker instead of the value.
    private static string Echo(string value) =>
        string.Concat(
            value[..Math.Min(value.Length, MaxEchoedIssuerChars)].ReplaceLineEndings(string.Empty).Replace('[', '('),
            value.Length > MaxEchoedIssuerChars ? TruncationMarker : string.Empty);
}
