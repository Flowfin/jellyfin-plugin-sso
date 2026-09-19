// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;

namespace Jellyfin.Plugin.SSO_Auth.Api.Oidc;

/// <summary>
/// What a refused authorization request points the administrator at (#1763). The closing sentence of the
/// refused-challenge log line asserts a cause, and #1610 gave it one cause for every code: the redirect
/// URI. At the pushed-authorization endpoint the provider separates two of them, so a line that names the
/// URI for all of them sends a reader to re-check a setting the provider never objected to.
/// </summary>
internal enum OidcChallengeCause
{
    /// <summary>
    /// The answer names neither cause this line knows how to act on. The closing sentence then asserts
    /// nothing. This is the default, and it is where an HTTP status, a transport failure and any
    /// unmeasured code all land, rather than being folded into the nearest neighbour.
    /// </summary>
    Unnamed = 0,

    /// <summary>
    /// The answer is the one the redirect-URI sentence was measured against. On Pocket ID 2.14 a callback
    /// the client does not hold comes back 400 <c>invalid_request</c>, and with pushed authorization on
    /// that exchange is server to server, so the URI appears nowhere the administrator can reach it. This
    /// is the row the sentence from #1610 was written for, and it is the only row that reaches it.
    /// </summary>
    RedirectUri = 1,

    /// <summary>
    /// The provider refused the client itself. Measured on the same provider: a missing or wrong secret on
    /// a confidential client comes back 401 <c>invalid_client</c>, which reaches this side as the
    /// <c>Unauthorized</c> reason phrase.
    /// </summary>
    ClientAuthentication = 2,
}

/// <summary>
/// Reads the one field the identity library hands on from a failed authorization-request preparation and
/// says which cause it carries, so the log line can follow it instead of asserting one cause for every
/// refusal (#1763).
/// </summary>
/// <remarks>
/// <para>
/// THE CLASSIFICATION READS THE CODE AND NOTHING ELSE, AND THAT IS A PROPERTY OF THE LIBRARY RATHER THAN A
/// CHOICE. <c>AuthorizeState.ErrorDescription</c> is not the provider's words: both pinned versions
/// overwrite it with one constant before the plugin sees it, so nothing can be read out of it.
/// </para>
/// <code>
/// ilspycmd -t Duende.IdentityModel.OidcClient.AuthorizeClient Duende.IdentityModel.OidcClient.dll
///     _logger.LogError("Failed to push authorization parameters");
///     state.Error = ((ProtocolResponse)val).Error;
///     state.ErrorDescription = "Failed to push authorization parameters";
/// </code>
/// <para>
/// WHAT THE CODE ITSELF IS DEPENDS ON THE STATUS, WHICH THIS SIDE NEVER RECEIVES.
/// <c>ProtocolResponse.Error</c> returns the parsed <c>error</c> member only where the response was a 400;
/// every other unsuccessful status yields the HTTP reason phrase, and a transport failure yields the
/// exception message. So <c>invalid_request</c> is a provider's code, <c>Unauthorized</c> is a reason
/// phrase for a 401, and the two are told apart here by name because no status reaches this call.
/// </para>
/// <code>
/// ilspycmd -t Duende.IdentityModel.Client.ProtocolResponse Duende.IdentityModel.dll
///     if (ErrorType == ResponseErrorType.Http) { return HttpErrorReason; }
///     if (ErrorType == ResponseErrorType.Exception) { return Exception.Message; }
///     return TryGet("error");
///     ...
///     if (!httpResponse.IsSuccessStatusCode &amp;&amp; httpResponse.StatusCode != HttpStatusCode.BadRequest)
/// </code>
/// <para>
/// THE BOUND THAT FOLLOWS, STATED RATHER THAN ENGINEERED AROUND. A reason phrase is the server's to
/// choose, so a 401 answered with any phrase but <c>Unauthorized</c> is not recognised as a client
/// refusal and falls to <see cref="OidcChallengeCause.Unnamed"/>. That direction loses a helpful sentence
/// and asserts nothing false, which is the direction this rule is for. Every set below is closed and
/// named for the same reason.
/// </para>
/// </remarks>
internal static class OidcChallengeRefusal
{
    // The client was refused rather than the request. `invalid_client` is RFC 6749 section 5.2 and reaches
    // this side only where the provider answered it with a 400; `Unauthorized` is the reason phrase a 401
    // arrives as, and is the spelling the run behind #1763 logged. `unauthorized_client` is deliberately
    // NOT here: it is about a grant this client may not use, not about proving which client it is, and
    // the sentence this set reaches sends a reader to the client ID and the secret.
    private static readonly string[] ClientAuthenticationCodes = ["invalid_client", "Unauthorized"];

    // The one code the redirect-URI sentence was measured against, on a live Pocket ID 2.14 reproducing
    // #1608: a callback the client does not hold comes back 400 `invalid_request`. It is a set of one on
    // purpose. A neighbouring code that is request-shaped in the abstract - `invalid_request_object`,
    // `invalid_request_uri`, or the registration-time `invalid_redirect_uri` - is not a code about the
    // callback, so sending a reader to re-check the callback for it is the move #1763 exists to stop,
    // one code further out. It arrives only on a 400, which is the one status whose body this side reads
    // a code out of at all.
    private static readonly string[] RedirectUriCodes = ["invalid_request"];

    /// <summary>
    /// Says which cause the refusal carries.
    /// </summary>
    /// <param name="error">
    /// <c>AuthorizeState.Error</c>: the provider's error code where the answer was a 400, the HTTP reason
    /// phrase for any other unsuccessful status, or the exception message where the request never arrived.
    /// </param>
    /// <returns>The cause the closing sentence of the refusal line may assert.</returns>
    internal static OidcChallengeCause Classify(string? error)
    {
        var code = error?.Trim();

        if (Matches(code, ClientAuthenticationCodes))
        {
            return OidcChallengeCause.ClientAuthentication;
        }

        if (Matches(code, RedirectUriCodes))
        {
            return OidcChallengeCause.RedirectUri;
        }

        return OidcChallengeCause.Unnamed;
    }

    private static bool Matches(string? code, string[] set)
    {
        if (string.IsNullOrEmpty(code))
        {
            return false;
        }

        foreach (var candidate in set)
        {
            if (string.Equals(code, candidate, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }
}
