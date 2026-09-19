// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using Jellyfin.Plugin.SSO_Auth.Api.Oidc;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// Tests for <see cref="OidcChallengeRefusal.Classify"/> - which cause the closing sentence of the
/// refused-challenge log line may assert (#1763). The line carried one closing sentence for every
/// refusal, naming the redirect URI, and a reporter who had already confirmed that URI against the
/// provider was told to check it again for a refusal that was about the client secret (#1762).
/// <para>
/// Every row below is a value the identity library can actually produce at this call. That is not a
/// detail: the library hands on ONE field, and what is in it depends on the status. A 400 yields the
/// provider's own <c>error</c> member; any other unsuccessful status yields the HTTP reason phrase; a
/// request that never arrived yields the exception message. Rows invented outside those three shapes
/// would certify behaviour no caller can reach.
/// </para>
/// </summary>
public class OidcChallengeRefusalTests
{
    [Fact]
    public void Classify_TheMeasuredCallbackRefusal_IsAboutTheRedirectUri()
    {
        // Reached only on a 400, which is the one status the library reads a code out of, and measured on
        // a live Pocket ID 2.14: a callback the client does not hold comes back 400 `invalid_request`.
        Assert.Equal(OidcChallengeCause.RedirectUri, OidcChallengeRefusal.Classify("invalid_request"));
    }

    [Theory]
    // Request-shaped in the abstract and not about the callback. `invalid_request_object` and
    // `invalid_request_uri` are about a request object; `invalid_redirect_uri` is a registration-time
    // code this endpoint does not return at all. Sending a reader to re-check the callback for any of
    // them is the move this change exists to stop, one code further out.
    [InlineData("invalid_request_object")]
    [InlineData("invalid_request_uri")]
    [InlineData("invalid_redirect_uri")]
    public void Classify_ANeighbouringRequestCode_IsNotAboutTheRedirectUri(string code)
    {
        Assert.Equal(OidcChallengeCause.Unnamed, OidcChallengeRefusal.Classify(code));
    }

    [Theory]
    // `Unauthorized` is the reason phrase a 401 arrives as - the spelling the run behind #1763 logged,
    // because the library never exposes the `invalid_client` the provider put in the body of that 401.
    // `invalid_client` itself is reachable from a provider that answers it with a 400.
    [InlineData("Unauthorized")]
    [InlineData("invalid_client")]
    public void Classify_AClientRefusal_IsAboutClientAuthentication(string code)
    {
        Assert.Equal(OidcChallengeCause.ClientAuthentication, OidcChallengeRefusal.Classify(code));
    }

    [Theory]
    // Reason phrases for the other unsuccessful statuses, and the message of a transport failure. None
    // of them names a cause this line can act on, and the sentence they reach says so rather than
    // choosing the nearest neighbour.
    [InlineData("Forbidden")]
    [InlineData("Not Found")]
    [InlineData("Internal Server Error")]
    [InlineData("Bad Gateway")]
    [InlineData("No connection could be made because the target machine actively refused it.")]
    [InlineData("server_error")]
    // About a grant this client may not use rather than about proving which client it is, so it must not
    // reach the sentence that sends a reader to the client ID and the secret.
    [InlineData("unauthorized_client")]
    public void Classify_AnAnswerNamingNeitherCause_AssertsNeither(string code)
    {
        Assert.Equal(OidcChallengeCause.Unnamed, OidcChallengeRefusal.Classify(code));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void Classify_AnAnswerWithNothingInIt_AssertsNeitherCause(string? code)
    {
        Assert.Equal(OidcChallengeCause.Unnamed, OidcChallengeRefusal.Classify(code));
    }

    [Theory]
    // A reason phrase is the server's to spell, and a code is the provider's, so a row must not turn on
    // a casing or on surrounding space that neither of them promises.
    [InlineData("INVALID_REQUEST")]
    [InlineData(" invalid_request ")]
    public void Classify_ReadsARequestShapedCodeWithoutDependingOnItsSpelling(string code)
    {
        Assert.Equal(OidcChallengeCause.RedirectUri, OidcChallengeRefusal.Classify(code));
    }

    [Theory]
    [InlineData("unauthorized")]
    [InlineData(" invalid_client ")]
    public void Classify_ReadsAClientRefusalWithoutDependingOnItsSpelling(string code)
    {
        Assert.Equal(OidcChallengeCause.ClientAuthentication, OidcChallengeRefusal.Classify(code));
    }

    [Fact]
    public void Classify_A401AnsweredWithAnotherReasonPhrase_FallsToNeither()
    {
        // The bound the class states, pinned so it is a known limit rather than a surprise. A reason
        // phrase is chosen by whatever answered, and this side never sees the status, so a 401 spelled
        // any other way loses the client sentence. It loses a helpful sentence and asserts nothing
        // false, which is the direction the rule is for.
        Assert.Equal(OidcChallengeCause.Unnamed, OidcChallengeRefusal.Classify("Client Authentication Required"));
    }
}
