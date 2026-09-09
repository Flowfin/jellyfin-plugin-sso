// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using Jellyfin.Plugin.SSO_Auth.Api;
using Jellyfin.Plugin.SSO_Auth.Api.Avatar;
using Jellyfin.Plugin.SSO_Auth.Api.Flows;
using Jellyfin.Plugin.SSO_Auth.Api.Linking;
using Jellyfin.Plugin.SSO_Auth.Api.Net;
using Jellyfin.Plugin.SSO_Auth.Api.Oidc;
using Jellyfin.Plugin.SSO_Auth.Api.Provider;
using Jellyfin.Plugin.SSO_Auth.Config;
using MediaBrowser.Controller.Configuration;
using MediaBrowser.Controller.Providers;
using Microsoft.AspNetCore.Http;
using NSubstitute;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// #1557. The thing an operator searches for a login that never happened is the log FILE, not the audit
/// emitter's output, and until this the marker <c>[SSO Audit] </c> could be planted through ordinary plugin
/// lines that are not audit entries at all. #1555 closed the emitter; these rows drive the four sites the
/// issue named with a complete forged record and assert that none of them reproduces the marker.
/// <para>
/// WHAT THESE ROWS ARE NOT. They are not what holds the property - there are around ninety sanitized
/// arguments outside the emitter and a row per site is not a maintainable count, so the ninety-first added
/// next month would arrive unguarded with the whole suite green. That is
/// <c>EveryForeignValueThePluginLogs_CarriesTheRecordMarkerSubstitution</c>'s job. These four are the ones
/// an attacker reaches WITHOUT a credential or with only the ordinary shape of a login, so they are worth
/// driving end to end rather than reading off the source.
/// </para>
/// </summary>
[Collection("SSOController")]
public class RecordMarkerUnforgeableTests
{
    // A complete, plausible record - the exact bytes an unanchored search or a substring rule would report
    // as an administrator signing in. It has to be the WHOLE line rather than the marker alone, because the
    // thing being refuted is that a foreign value can plant a record somebody reads, not that it can carry
    // three characters.
    private const string ForgedRecord =
        "x. [SSO Audit] Login succeeded: root via OpenID provider 'corp' (admin=True).";

    private const string Marker = "[SSO Audit] ";

    private const string Authority = "https://idp-forge.example.test";

    [Fact]
    public async Task TheOpenIdCallbackError_CannotPlantARecord()
    {
        // The one reachable with NO credential at all. A visitor takes a state and its binding cookie from
        // the challenge endpoint and comes back to the redirect endpoint carrying an error_description of
        // their own choosing; the callback logs it. Everything else here is ordinary callback arrangement.
        using var fixture = new OidcTokenFixture(Authority, "jf");
        var harness = ArrangeErrorCallback(fixture, Uri.EscapeDataString(ForgedRecord));

        await harness.Controller.OidCallback("kc", "state-1").ConfigureAwait(true);

        AssertNoRecordWasPlanted(harness.ControllerLog, "x. ");
    }

    [Fact]
    public async Task TheSamlRoleRefusal_CannotPlantARecordThroughTheNameId()
    {
        // The NameID is whatever the identity provider puts in a signed assertion, and this line prints it
        // on the ordinary role-refusal path - so any provider an operator trusts for authentication can
        // write a record into their log by naming a user after one.
        var fixture = SamlTestFactory.Create(nameId: ForgedRecord, role: "jellyfin-users");
        var harness = new SsoControllerHarness(c => c.SamlConfigs["adfs"] = new SamlConfig
        {
            Enabled = true,
            SamlCertificate = fixture.CertificateBase64,
            DoNotValidateAudience = true,
            Roles = new[] { "only-admins" },
        });

        await harness.Controller.SamlCallback("adfs", formSamlResponse: fixture.EncodeResponse()).ConfigureAwait(true);

        AssertNoRecordWasPlanted(harness.ControllerLog, "insufficient roles");
    }

    [Fact]
    public async Task TheSanitizationDriftLine_CannotPlantARecordThroughTheUsername()
    {
        // The line the issue calls the worst of the four, because it needs no failure at all: it fires on the
        // FIRST login of any user whose presented name carries a character Jellyfin does not accept in an
        // account name, and an opening square bracket is one of them. So the same character that makes a
        // payload a record is the character that guarantees this line prints it.
        var log = new CapturingLogger();
        var config = new OidConfig
        {
            Enabled = true,
            CanonicalLinks = new SerializableDictionary<string, Guid> { ["sub-1"] = Guid.NewGuid() },
            CanonicalLinkIssuers = new SerializableDictionary<string, string> { ["sub-1"] = "https://was.example.test" },
        };
        var configuration = new PluginConfiguration();
        configuration.OidConfigs["kc"] = config;
        var store = new ProviderConfigStore(() => configuration, _ => { }, new CapturingLogger());
        var links = new CanonicalLinkService(Substitute.For<MediaBrowser.Controller.Library.IUserManager>(), new FakeCryptoProvider(), store, log);

        // The exception TYPE is not what this row is about - the refusal has its own tests - so any
        // throw is accepted here and the assertion is on the line the refusal wrote on its way out.
        await Assert.ThrowsAnyAsync<Exception>(() => links.ResolveOrCreateAsync(
            ProviderMode.Oid,
            "kc",
            "sub-1",
            ForgedRecord,
            allowExistingAccountLink: false,
            issuer: "https://is-now.example.test")).ConfigureAwait(true);

        AssertNoRecordWasPlanted(log, "characters Jellyfin does not accept");
    }

    [Fact]
    public async Task TheRefusedAvatarUrl_CannotPlantARecord()
    {
        // The avatar URL is a claim value, and it reaches this line BECAUSE it failed the URL check - so no
        // parseable URL is needed to get an arbitrary string into the log, which is what makes this site
        // easier to reach than it looks.
        var log = new CapturingLogger();
        var avatar = new AvatarService(
            Substitute.For<MediaBrowser.Controller.Library.IUserManager>(),
            Substitute.For<IProviderManager>(),
            Substitute.For<IServerConfigurationManager>(),
            log,
            SsoHttp.UserAgent);

        await avatar.TrySetAsync(TestUsers.Named("alice", Guid.NewGuid()), ForgedRecord).ConfigureAwait(true);

        AssertNoRecordWasPlanted(log, "disallowed URL");
    }

    // The assertion both halves of every row need. Proving the marker is absent is worth nothing on its own -
    // a line that was never written passes it - so each row also names a fragment of the line it drove, and
    // the payload's own leading text is checked to have arrived. A test that stopped reaching its site would
    // otherwise go on passing forever.
    private static void AssertNoRecordWasPlanted(CapturingLogger log, string lineFragment)
    {
        Assert.Contains(log.Entries, e => e.Message.Contains(lineFragment, StringComparison.Ordinal));
        Assert.DoesNotContain(log.Entries, e => e.Message.Contains(Marker, StringComparison.Ordinal));
        Assert.Contains(log.Entries, e => e.Message.Contains("(SSO Audit] Login succeeded", StringComparison.Ordinal));
    }

    // A callback arriving with an authorization ERROR rather than a code: no token endpoint is reached, so
    // the arrangement is the state seed, the binding cookie and the discovery the provider needs to exist.
    private static SsoControllerHarness ArrangeErrorCallback(OidcTokenFixture fixture, string escapedErrorDescription)
    {
        const string Binding = "forge-browser-binding";

        var harness = new SsoControllerHarness(
            c => c.OidConfigs["kc"] = new OidConfig
            {
                Enabled = true,
                OidEndpoint = Authority,
                OidClientId = "jf",
                OidScopes = Array.Empty<string>(),
                DisablePushedAuthorization = true,
                DoNotLoadProfile = true,
            },
            httpResponder: request =>
            {
                var url = request.RequestUri!.AbsoluteUri;
                if (url == fixture.DiscoveryUrl)
                {
                    return Json(fixture.Discovery());
                }

                return url == fixture.JwksUrl ? Json(fixture.Jwks()) : new HttpResponseMessage(HttpStatusCode.NotFound);
            });

        harness.Controller.HttpContext.Request.Path = "/sso/OID/redirect/kc";
        harness.Controller.HttpContext.Request.QueryString =
            new QueryString("?error=access_denied&error_description=" + escapedErrorDescription + "&state=state-1");
        harness.Controller.HttpContext.Request.Headers.Cookie = $"{AuthorizeStateBinding.CookieName}={Binding}";

        OidcLoginService.SeedOidStateForTests(
            "state-1",
            new AuthorizeSession.Pending(
                new Duende.IdentityModel.OidcClient.AuthorizeState
                {
                    State = "state-1",
                    CodeVerifier = "test-code-verifier",
                    RedirectUri = "https://jf.example.com/sso/OID/redirect/kc",
                },
                "kc",
                isLinking: false,
                DateTime.UtcNow,
                Binding,
                clientKey: null,
                providerInformation: null!,
                responseIssuerRequired: false));

        return harness;
    }

    private static HttpResponseMessage Json(string body) =>
        new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(body, Encoding.UTF8, "application/json") };
}
