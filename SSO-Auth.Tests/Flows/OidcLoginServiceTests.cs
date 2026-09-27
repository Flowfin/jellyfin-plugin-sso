// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Linq;
using System.Net.Http;
using System.Security.Claims;
using System.Threading.Tasks;
using Duende.IdentityModel.OidcClient;
using Jellyfin.Plugin.SSO_Auth.Api;
using Jellyfin.Plugin.SSO_Auth.Api.Session;
using Jellyfin.Plugin.SSO_Auth.Api.Oidc;
using Jellyfin.Plugin.SSO_Auth.Api.Linking;
using Jellyfin.Plugin.SSO_Auth.Api.Avatar;
using Jellyfin.Plugin.SSO_Auth.Api.Net;
using Jellyfin.Plugin.SSO_Auth.Api.Events;
using Jellyfin.Plugin.SSO_Auth.Api.Flows;
using Jellyfin.Plugin.SSO_Auth.Api.Shared;
using Jellyfin.Plugin.SSO_Auth.Config;
using MediaBrowser.Controller.Configuration;
using MediaBrowser.Controller.Events;
using MediaBrowser.Controller.Library;
using MediaBrowser.Controller.Providers;
using MediaBrowser.Controller.Session;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using NSubstitute;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// Direct unit tests of <see cref="OidcLoginService"/>, the OpenID flow extracted off the controller
/// (#160, #318 step 12). The end-to-end challenge/callback/authenticate/link behaviour is still exercised
/// through the thin controller endpoints in <see cref="SSOControllerOidPostTests"/>,
/// <see cref="SSOControllerOidAuthTests"/> and <see cref="SSOControllerLinkTests"/> (each endpoint is now a
/// one-line delegation, so a passing controller test is a passing service test); these add coverage that
/// targets the service in isolation - the fail-closed guard branches that reject before any collaborator is
/// touched, and the process-wide-state test hooks that moved with the flow. Uses the non-parallel
/// <c>SSOController</c> collection because it sets the static <see cref="SSOPlugin.Instance"/>.
/// </summary>
[Collection("SSOController")]
public class OidcLoginServiceTests
{
    [Fact]
    public async Task ChallengeAsync_DisabledProvider_RejectsAsUnknownProvider()
    {
        var (service, context) = Build(c => c.OidConfigs["kc"] = new OidConfig { Enabled = false });
        context.Request.Path = "/sso/OID/start/kc";

        // A disabled provider fails closed before any discovery fetch or authorization request, with the
        // same uniform body the unknown-provider case gets - so the two cannot be told apart (#318).
        var result = await service.ChallengeAsync("kc", isLinking: false, context.Request, context.Response);

        var content = Assert.IsType<ContentResult>(result);
        Assert.Equal(400, content.StatusCode);
        Assert.Equal("No matching provider found", content.Content);
    }

    [Fact]
    public async Task ChallengeAsync_UnknownProvider_RejectsAsUnknownProvider()
    {
        var (service, context) = Build(_ => { });
        context.Request.Path = "/sso/OID/start/nope";

        var result = await service.ChallengeAsync("nope", isLinking: false, context.Request, context.Response);

        var content = Assert.IsType<ContentResult>(result);
        Assert.Equal(400, content.StatusCode);
        Assert.Equal("No matching provider found", content.Content);
    }

    [Fact]
    public async Task AuthenticateAsync_MissingData_ReturnsBadRequest()
    {
        var (service, _) = Build(c => c.OidConfigs["kc"] = new OidConfig { Enabled = true });

        var result = await service.AuthenticateAsync("kc", new AuthResponse(), bindingCookie: null, () => "127.0.0.1");

        Assert.IsType<BadRequestObjectResult>(result);
    }

    [Fact]
    public async Task AuthenticateAsync_UnknownState_RejectsAsInvalidState()
    {
        var (service, _) = Build(c => c.OidConfigs["kc"] = new OidConfig { Enabled = true });

        // No state was seeded, so the redeem misses - a client-caused 400, the same body an expired or
        // replayed state gets, so a replay stays indistinguishable from an expiry.
        var result = await service.AuthenticateAsync("kc", new AuthResponse { Data = "no-such-state" }, bindingCookie: null, () => "127.0.0.1");

        var content = Assert.IsType<ContentResult>(result);
        Assert.Equal(400, content.StatusCode);
        Assert.Equal("Invalid or expired state", content.Content);
    }

    [Fact]
    public void StateSummaries_ReflectSeededState_AndResetClearsThem()
    {
        var (service, _) = Build(c => c.OidConfigs["kc"] = new OidConfig { Enabled = true });

        var pending = new AuthorizeSession.Pending(new AuthorizeState { State = "seed-1" }, "kc", isLinking: false, DateTime.UtcNow, "binding", clientKey: null, providerInformation: null!, responseIssuerRequired: false);
        OidcLoginService.SeedOidStateForTests("seed-1", pending);

        Assert.Contains(service.StateSummaries(), s => s.Provider == "kc" && !s.Valid);

        // The reset hook moved with the statics; it must drop the seeded state so it cannot leak between tests.
        OidcLoginService.ResetOidStateForTests();
        Assert.Empty(service.StateSummaries());
    }

    [Fact]
    public void ResolveChallengeNewPath_ProviderDisabledInTheRaceWindow_SkipsThePersist_ButStillReturnsThisRequestsDerivedSpelling()
    {
        // #412 review follow-up: exercises the Mutate delegate's own re-check inside the shared
        // ChallengeNewPathResolver (unified across both flows in #670), driven with the OpenID map selector.
        // `config` mirrors the reference the real caller already captured under ReadConfiguration's lock
        // (FindOidConfig) before its own Enabled check passed; something then disables the provider in the
        // LIVE store before this write attempt runs - a race the outer check cannot see. The current
        // challenge must still get its own freshly-derived spelling for its redirect, but the disabled
        // provider's stored NewPath must be left untouched rather than written into.
        var (_, context) = Build(c => c.OidConfigs["kc"] = new OidConfig { Enabled = true, NewPath = false });
        var config = SSOPlugin.Instance.ReadConfiguration(c => c.OidConfigs["kc"]);
        SSOPlugin.Instance.MutateConfiguration(c => c.OidConfigs["kc"].Enabled = false);
        context.Request.Path = "/sso/OID/start/kc";

        var result = ChallengeNewPathResolver.ResolveChallengeNewPath("kc", config, isLinking: false, context.Request, Substitute.For<ILogger>(), c => c.OidConfigs);

        Assert.True(result); // this request's own redirect still uses the freshly-derived spelling
        Assert.False(SSOPlugin.Instance.ReadConfiguration(c => c.OidConfigs["kc"].NewPath)); // stored value untouched
    }

    [Fact]
    public void ClaimsForDenialLog_KeepsEveryType_AndOnlyTheRoleClaimAndSubKeepTheirValue()
    {
        // The role-denial warning used to print every claim with its value, so a refused login wrote the
        // person's display name, username and e-mail address into the server log (#1881). The shape below is
        // what Keycloak's profile scope delivers; the line must still show which claims arrived, with the
        // role claim's value (what the operator compares against the allow-list) and sub (the audit key).
        var claims = new[]
        {
            new Claim("sub", "6f2c-alice"),
            new Claim("realm_access", "{\"roles\":[\"viewer\"]}"),
            new Claim("name", "Alice Example"),
            new Claim("preferred_username", "alice"),
            new Claim("given_name", "Alice"),
            new Claim("family_name", "Example"),
            new Claim("email", "alice@example.org"),
            new Claim("Realm_Access", "{\"roles\":[\"admin\"]}"),
        };
        var config = new OidConfig { RoleClaim = "realm_access.roles", Roles = new[] { "jellyfin-access" } };

        var logged = OidcLoginService.ClaimsForDenialLog(claims, config).ToList();

        Assert.Equal(claims.Select(c => c.Type), logged.Select(c => c.Type));
        Assert.Equal("6f2c-alice", logged.Single(c => c.Type == "sub").Value);
        Assert.Equal("{\"roles\":[\"viewer\"]}", logged.Single(c => c.Type == "realm_access").Value);
        var line = string.Join(" ", logged.Select(c => c.Type + "=" + c.Value));
        foreach (var profile in new[] { "Alice", "alice@", "Example", "=alice" })
        {
            Assert.DoesNotContain(profile, line, StringComparison.Ordinal);
        }

        Assert.Equal(6, logged.Count(c => c.Value == "<redacted>"));
    }

    [Fact]
    public void ClaimsForDenialLog_WithNoRoleClaimConfigured_KeepsOnlySub()
    {
        // No role path means no allow-list comparison to serve, so a claim that merely happens to be named
        // like a role claim keeps nothing; a null path must not match a claim type either.
        var claims = new[] { new Claim("sub", "s-1"), new Claim("Sub", "s-2"), new Claim("roles", "viewer"), new Claim("email", "bob@example.org") };

        var logged = OidcLoginService.ClaimsForDenialLog(claims, new OidConfig()).ToList();

        Assert.Equal(new[] { "s-1", "<redacted>", "<redacted>", "<redacted>" }, logged.Select(c => c.Value));
    }

    [Fact]
    public void RoleClaimType_IsTheFirstSegmentOfTheConfiguredPath_WithEscapedDotsKept()
    {
        Assert.Equal("realm_access", OidcAuthorizeStateBuilder.RoleClaimType(new OidConfig { RoleClaim = "realm_access.roles" }));
        Assert.Equal("urn:zitadel:iam:org:project:roles", OidcAuthorizeStateBuilder.RoleClaimType(new OidConfig { RoleClaim = "urn:zitadel:iam:org:project:roles" }));
        Assert.Equal("a.b", OidcAuthorizeStateBuilder.RoleClaimType(new OidConfig { RoleClaim = @"a\.b.c" }));
        Assert.Null(OidcAuthorizeStateBuilder.RoleClaimType(new OidConfig()));
    }

    // Builds an OidcLoginService over the same collaborator graph the controller constructs, against a
    // freshly-bootstrapped SSOPlugin.Instance seeded via the configure callback and a DefaultHttpContext for
    // the request/response the challenge reads and writes. The harness resets the process-wide OpenID state,
    // so each test starts clean.
    private static (OidcLoginService Service, DefaultHttpContext Context) Build(Action<PluginConfiguration> configure)
    {
        var harness = new SsoControllerHarness(configure);
        var logger = Substitute.For<ILogger>();

        var canonicalLinks = new CanonicalLinkService(harness.UserManager, new FakeCryptoProvider(), SSOPlugin.Instance.ConfigStore, logger);
        var avatarService = new AvatarService(harness.UserManager, Substitute.For<IProviderManager>(), Substitute.For<IServerConfigurationManager>(), logger, SsoHttp.UserAgent);
        var sessionManager = Substitute.For<ISessionManager>();
        var sessionMinter = new SessionMinter(harness.UserManager, avatarService, sessionManager, logger);
        var ssoOnly = new SsoOnlyLoginService(harness.UserManager, SSOPlugin.Instance.ConfigStore, logger);
        var loginCompletion = new LoginCompletionService(canonicalLinks, sessionMinter, ssoOnly, SSOPlugin.Instance.ConfigStore, sessionManager, logger);
        var service = new OidcLoginService(loginCompletion, canonicalLinks, new SsoLoginEvents(Substitute.For<IEventManager>(), logger), Substitute.For<IHttpClientFactory>(), Substitute.For<ILoggerFactory>(), logger);

        var context = new DefaultHttpContext();
        context.Request.Scheme = "https";
        context.Request.Host = new HostString("jf.example.com");
        return (service, context);
    }
}
