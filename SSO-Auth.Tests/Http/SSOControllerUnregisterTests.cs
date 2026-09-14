// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Net;
using System.Reflection;
using System.Threading.Tasks;
using Jellyfin.Data;
using Jellyfin.Database.Implementations.Entities;
using Jellyfin.Database.Implementations.Enums;
using Jellyfin.Plugin.SSO_Auth;
using Jellyfin.Plugin.SSO_Auth.Api.Http;
using Jellyfin.Plugin.SSO_Auth.Api.Linking;
using Jellyfin.Plugin.SSO_Auth.Api.Session;
using Jellyfin.Plugin.SSO_Auth.Api;
using Jellyfin.Plugin.SSO_Auth.Config;
using MediaBrowser.Common.Api;
using MediaBrowser.Controller.Net;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using NSubstitute;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// In-process tests of the <c>Unregister</c> endpoint via <see cref="SsoControllerHarness"/>: a known
/// user's SSO is revoked (its canonical links are dropped and the auth provider is persisted), and the
/// revoke returns Ok. The unknown-user guard is covered in <see cref="SSOControllerChallengeTests"/>.
/// <para>
/// AN ADMINISTRATOR MAY NOT STRAND THEIR OWN SERVER THROUGH IT (#1741). The route removes every link the
/// account holds and ends its sessions in one call, and the self-service unlink refuses exactly that press
/// where no other administrator holds a way in (#1732); this route takes the same reading, over the same
/// two facts, before anything is removed. Every refusal arm below is paired with the case that must still
/// go through, because a revoke that refused the administrator it exists for would be as wrong as one
/// that stranded them.
/// </para>
/// </summary>
[Collection("SSOController")]
public class SSOControllerUnregisterTests
{
    private static readonly Guid UserId = Guid.Parse("44444444-4444-4444-4444-444444444444");
    private static readonly Guid OperatorId = Guid.Parse("46464646-4646-4646-4646-464646464646");
    private static readonly Guid RootId = Guid.Parse("47474747-4747-4747-4747-474747474747");
    private const string RefusalClause = "no other administrator on this server";

    [Fact]
    public async Task Unregister_KnownUser_PersistsProviderSwitch_ReturnsOk()
    {
        var harness = new SsoControllerHarness();
        var user = SeedUser(harness);

        var result = await harness.Controller.Unregister("alice", "Jellyfin");

        Assert.IsType<OkResult>(result);
        // The switch back to the local auth provider must be PERSISTED (a prior version only set it in memory).
        Assert.Equal("Jellyfin", user.AuthenticationProviderId);
        await harness.UserManager.Received(1).UpdateUserAsync(user);
    }

    [Fact]
    public async Task Unregister_KnownUser_RemovesTheUsersCanonicalLinks()
    {
        var harness = new SsoControllerHarness(c =>
            c.OidConfigs["keycloak"] = new OidConfig
            {
                CanonicalLinks = new SerializableDictionary<string, Guid> { ["sub-alice"] = UserId },
            });
        SeedUser(harness);

        await harness.Controller.Unregister("alice", "Jellyfin");

        // Revoking SSO must drop every canonical link pointing at the user, or the account could still sign in (#213).
        var links = SSOPlugin.Instance.ReadConfiguration(c => c.OidConfigs["keycloak"].CanonicalLinks);
        Assert.False(links.ContainsKey("sub-alice"));
    }

    [Fact]
    public async Task Unregister_KnownUser_RevokesTheTargetUsersActiveTokens()
    {
        var harness = new SsoControllerHarness();
        SeedUser(harness);

        await harness.Controller.Unregister("alice", "Jellyfin");

        // A hard revoke must also terminate the user's already-issued tokens, scoped to this one user; null
        // revokes all of their tokens (#440).
        await harness.SessionManager.Received(1).RevokeUserTokens(UserId, null);
    }

    [Fact]
    public async Task Unregister_DoesNotRevokeTokensForOtherUsers()
    {
        var harness = new SsoControllerHarness();
        SeedUser(harness);
        var otherUser = Guid.Parse("55555555-5555-5555-5555-555555555555");

        await harness.Controller.Unregister("alice", "Jellyfin");

        // The revoke is scoped strictly to the resolved target - no other user's tokens may be swept.
        await harness.SessionManager.DidNotReceive().RevokeUserTokens(otherUser, Arg.Any<string?>());
    }

    [Fact]
    public async Task Unregister_TokenRevokeNoOp_StillCompletesOk()
    {
        // With the mock's default (a completed no-op task) the revoke changes nothing; the unregister must
        // still persist the provider switch and return Ok.
        var harness = new SsoControllerHarness();
        var user = SeedUser(harness);

        var result = await harness.Controller.Unregister("alice", "Jellyfin");

        Assert.IsType<OkResult>(result);
        await harness.UserManager.Received(1).UpdateUserAsync(user);
        await harness.SessionManager.Received(1).RevokeUserTokens(UserId, null);
    }

    [Fact]
    public async Task Unregister_WhenTokenRevokeFails_LinksAlreadyRemovedAndProviderPersisted()
    {
        // The token revoke runs LAST, after the durable revoke is committed, so a failure there cannot leave
        // the unregister half-done: the links are already dropped and the provider switch persisted (#440).
        var harness = new SsoControllerHarness(c =>
            c.OidConfigs["keycloak"] = new OidConfig
            {
                CanonicalLinks = new SerializableDictionary<string, Guid> { ["sub-alice"] = UserId },
            });
        var user = SeedUser(harness);
        harness.SessionManager.RevokeUserTokens(Arg.Any<Guid>(), Arg.Any<string?>())
            .Returns(Task.FromException(new InvalidOperationException("session store unavailable")));

        await Assert.ThrowsAsync<InvalidOperationException>(() => harness.Controller.Unregister("alice", "Jellyfin"));

        var links = SSOPlugin.Instance.ReadConfiguration(c => c.OidConfigs["keycloak"].CanonicalLinks);
        Assert.False(links.ContainsKey("sub-alice"));
        Assert.Equal("Jellyfin", user.AuthenticationProviderId);
        await harness.UserManager.Received(1).UpdateUserAsync(user);
    }

    [Fact]
    public async Task Unregister_AuthorizedOverRateLimit_Returns429()
    {
        // #516: the admin SSO-revoke is throttled by the shared gate under its own "unregister" class. A burst
        // past the configured budget is refused with the same 429 the login path renders, before any work runs.
        var harness = new SsoControllerHarness(
            c =>
            {
                c.EnableRateLimit = true;
                c.RateLimitMaxAttempts = 1;
                c.RateLimitWindowSeconds = 60;
            },
            // A dedicated public address so the process-static limiter counter is this test's alone.
            clientIp: IPAddress.Parse("8.8.4.20"));
        var user = SeedUser(harness);

        // The first call passes the limiter, spends the single-attempt budget, and completes the revoke (Ok).
        Assert.IsType<OkResult>(await harness.Controller.Unregister("alice", "Jellyfin"));

        // The second is over budget and throttled before any work: a 429 from LoginOutcome.Throttled via the
        // single mapper (#474), carrying the machine-readable Retry-After.
        var throttled = Assert.IsType<ContentResult>(await harness.Controller.Unregister("alice", "Jellyfin"));
        Assert.Equal(429, throttled.StatusCode);
        Assert.Equal("Too many attempts. Please wait a moment and try again.", throttled.Content);

        var retryAfter = harness.Controller.Response.Headers.RetryAfter.ToString();
        Assert.True(
            int.TryParse(retryAfter, out var seconds) && seconds >= 1 && seconds <= 60,
            $"Retry-After must be whole seconds within the 60s window; was '{retryAfter}'.");

        // The throttled call did no work: only the first revoke touched the session manager (#440 untouched by the 429).
        await harness.SessionManager.Received(1).RevokeUserTokens(UserId, null);
    }

    [Fact]
    public async Task Unregister_AuthorizedUnderRateLimit_NotThrottled()
    {
        // With rate limiting enabled but the budget generous (the default 30/60s), a normal admin unregister is
        // unaffected: it revokes SSO and returns Ok, never a 429, and the #440 session revocation still fires.
        var harness = new SsoControllerHarness(
            c =>
            {
                c.EnableRateLimit = true;
                c.RateLimitMaxAttempts = 30;
                c.RateLimitWindowSeconds = 60;
            },
            clientIp: IPAddress.Parse("8.8.4.21"));
        SeedUser(harness);

        var result = await harness.Controller.Unregister("alice", "Jellyfin");

        Assert.IsType<OkResult>(result);
        await harness.SessionManager.Received(1).RevokeUserTokens(UserId, null);
    }

    [Fact]
    public void Unregister_IsGuardedByTheElevationPolicy_SoUnauthorizedNeverReachesTheLimiter()
    {
        // The in-process harness calls the action directly, bypassing MVC's authorization filters, so the
        // "unauthorized never 429" property is pinned structurally instead: the [Authorize(RequiresElevation)]
        // filter rejects a non-elevated caller (401/403) BEFORE the action body - and thus before the
        // RateLimitCheck the body fronts itself with - runs. So no 429 can ever precede the auth rejection: a
        // hammering unauthorized caller is refused, never throttled, and never consumes the "unregister" budget.
        var authorize = typeof(SSOController).GetMethod(nameof(SSOController.Unregister))!
            .GetCustomAttribute<AuthorizeAttribute>();

        Assert.NotNull(authorize);
        Assert.Equal(Policies.RequiresElevation, authorize!.Policy);
    }

    [Fact]
    public async Task Unregister_AnAdministratorRevokingTheirOwnAccount_WithNobodyElseAbleToSignIn_IsRefused_AndNothingIsTouched()
    {
        // THE CASE #1741 IS ABOUT. The caller is the account being revoked, they are the only enabled
        // administrator on the server, and the revoke would take their last SSO link, repoint them onto a
        // password this plugin may have minted and never recorded, and end their session in the same call.
        // Refused before anything is removed: the link stays, the provider is not written, no token goes,
        // and the operator's log carries the refusal.
        var harness = new SsoControllerHarness(c => c.OidConfigs["keycloak"] = LinkedProvider(("sub-alice", UserId)));
        var alice = SeedUser(harness, administrator: true);
        ActingAs(harness, alice);
        harness.UserManager.GetUsers().Returns(new[] { alice });

        var result = await harness.Controller.Unregister("alice", "Jellyfin");

        AssertRefused(result);
        Assert.Equal(UserId, SSOPlugin.Instance.ReadConfiguration(c => c.OidConfigs["keycloak"].CanonicalLinks)["sub-alice"]);
        Assert.NotEqual("Jellyfin", alice.AuthenticationProviderId);
        await harness.UserManager.DidNotReceive().UpdateUserAsync(Arg.Any<User>());
        await harness.SessionManager.DidNotReceive().RevokeUserTokens(Arg.Any<Guid>(), Arg.Any<string?>());
        Assert.Single(harness.ControllerLog.Entries, e => e.Message.Contains("[SSO Audit] Refused an administrator's revoke of their own SSO links", StringComparison.Ordinal));
    }

    [Fact]
    public async Task Unregister_AnAdministratorRevokingTheirOwnAccount_WithAnotherAdministratorHoldingALink_StillRevokes()
    {
        // THE BOUND, and the reason the rule is a pair of facts rather than a refusal of every self-revoke.
        // A second administrator with a link on an enabled provider can undo whatever this press does, so
        // the cleanup goes through exactly as it did before #1741: links dropped, provider persisted,
        // tokens revoked. Without this arm the guard could refuse every administrator's self-revoke and
        // still pass the one above.
        var harness = new SsoControllerHarness(c => c.OidConfigs["keycloak"] = LinkedProvider(("sub-alice", UserId), ("sub-root", RootId)));
        var alice = SeedUser(harness, administrator: true);
        ActingAs(harness, alice);
        harness.UserManager.GetUsers().Returns(new[] { alice, Administrator("root", RootId) });

        var result = await harness.Controller.Unregister("alice", "Jellyfin");

        Assert.IsType<OkResult>(result);
        var links = SSOPlugin.Instance.ReadConfiguration(c => c.OidConfigs["keycloak"].CanonicalLinks);
        Assert.False(links.ContainsKey("sub-alice"));
        Assert.Equal(RootId, links["sub-root"]);
        Assert.Equal("Jellyfin", alice.AuthenticationProviderId);
        await harness.SessionManager.Received(1).RevokeUserTokens(UserId, null);
    }

    [Fact]
    public async Task Unregister_AnAdministratorRevokingTheirOwnAccount_WithAnotherAdministratorHoldingOnlyAPassword_IsRefused()
    {
        // THE COST OF THE READING, PINNED SO IT IS PAID KNOWINGLY. The other administrator has a stored
        // password and no link, and a stored password is never counted - this plugin mints one onto every
        // account it provisions and records nowhere which, so the hash is a credential somebody holds or a
        // seal nobody can open. That is the purge's reading and #1732's, and this route takes it too; a
        // real break-glass password reads as no way in here, and telling the two apart is #1733.
        var harness = new SsoControllerHarness(c => c.OidConfigs["keycloak"] = LinkedProvider(("sub-alice", UserId)));
        var alice = SeedUser(harness, administrator: true);
        ActingAs(harness, alice);
        var root = Administrator("root", RootId);
        root.AuthenticationProviderId = SsoAuthenticationProviders.DefaultPasswordProviderId;
        root.Password = "a-real-hash";
        harness.UserManager.GetUsers().Returns(new[] { alice, root });

        AssertRefused(await harness.Controller.Unregister("alice", "Jellyfin"));
        await harness.SessionManager.DidNotReceive().RevokeUserTokens(Arg.Any<Guid>(), Arg.Any<string?>());
    }

    [Fact]
    public async Task Unregister_AnAdministratorRevokingSomebodyElse_WithNobodyElseAbleToSignIn_StillRevokes_AndPaysNoSurvey()
    {
        // THE ACT THE ROUTE EXISTS FOR. An administrator cutting one account off is not stranding
        // themselves however alone they are on the server, so the survey is not even asked: the roster is
        // never read, and the revoke goes through with no other administrator in sight.
        var harness = new SsoControllerHarness(c => c.OidConfigs["keycloak"] = LinkedProvider(("sub-alice", UserId)));
        var alice = SeedUser(harness, administrator: true);
        ActingAs(harness, Administrator("operator", OperatorId));
        harness.UserManager.GetUsers().Returns(new[] { alice });

        var result = await harness.Controller.Unregister("alice", "Jellyfin");

        Assert.IsType<OkResult>(result);
        Assert.False(SSOPlugin.Instance.ReadConfiguration(c => c.OidConfigs["keycloak"].CanonicalLinks).ContainsKey("sub-alice"));
        harness.UserManager.DidNotReceive().GetUsers();
        await harness.SessionManager.Received(1).RevokeUserTokens(UserId, null);
    }

    [Fact]
    public async Task Unregister_AnAdministratorRevokingTheirOwnAccount_ThatAcceptsAPassword_StillRevokes_AndPaysNoSurvey()
    {
        // The password half is the same bound the self-service route has. An administrator whose account
        // routes to the built-in password provider keeps that door through the repoint, so revoking their
        // own links strands nobody, however alone they are on the server - and the ordinary single-owner
        // server is exactly this shape. The survey is not even asked.
        var harness = new SsoControllerHarness(c => c.OidConfigs["keycloak"] = LinkedProvider(("sub-alice", UserId)));
        var alice = SeedUser(harness, administrator: true);
        alice.AuthenticationProviderId = SsoAuthenticationProviders.DefaultPasswordProviderId;
        ActingAs(harness, alice);
        harness.UserManager.GetUsers().Returns(new[] { alice });

        var result = await harness.Controller.Unregister("alice", "Jellyfin");

        Assert.IsType<OkResult>(result);
        Assert.False(SSOPlugin.Instance.ReadConfiguration(c => c.OidConfigs["keycloak"].CanonicalLinks).ContainsKey("sub-alice"));
        harness.UserManager.DidNotReceive().GetUsers();
        await harness.SessionManager.Received(1).RevokeUserTokens(UserId, null);
    }

    [Fact]
    public async Task Unregister_AnAdministratorRevokingTheirOwnAccount_WhoseOnlyLinkIsOnADisabledProvider_StillRevokes_AndPaysNoSurvey()
    {
        // THE REVOKE MUST TAKE A WAY IN. A link on a switched-off provider cannot sign anybody in as it
        // stands, so the guard reads it as the self-service guard does and lets the revoke through; refusing
        // here would take the disable-then-clean-up workflow (#380) from the one administrator on the
        // server. What that reading costs - the provider switched back on would have been a way in - is
        // written at both guards rather than claimed away here. The survey is not even asked.
        var harness = new SsoControllerHarness(c => c.OidConfigs["retired"] = LinkedProvider(enabled: false, ("sub-alice", UserId)));
        var alice = SeedUser(harness, administrator: true);
        ActingAs(harness, alice);
        harness.UserManager.GetUsers().Returns(new[] { alice });

        var result = await harness.Controller.Unregister("alice", "Jellyfin");

        Assert.IsType<OkResult>(result);
        Assert.False(SSOPlugin.Instance.ReadConfiguration(c => c.OidConfigs["retired"].CanonicalLinks).ContainsKey("sub-alice"));
        Assert.Equal("Jellyfin", alice.AuthenticationProviderId);
        harness.UserManager.DidNotReceive().GetUsers();
    }

    [Fact]
    public async Task Unregister_AnAdministratorRevokingTheirOwnAccount_ThatHoldsNoLink_StillRepoints()
    {
        // The way back for an administrator already stranded: left on this plugin's provider id with no
        // link, they can sign in with nothing, and this route is the one call that puts them back on the
        // password provider. A guard that refused it would be standing between them and the repair.
        var harness = new SsoControllerHarness();
        var alice = SeedUser(harness, administrator: true);
        alice.AuthenticationProviderId = SsoManagedProviderId.Value;
        ActingAs(harness, alice);
        harness.UserManager.GetUsers().Returns(new[] { alice });

        var result = await harness.Controller.Unregister("alice", "Jellyfin");

        Assert.IsType<OkResult>(result);
        Assert.Equal("Jellyfin", alice.AuthenticationProviderId);
        await harness.UserManager.Received(1).UpdateUserAsync(alice);
        harness.UserManager.DidNotReceive().GetUsers();
    }

    [Fact]
    public async Task Unregister_AnApiKeyCaller_IsNotTheHolder_AndRevokes()
    {
        // The host admits a dashboard API key through the elevation policy with no user behind it, and an
        // API key has no account to strand. Read as an unresolved caller it was the holder of every account
        // it revoked, which refused the documented automation path on any server whose administrators sign
        // in by password; it is the one caller class the fail-closed default must not swallow.
        var harness = new SsoControllerHarness(c => c.OidConfigs["keycloak"] = LinkedProvider(("sub-alice", UserId)));
        var alice = SeedUser(harness, administrator: true);
        harness.AuthContext.GetAuthorizationInfo(Arg.Any<HttpRequest>()).Returns(Task.FromResult(new AuthorizationInfo { IsApiKey = true, User = null }));
        harness.UserManager.GetUsers().Returns(new[] { alice });

        var result = await harness.Controller.Unregister("alice", "Jellyfin");

        Assert.IsType<OkResult>(result);
        Assert.False(SSOPlugin.Instance.ReadConfiguration(c => c.OidConfigs["keycloak"].CanonicalLinks).ContainsKey("sub-alice"));
        harness.UserManager.DidNotReceive().GetUsers();
        await harness.SessionManager.Received(1).RevokeUserTokens(UserId, null);
    }

    [Fact]
    public async Task Unregister_AnUnresolvedCaller_IsTreatedAsTheAccountItself()
    {
        // Fail closed on a caller the host resolves to neither a user nor an API key, the way the
        // self-service route does: an ambiguous caller narrows an exemption, so it is read as the one
        // acting on itself rather than as the one the exemption was written for. With nobody else able to
        // sign in, that is a refusal rather than a lockout.
        var harness = new SsoControllerHarness(c => c.OidConfigs["keycloak"] = LinkedProvider(("sub-alice", UserId)));
        var alice = SeedUser(harness, administrator: true);
        harness.AuthContext.GetAuthorizationInfo(Arg.Any<HttpRequest>()).Returns(Task.FromResult(new AuthorizationInfo { User = null }));
        harness.UserManager.GetUsers().Returns(new[] { alice });

        AssertRefused(await harness.Controller.Unregister("alice", "Jellyfin"));
        await harness.SessionManager.DidNotReceive().RevokeUserTokens(Arg.Any<Guid>(), Arg.Any<string?>());
    }

    [Fact]
    public async Task Unregister_AServerThatCannotBeSurveyed_Refuses_RatherThanRevoking()
    {
        // The one build this plugin cannot enumerate must not be the one build where the guard is off. The
        // roster accessor answers nothing, which the enumeration turns into a throw rather than an empty
        // server; the survey then answers "nobody is left", and the refusal says so in the log instead of
        // a 500 escaping or a revoke going through.
        var harness = new SsoControllerHarness(c => c.OidConfigs["keycloak"] = LinkedProvider(("sub-alice", UserId)));
        var alice = SeedUser(harness, administrator: true);
        ActingAs(harness, alice);
        harness.UserManager.GetUsers().Returns((System.Collections.Generic.IReadOnlyList<User>?)null);

        AssertRefused(await harness.Controller.Unregister("alice", "Jellyfin"));
        await harness.SessionManager.DidNotReceive().RevokeUserTokens(Arg.Any<Guid>(), Arg.Any<string?>());
        Assert.Single(harness.ControllerLog.Entries, e => e.Message.Contains("Could not survey the other administrator accounts", StringComparison.Ordinal));
    }

    private static void AssertRefused(ActionResult result)
    {
        var refused = Assert.IsType<ObjectResult>(result);
        Assert.Equal(StatusCodes.Status403Forbidden, refused.StatusCode);
        // The page keys its own sentence off this clause, so the two are pinned together here.
        Assert.Contains(RefusalClause, Assert.IsType<string>(refused.Value), StringComparison.Ordinal);
    }

    private static OidConfig LinkedProvider(params (string Subject, Guid User)[] links) => LinkedProvider(enabled: true, links);

    private static OidConfig LinkedProvider(bool enabled, params (string Subject, Guid User)[] links)
    {
        var config = new OidConfig { Enabled = enabled, CanonicalLinks = new SerializableDictionary<string, Guid>() };
        foreach (var (subject, user) in links)
        {
            config.CanonicalLinks[subject] = user;
        }

        return config;
    }

    private static User Administrator(string name, Guid id)
    {
        var user = TestUsers.Named(name, id);
        user.SetPermission(PermissionKind.IsAdministrator, true);
        return user;
    }

    // Resolves the CALLER behind the request. Since #1741 the route asks who the caller is before it
    // removes anything, and a caller it cannot resolve is treated as the account itself.
    private static void ActingAs(SsoControllerHarness harness, User caller)
    {
        harness.AuthContext.GetAuthorizationInfo(Arg.Any<HttpRequest>()).Returns(Task.FromResult(new AuthorizationInfo { User = caller }));
    }

    // Registers a user with the harness's mocked IUserManager so GetUserByName resolves it, and resolves the
    // caller as a DIFFERENT administrator - the act this route exists for - so the tests of the revoke
    // itself are not judged by the self-revoke guard.
    private static User SeedUser(SsoControllerHarness harness, bool administrator = false)
    {
        var user = TestUsers.Named("alice", UserId);
        user.SetPermission(PermissionKind.IsAdministrator, administrator);
        harness.UserManager.GetUserByName("alice").Returns(user);
        ActingAs(harness, Administrator("operator", OperatorId));
        return user;
    }
}
