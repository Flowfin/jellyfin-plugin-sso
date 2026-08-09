// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Reflection;
using System.Threading.Tasks;
using Duende.IdentityModel.OidcClient;
using Jellyfin.Data;
using Jellyfin.Database.Implementations.Entities;
using Jellyfin.Database.Implementations.Enums;
using Jellyfin.Plugin.SSO_Auth.Api.Flows;
using Jellyfin.Plugin.SSO_Auth.Api.Oidc;
using Jellyfin.Plugin.SSO_Auth.Api.Session;
using Jellyfin.Plugin.SSO_Auth.Config;
using MediaBrowser.Controller.Net;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using NSubstitute;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// The browser-bound authorize value reaches one decision wherever it arrives (#1161). The value is the
/// unguessable per-flow token this server minted and handed to a browser: the OpenID authorize
/// <c>state</c>, and the one-time login-outcome token the SAML assertion-consumer leg renders. It arrives
/// on three media - a query string, a JSON body property, and the cookie half of the pair - and the
/// decision it must reach is <see cref="AuthorizeStateBinding"/>: the caller presents the binding cookie
/// the challenge set, or the value is refused.
/// <para>
/// The route set is DERIVED from <see cref="EntryPointInventory"/> rather than listed, because the route
/// somebody forgot to add to a list is the route that skipped the check. A new entry point taking a
/// <c>state</c> parameter or an <see cref="AuthResponse"/> body is in the derived class and fails
/// <see cref="EveryAuthorizeValueEntryPoint_IsClassifiedAndProven"/> until it is classified here.
/// </para>
/// <para>
/// The check is NOT uniform across the class, and pretending otherwise would weaken the rule into one
/// that passes on a build with a binding check removed. Four legs present a binding cookie; the SAML half
/// of the link route presents none, because the value it carries in <c>AuthResponse.Data</c> is a signed
/// assertion rather than a browser-minted token, so there is nothing bound to a cookie and its one-time-use
/// control is the replay cache instead. That asymmetry is declared per leg below, with its reason, so a
/// later reader does not re-derive the question and a fifth leg cannot inherit the exemption silently.
/// </para>
/// </summary>
[Collection("SSOController")]
public class AuthorizeValueBindingConformanceTests
{
    private static readonly Guid Target = Guid.Parse("55555555-5555-5555-5555-555555555555");
    private const string Binding = "conformance-browser-binding";
    private const string OtherBinding = "a-different-browsers-binding-id";
    private const string AuthnRequestId = "_authnreq-1161";

    /// <summary>
    /// One leg of the browser-bound authorize value: a route, the protocol it is serving on that route,
    /// the binding cookie it presents (null where it presents none), the name of the test proving it, and
    /// why it is shaped that way.
    /// </summary>
    private sealed record AuthorizeValueLeg(string Template, string Protocol, string? Cookie, string Proof, string Why);

    // Every leg the class reaches. A template appears once per protocol it serves, because {mode}/Link
    // serves two and they do not carry the same kind of value.
    private static readonly AuthorizeValueLeg[] Legs =
    {
        new(
            "OID/r/{provider}",
            "oid",
            AuthorizeStateBinding.CookieName,
            nameof(OidCallback_WithoutTheBindingCookie_RefusesTheState),
            "The IdP redirect leg: the state arrives in the query string and is peeked, not consumed, so the browser that started the flow can still complete it after a transport failure."),
        new(
            "OID/redirect/{provider}",
            "oid",
            AuthorizeStateBinding.CookieName,
            nameof(OidCallback_WithoutTheBindingCookie_RefusesTheState),
            "The second template on the same action, kept for the descriptive URL; one action, so one proof covers both."),
        new(
            "OID/Auth/{provider}",
            "oid",
            AuthorizeStateBinding.CookieName,
            nameof(OidAuth_WithoutTheBindingCookie_RefusesWithoutConsumingTheState),
            "The session-minting leg: the state arrives in AuthResponse.Data and is redeemed once, so the binding must be checked before the atomic claim."),
        new(
            "SAML/Auth/{provider}",
            "saml",
            AuthorizeStateBinding.SamlCookieName,
            nameof(SamlAuth_WithoutTheBindingCookie_RefusesTheOutcomeToken),
            "The SAML session-minting leg: the one-time outcome token arrives in AuthResponse.Data and its solicited correlation is bound to the SAML cookie, which is a distinct name so the two flows cannot cross-satisfy each other."),
        new(
            "{mode}/Link/{provider}/{jellyfinUserId}",
            "oid",
            AuthorizeStateBinding.CookieName,
            nameof(AddCanonicalLink_Oid_WithoutTheBindingCookie_RefusesWithoutConsumingTheState),
            "The OpenID manual-link leg redeems the same authorize state the login leg does, so it carries the same binding."),
        new(
            "{mode}/Link/{provider}/{jellyfinUserId}",
            "saml",
            null,
            nameof(AddCanonicalLink_Saml_CarriesASignedAssertionRatherThanABoundToken),
            "The SAML manual-link leg is the one member of the class that presents no binding cookie: AuthResponse.Data carries a signed SAML response validated in full on the spot, not a token this server minted for a browser, so no binding id was ever recorded to compare against. Its one-time-use control is the assertion replay cache."),
    };

    // Routes deliberately NOT in the class. Each takes a browser-supplied value that looks adjacent and is
    // not this one; sweeping any of them in would force a binding check onto a route that has nothing to
    // bind, and relaxing the rule until they passed would stop it asserting anything.
    private static readonly (string Template, string Why)[] NotThisClass =
    {
        ("OID/States", "An elevation-gated admin summary of in-flight flows. It accepts no inbound value at all."),
        ("SAML/p/{provider}", "The relayState parameter here is a two-valued mode flag this plugin emitted itself ('linking' or absent), not an unguessable per-flow token: there is nothing to bind and nothing to consume."),
        ("SAML/post/{provider}", "The second template on the same assertion-consumer action, for the same reason. It is also a cross-site POST from the IdP, on which a SameSite=Lax cookie is not sent."),
        ("SAML/Logout/{provider}", "The RelayState form field is echoed back on the signed LogoutResponse within the binding's byte cap. The trust anchor on that route is the XML signature plus the LogoutRequest's own one-time-use, not a browser binding."),
    };

    [Fact]
    public void EveryAuthorizeValueEntryPoint_IsClassifiedAndProven()
    {
        // The rule proper. The derived set and the declared set must agree in BOTH directions: an entry
        // point taking a state parameter or an AuthResponse body with no declared leg is a route that
        // reached the flow tier without anyone deciding whether it is browser-bound, and a declared leg
        // whose route no longer exists is a stale exemption that would silently cover a renamed route.
        var derived = DerivedTemplates();

        Assert.True(
            derived.Count >= 5,
            $"The authorize-value entry-point walk found only {derived.Count} routes; it has stopped seeing the real controllers and this rule would now pass over a surface too small to mean anything (#1159, #1161).");

        var declared = Legs.Select(l => l.Template).ToHashSet(StringComparer.Ordinal);

        var unclassified = derived.Where(t => !declared.Contains(t)).ToList();
        Assert.True(
            unclassified.Count == 0,
            "These entry points carry the browser-bound authorize value and no leg is declared for them - declare each one, with the binding cookie it presents or the reason it presents none (#1161): " + string.Join(", ", unclassified));

        var stale = declared.Where(t => !derived.Contains(t)).ToList();
        Assert.True(
            stale.Count == 0,
            "These templates have a declared authorize-value leg but no entry point carries that value on them any more - a route was renamed; update the table (#1161): " + string.Join(", ", stale));

        // The declaration is bound to its proof: deleting a proving test leaves the leg claiming a check
        // that nothing exercises, which is the state this rule exists to make impossible.
        var proofs = GetType().GetMethods(BindingFlags.Public | BindingFlags.Instance | BindingFlags.DeclaredOnly)
            .Select(m => m.Name)
            .ToHashSet(StringComparer.Ordinal);

        var unproven = Legs.Where(l => !proofs.Contains(l.Proof)).Select(l => $"{l.Template} ({l.Protocol}) -> {l.Proof}").ToList();
        Assert.True(
            unproven.Count == 0,
            "These legs name a proving test that does not exist on this class - restore the test or correct the name (#1161): " + string.Join(", ", unproven));
    }

    [Fact]
    public void TheAdjacentRoutes_AreNotSweptIntoTheClass()
    {
        // Must-not-catch. Each of these carries a browser-supplied value that is not the browser-bound
        // authorize value, and the rule above would be wrong about all four if the derivation widened -
        // for instance to "any string parameter the browser controls".
        var derived = DerivedTemplates();

        foreach (var (template, why) in NotThisClass)
        {
            Assert.False(
                derived.Contains(template),
                $"'{template}' was swept into the browser-bound authorize-value class, and it does not carry that value: {why} (#1161)");
        }

        // The four are real routes rather than typos, so this stays a statement about the shipped surface.
        var all = EntryPointInventory.OfThePlugin().Select(e => e.Template).ToHashSet(StringComparer.Ordinal);
        var missing = NotThisClass.Select(n => n.Template).Where(t => !all.Contains(t)).ToList();
        Assert.True(
            missing.Count == 0,
            "These must-not-catch templates name no entry point at all - a route was renamed and the exclusion now protects nothing (#1161): " + string.Join(", ", missing));
    }

    [Fact]
    public void TheBindingCookieNames_ArePinnedByReflection()
    {
        // Sentinel. Every cookie a leg above names must be one the binding type actually declares, so a
        // renamed or deleted constant cannot leave the table pointing at a string nothing sets.
        var declaredCookies = typeof(AuthorizeStateBinding)
            .GetFields(BindingFlags.NonPublic | BindingFlags.Public | BindingFlags.Static)
            .Where(f => f.IsLiteral && f.FieldType == typeof(string))
            .Select(f => (string)f.GetRawConstantValue()!)
            .ToHashSet(StringComparer.Ordinal);

        Assert.Equal(2, declaredCookies.Count);

        var orphaned = Legs.Where(l => l.Cookie is not null && !declaredCookies.Contains(l.Cookie)).Select(l => l.Template).ToList();
        Assert.True(
            orphaned.Count == 0,
            "These legs name a binding cookie AuthorizeStateBinding no longer declares (#1161): " + string.Join(", ", orphaned));

        // Both declared cookies are in use: a flow that stopped presenting its cookie entirely would
        // otherwise leave the constant alive and this table silently one leg short.
        var used = Legs.Where(l => l.Cookie is not null).Select(l => l.Cookie!).ToHashSet(StringComparer.Ordinal);
        Assert.Equal(declaredCookies.OrderBy(c => c, StringComparer.Ordinal), used.OrderBy(c => c, StringComparer.Ordinal));
    }

    [Fact]
    public async Task OidCallback_WithoutTheBindingCookie_RefusesTheState()
    {
        // The redirect leg peeks the state under the binding. With no cookie presented the state is
        // refused, and because the callback peeks rather than consumes, the originating browser is not
        // stranded by the refusal.
        // A reachable-but-unhelpful authorization server: the code exchange past the binding gate fails on
        // its own terms rather than on an unconfigured provider, so the second half below is a statement
        // about the gate and not about the fixture.
        var harness = new SsoControllerHarness(
            c => c.OidConfigs["kc"] = new OidConfig
            {
                Enabled = true,
                OidEndpoint = "https://idp.example/",
                OidClientId = "jellyfin",
            },
            httpResponder: _ => new HttpResponseMessage(HttpStatusCode.NotFound));
        SeedPendingState(harness, "state-1");

        Assert.Equal("Invalid or expired state", ContentOf(await harness.Controller.OidCallback("kc", "state-1")));

        // The same state, same process, presented by the browser that started the flow: it gets past the
        // binding gate to the code exchange. Whatever happens there, it is no longer this refusal - which
        // is what makes the assertion above a statement about the binding rather than about the state.
        SetCookie(harness, AuthorizeStateBinding.CookieName, Binding);
        Assert.NotEqual("Invalid or expired state", ContentOf(await harness.Controller.OidCallback("kc", "state-1")));
    }

    [Fact]
    public async Task OidAuth_WithoutTheBindingCookie_RefusesWithoutConsumingTheState()
    {
        // The one-time consume happens on this leg, so the binding is checked BEFORE the atomic claim:
        // an unbound caller must not be able to burn a state the right browser still holds.
        var harness = new SsoControllerHarness(c => c.OidConfigs["kc"] = new OidConfig { Enabled = true });
        SeedReadyState(harness, "state-1");

        var refused = Assert.IsType<ContentResult>(await harness.Controller.OidAuth("kc", Redeem("state-1")));
        Assert.Equal("Invalid or expired state", refused.Content);

        SetCookie(harness, AuthorizeStateBinding.CookieName, Binding);
        Assert.IsNotType<ContentResult>(await harness.Controller.OidAuth("kc", Redeem("state-1")));
    }

    [Fact]
    public async Task SamlAuth_WithoutTheBindingCookie_RefusesTheOutcomeToken()
    {
        // The SAML mint leg binds a SOLICITED login to the browser that issued the AuthnRequest. With no
        // cookie presented the correlation fails closed and nothing is provisioned.
        var fixture = SamlTestFactory.Create(nameId: "alice", inResponseTo: AuthnRequestId);
        var harness = SamlHarness(fixture);
        SamlLoginService.SeedSamlRequestForTests("adfs", AuthnRequestId, Binding, DateTime.UtcNow.AddMinutes(15));

        var token = SamlOutcomeToken(await harness.Controller.SamlCallback("adfs", formSamlResponse: fixture.EncodeResponse()));

        var refused = Assert.IsType<ContentResult>(await harness.Controller.SamlAuth("adfs", new AuthResponse { Data = token }));

        Assert.Equal(400, refused.StatusCode);
        Assert.Equal("SAML response validation failed", refused.Content);
        await harness.UserManager.DidNotReceive().CreateUserAsync(Arg.Any<string>());
    }

    [Fact]
    public async Task AddCanonicalLink_Oid_WithoutTheBindingCookie_RefusesWithoutConsumingTheState()
    {
        // The manual-link redeem is browser-bound exactly like the login redeem, and for the same reason:
        // an unbound caller must not be able to bind their own provider identity to a Jellyfin account.
        var harness = LinkHarness(c => c.OidConfigs["keycloak"] = new OidConfig { Enabled = true });
        SeedReadyState(harness, "state-1", provider: "keycloak");

        var refused = Assert.IsType<ContentResult>(
            await harness.Controller.AddCanonicalLink("oid", "keycloak", Target, new AuthResponse { Data = "state-1" }));
        Assert.Equal("Invalid or expired state", refused.Content);
        Assert.False(SSOPlugin.Instance.ReadConfiguration(c => c.OidConfigs["keycloak"].CanonicalLinks.ContainsKey("sub-1")));

        // Not consumed: the browser that started the flow still links with the same token.
        SetCookie(harness, AuthorizeStateBinding.CookieName, Binding);
        Assert.IsType<NoContentResult>(await harness.Controller.AddCanonicalLink("oid", "keycloak", Target, new AuthResponse { Data = "state-1" }));
    }

    [Fact]
    public async Task AddCanonicalLink_Saml_CarriesASignedAssertionRatherThanABoundToken()
    {
        // The declared exemption, proven rather than asserted. This leg links with NO binding cookie
        // presented at all, which is what makes it the one member of the class outside the binding rule -
        // and the one-time-use control that stands in its place bites: the same assertion replayed is
        // refused. If this leg is ever converted to a browser-minted token, the first half goes red.
        var fixture = SamlTestFactory.Create(nameId: "alice");
        var harness = LinkHarness(c => c.SamlConfigs["adfs"] = new SamlConfig
        {
            Enabled = true,
            SamlCertificate = fixture.CertificateBase64,
            DoNotValidateAudience = true,
            EnableAuthorization = false,
        });
        harness.Controller.HttpContext.Request.Headers.Remove("Cookie");

        var encoded = fixture.EncodeResponse();
        Assert.IsType<NoContentResult>(await harness.Controller.AddCanonicalLink("saml", "adfs", Target, new AuthResponse { Data = encoded }));
        Assert.True(SSOPlugin.Instance.ReadConfiguration(c => c.SamlConfigs["adfs"].CanonicalLinks.ContainsKey("alice")));

        var replayed = await harness.Controller.AddCanonicalLink("saml", "adfs", Target, new AuthResponse { Data = encoded });
        Assert.Equal("SAML response validation failed", ContentOf(replayed));
    }

    // The class predicate: the browser-bound authorize value arrives either as a parameter literally named
    // "state" or inside the AuthResponse body, whose Data property is the token on every leg that carries
    // one. Both halves are needed - a query-only predicate misses the three redeem legs, and a body-only
    // predicate misses the two redirect legs.
    private static HashSet<string> DerivedTemplates() =>
        EntryPointInventory.OfThePlugin()
            .Where(e => e.Parameters.Any(p =>
                string.Equals(p.Name, "state", StringComparison.Ordinal)
                || p.ParameterType == typeof(AuthResponse)))
            .Select(e => e.Template)
            .ToHashSet(StringComparer.Ordinal);

    private static void SetCookie(SsoControllerHarness harness, string name, string value) =>
        harness.Controller.HttpContext.Request.Headers.Cookie = $"{name}={value}";

    private static string? ContentOf(ActionResult result) => result switch
    {
        ContentResult content => content.Content,
        ObjectResult obj => obj.Value?.ToString(),
        _ => null,
    };

    private static AuthResponse Redeem(string state) => new AuthResponse
    {
        Data = state,
        DeviceID = "device-1",
        DeviceName = "Test Device",
        AppName = "Jellyfin Web",
        AppVersion = "1.0",
    };

    // The discovery metadata the challenge recorded on the state. Since #1067 every client construction
    // site pre-assigns it, so a state carrying none is not a shape the callback can meet in production -
    // seeding one keeps the redirect proof on the real path.
    private static AuthorizeSession.Pending PendingFor(string token, string provider) =>
        new(
            new AuthorizeState { State = token },
            provider,
            isLinking: false,
            DateTime.UtcNow,
            Binding,
            clientKey: null,
            providerInformation: new ProviderInformation
            {
                IssuerName = "https://idp.example/",
                AuthorizeEndpoint = "https://idp.example/authorize",
                TokenEndpoint = "https://idp.example/token",
                KeySet = new Duende.IdentityModel.Jwk.JsonWebKeySet("{\"keys\":[]}"),
            },
            responseIssuerRequired: false);

    // A state the redirect leg can peek: Pending is the shape the challenge stores before the code
    // exchange, which is what PeekCurrent looks for.
    private static void SeedPendingState(SsoControllerHarness harness, string token, string provider = "kc")
    {
        _ = harness;
        OidcLoginService.SeedOidStateForTests(token, PendingFor(token, provider));
    }

    // A state the redeem legs can claim, with the user provisioning the happy path drives mocked so the
    // "not refused for this reason" half of each proof reaches a real outcome.
    private static void SeedReadyState(SsoControllerHarness harness, string token, string provider = "kc")
    {
        OidcLoginService.SeedOidStateForTests(token, new AuthorizeSession.Ready(
            PendingFor(token, provider),
            new OidcAuthorizeStateBuilder.OidcAuthorizeState(
                Username: "alice", Subject: "sub-1", Issuer: null, EmailVerified: null, Valid: true, Admin: false,
                EnableLiveTv: false, EnableLiveTvManagement: false, Folders: new List<string>(), AvatarUrl: null)));

        var user = TestUsers.Named("alice", Target);
        harness.UserManager.CreateUserAsync("alice").Returns(user);
        harness.UserManager.GetUserById(Target).Returns(user);
    }

    private static SsoControllerHarness SamlHarness(SamlFixture fixture)
    {
        var harness = new SsoControllerHarness(c => c.SamlConfigs["adfs"] = new SamlConfig
        {
            Enabled = true,
            SamlCertificate = fixture.CertificateBase64,
            DoNotValidateAudience = true,
            EnableAuthorization = false,
            AllowExistingAccountLink = false,
        });
        var user = TestUsers.Named("alice", Target);
        harness.UserManager.CreateUserAsync("alice").Returns(user);
        harness.UserManager.GetUserById(Target).Returns(user);
        return harness;
    }

    // The link routes run behind AssertCanUpdateUser, so the caller identity has to be mocked before the
    // binding decision is reached at all. No binding cookie is set here: presenting one is what each proof
    // varies.
    private static SsoControllerHarness LinkHarness(Action<PluginConfiguration> configure)
    {
        var harness = new SsoControllerHarness(configure);

        var user = new User("caller", "SSO-Auth", "Default") { Id = Target, EnableUserPreferenceAccess = true };
        user.SetPermission(PermissionKind.IsAdministrator, true);
        harness.AuthContext.GetAuthorizationInfo(Arg.Any<HttpRequest>()).Returns(Task.FromResult(new AuthorizationInfo { User = user }));
        return harness;
    }

    // The auth page the SAML callback renders carries the one-time token as `var data = "<hex>";`.
    private static string SamlOutcomeToken(ActionResult callbackResult)
    {
        var page = Assert.IsType<ContentResult>(callbackResult);
        var marker = "var data = \"";
        var start = page.Content!.IndexOf(marker, StringComparison.Ordinal);
        Assert.True(start >= 0, "the login auth page must carry a one-time token, not the assertion");
        start += marker.Length;
        return page.Content[start..page.Content.IndexOf('"', start)];
    }
}
