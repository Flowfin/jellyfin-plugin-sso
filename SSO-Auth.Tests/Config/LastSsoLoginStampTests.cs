// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using System.Xml.Serialization;
using Jellyfin.Plugin.SSO_Auth.Api;
using Jellyfin.Plugin.SSO_Auth.Api.Avatar;
using Jellyfin.Plugin.SSO_Auth.Api.Flows;
using Jellyfin.Plugin.SSO_Auth.Api.Identity;
using Jellyfin.Plugin.SSO_Auth.Api.Linking;
using Jellyfin.Plugin.SSO_Auth.Api.Oidc;
using Jellyfin.Plugin.SSO_Auth.Api.Provider;
using Jellyfin.Plugin.SSO_Auth.Api.Session;
using Jellyfin.Plugin.SSO_Auth.Config;
using MediaBrowser.Controller.Authentication;
using MediaBrowser.Controller.Configuration;
using MediaBrowser.Controller.Library;
using MediaBrowser.Controller.Providers;
using MediaBrowser.Controller.Session;
using NSubstitute;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// The bounded last-SSO-login stamp (#1120): where it is written, that it stays one entry per existing link
/// rather than becoming an event log, that it is erased by every route that erases the link, and that the
/// roster can tell "never" from an instant.
/// <para>
/// The boundedness is the whole review. The acceptance criterion this issue inherits is "no new unbounded PII
/// store", and the design that satisfies it is one entry beside a link that already exists - so the tests
/// below assert the cardinality directly (N logins, one entry) rather than trusting the shape of the code.
/// </para>
/// <para>
/// The second property is a cost one, and it is a security property here rather than a performance nicety: an
/// established user's repeat login pays no configuration persist today, and the file this would write on every
/// login carries every provider secret envelope and every link map. <see cref="ASecondLoginInsideTheWindow_WritesNothing"/>
/// is what refuses a write-through stamp sneaking back in.
/// </para>
/// </summary>
public class LastSsoLoginStampTests
{
    private static readonly Guid User = Guid.Parse("22222222-2222-2222-2222-222222222222");
    private static readonly DateTime Now = new(2026, 8, 17, 12, 0, 0, DateTimeKind.Utc);

    [Fact]
    public async Task ASuccessfulLogin_StampsTheLinkItResolved()
    {
        // The call site. Without it the map is a field nothing fills, and the roster column it exists for
        // would read "never" for every account forever.
        var config = new OidConfig { Enabled = true };
        var (service, users, _) = BuildLogin(config, out _);
        users.GetUserById(User).Returns(TestUsers.Named("alice", User));
        config.CanonicalLinks["sub-1"] = User;

        await service.CompleteAsync(Identity(), Response(), config, AdoptionGate.None, () => "203.0.113.9");

        Assert.True(config.CanonicalLinkLastLogins.ContainsKey("sub-1"));
        Assert.Equal(DateTimeKind.Utc, config.CanonicalLinkLastLogins["sub-1"].Kind);
    }

    [Fact]
    public async Task ManyLoginsForOneSubject_LeaveExactlyOneEntry()
    {
        // The boundedness clause, asserted as cardinality. An append-per-login design would pass every other
        // test in this file and fail exactly here, which is why the count is the assertion rather than the
        // presence of the key.
        var config = new OidConfig { Enabled = true };
        var (service, users, _) = BuildLogin(config, out _);
        users.GetUserById(User).Returns(TestUsers.Named("alice", User));
        config.CanonicalLinks["sub-1"] = User;

        for (var i = 0; i < 5; i++)
        {
            await service.CompleteAsync(Identity(), Response(), config, AdoptionGate.None, () => "203.0.113.9");
        }

        Assert.Single(config.CanonicalLinkLastLogins);
    }

    [Fact]
    public async Task ASecondLoginInsideTheWindow_WritesNothing()
    {
        // The flush policy, proven by counting persists rather than by reading the code. The first login of a
        // link stamps it and pays one write; the second inside the granularity window must pay none, because
        // the login path deliberately performs no configuration persist for an established user.
        var config = new OidConfig { Enabled = true };
        var (service, users, _) = BuildLogin(config, out var persists);
        users.GetUserById(User).Returns(TestUsers.Named("alice", User));
        config.CanonicalLinks["sub-1"] = User;

        await service.CompleteAsync(Identity(), Response(), config, AdoptionGate.None, () => "203.0.113.9");
        var afterFirst = persists.Count;

        await service.CompleteAsync(Identity(), Response(), config, AdoptionGate.None, () => "203.0.113.9");

        Assert.Equal(1, afterFirst);
        Assert.Equal(afterFirst, persists.Count);
    }

    [Fact]
    public void AStampOlderThanTheGranularity_IsRewritten()
    {
        // The other half of the same rule: coalescing may not become "written once and then frozen", or the
        // roster would report a user's first-ever login as their last one for the rest of the deployment.
        var configuration = new PluginConfiguration();
        var config = new OidConfig { Enabled = true };
        configuration.OidConfigs["kc"] = config;
        config.CanonicalLinks["sub-1"] = User;
        config.CanonicalLinkLastLogins["sub-1"] = Now - ProviderConfigBase.LastSsoLoginGranularity - TimeSpan.FromMinutes(1);

        LinkService(configuration, () => Now).RecordLastSsoLogin(ProviderMode.Oid, "kc", "sub-1");

        Assert.Equal(Now, config.CanonicalLinkLastLogins["sub-1"]);
    }

    [Fact]
    public void AStampStoredInTheFuture_IsCorrectedRatherThanFrozen()
    {
        // The near-miss the age comparison invites, and a one-character mistake away from shipping: with the
        // test written as `now - stored >= granularity` alone, a stamp ahead of the clock - a configuration
        // restored from a machine whose clock ran fast, or a clock stepped back - is never overdue, so it is
        // frozen forever and the roster keeps reporting a login from the future.
        var configuration = new PluginConfiguration();
        var config = new OidConfig { Enabled = true };
        configuration.OidConfigs["kc"] = config;
        config.CanonicalLinks["sub-1"] = User;
        config.CanonicalLinkLastLogins["sub-1"] = Now + TimeSpan.FromDays(30);

        LinkService(configuration, () => Now).RecordLastSsoLogin(ProviderMode.Oid, "kc", "sub-1");

        Assert.Equal(Now, config.CanonicalLinkLastLogins["sub-1"]);
    }

    [Fact]
    public void AStampIsNeverWritten_ForASubjectThatHasNoLink()
    {
        // The ceiling on the map's size: an entry can only exist beside a live link, so the link map bounds
        // this one. Without it the stamp would be a scratch space any resolved-but-unlinked identity could
        // grow, which is the unbounded store the parent issue's criterion forbids.
        var configuration = new PluginConfiguration();
        var config = new OidConfig { Enabled = true };
        configuration.OidConfigs["kc"] = config;

        LinkService(configuration, () => Now).RecordLastSsoLogin(ProviderMode.Oid, "kc", "sub-unlinked");

        Assert.Empty(config.CanonicalLinkLastLogins);
    }

    [Fact]
    public void AStampIsNeverWritten_ForAnUnknownProvider_OrABlankKey()
    {
        // Two fail-closed arms of the only writer, both reachable from a real login: a provider deleted by a
        // save while a login for it was in flight, and the blank key an identity that did not resolve carries.
        // Neither may create an entry, and neither may throw out of a login that has already minted a session.
        var configuration = new PluginConfiguration();
        var config = new OidConfig { Enabled = true };
        configuration.OidConfigs["kc"] = config;
        config.CanonicalLinks["sub-1"] = User;
        var service = LinkService(configuration, () => Now);

        service.RecordLastSsoLogin(ProviderMode.Oid, "deleted-provider", "sub-1");
        service.RecordLastSsoLogin(ProviderMode.Oid, "kc", "   ");

        Assert.Empty(config.CanonicalLinkLastLogins);
    }

    [Fact]
    public void RemovingALink_RemovesItsStamp()
    {
        // Unlinking IS the erasure route the retention promise names, so a stamp surviving it would be login
        // history retained for a subject the server no longer knows - and a re-link of the same key would
        // report a last login belonging to the previous holder of it.
        var configuration = new PluginConfiguration();
        var config = new OidConfig { Enabled = true };
        configuration.OidConfigs["kc"] = config;
        config.CanonicalLinks["sub-1"] = User;
        config.CanonicalLinkLastLogins["sub-1"] = Now;

        LinkService(configuration, () => Now).TryRemoveLink(ProviderMode.Oid, "kc", "sub-1", User);

        Assert.Empty(config.CanonicalLinkLastLogins);
    }

    [Fact]
    public void RevokingAUserEverywhere_PrunesTheirStamps_OnBothProtocols()
    {
        // The administrator Unregister path removes links directly rather than through TryRemoveLink, so it
        // carries its own prune. SAML is asserted beside OpenID on purpose: the neighbouring issuer map is
        // OpenID-only, so an implementation copied from it prunes the OpenID arm and silently leaves every
        // SAML stamp behind - a test that only unlinked an OpenID user would pass over exactly that defect.
        var configuration = new PluginConfiguration();
        var oid = new OidConfig { Enabled = true };
        var saml = new SamlConfig { Enabled = true };
        configuration.OidConfigs["kc"] = oid;
        configuration.SamlConfigs["idp"] = saml;
        oid.CanonicalLinks["sub-1"] = User;
        oid.CanonicalLinkLastLogins["sub-1"] = Now;
        saml.CanonicalLinks["nameid-1"] = User;
        saml.CanonicalLinkLastLogins["nameid-1"] = Now;

        LinkService(configuration, () => Now).RemoveUserEverywhere(User);

        Assert.Empty(oid.CanonicalLinkLastLogins);
        Assert.Empty(saml.CanonicalLinkLastLogins);
    }

    [Fact]
    public void TheSamlArm_StampsAndRemovesToo()
    {
        // Both protocols carry the map, so both arms of the provider lookup have to be reachable rather than
        // inherited from the OpenID bookkeeping.
        var configuration = new PluginConfiguration();
        var config = new SamlConfig { Enabled = true };
        configuration.SamlConfigs["idp"] = config;
        config.CanonicalLinks["nameid-1"] = User;
        var service = LinkService(configuration, () => Now);

        service.RecordLastSsoLogin(ProviderMode.Saml, "idp", "nameid-1");
        Assert.Equal(Now, config.CanonicalLinkLastLogins["nameid-1"]);

        service.TryRemoveLink(ProviderMode.Saml, "idp", "nameid-1", User);
        Assert.Empty(config.CanonicalLinkLastLogins);
    }

    [Fact]
    public void AStampWrittenFromALocalClock_IsStoredAsUtc()
    {
        // One clock basis throughout (#676). Stored in the server's local time it would be serialized without
        // a zone and read by the roster as UTC, so the same login would appear hours out depending on where
        // the server is - the kind of defect nobody reports as a bug.
        var configuration = new PluginConfiguration();
        var config = new OidConfig { Enabled = true };
        configuration.OidConfigs["kc"] = config;
        config.CanonicalLinks["sub-1"] = User;
        var local = new DateTime(2026, 8, 17, 14, 0, 0, DateTimeKind.Local);

        LinkService(configuration, () => local).RecordLastSsoLogin(ProviderMode.Oid, "kc", "sub-1");

        var stored = config.CanonicalLinkLastLogins["sub-1"];
        Assert.Equal(DateTimeKind.Utc, stored.Kind);
        Assert.Equal(local.ToUniversalTime(), stored);
    }

    [Fact]
    public void Preserve_ReinjectsLiveStamps_IntoAStaleIncomingSave()
    {
        // The config-PUT regression, on both protocols. The map is withheld from JSON, so a config-page save
        // always arrives with it empty; without the re-injection an unrelated settings change resets every
        // "last SSO login" in the roster to never.
        var live = new PluginConfiguration();
        live.OidConfigs["idp"] = new OidConfig
        {
            OidEndpoint = "https://idp/.well-known",
            CanonicalLinks = new SerializableDictionary<string, Guid> { ["sub-1"] = User },
            CanonicalLinkLastLogins = new SerializableDictionary<string, DateTime> { ["sub-1"] = Now },
        };
        live.SamlConfigs["saml"] = new SamlConfig
        {
            CanonicalLinks = new SerializableDictionary<string, Guid> { ["nameid-1"] = User },
            CanonicalLinkLastLogins = new SerializableDictionary<string, DateTime> { ["nameid-1"] = Now },
        };

        var incoming = new PluginConfiguration();
        incoming.OidConfigs["idp"] = new OidConfig { OidEndpoint = "https://idp/.well-known" };
        incoming.SamlConfigs["saml"] = new SamlConfig();

        ServerManagedFields.Preserve(incoming, live);

        Assert.Equal(Now, incoming.OidConfigs["idp"].CanonicalLinkLastLogins["sub-1"]);
        Assert.Equal(Now, incoming.SamlConfigs["saml"].CanonicalLinkLastLogins["nameid-1"]);
    }

    [Fact]
    public void Preserve_OidEndpointChanged_ClearsTheStampsWithTheLinks()
    {
        // The repoint belt (#186) reaches the stamps. A different discovery URL is potentially a different
        // identity provider, and the links it drops are the ones these stamps key off - so keeping them would
        // retain login history for subjects this provider no longer knows, with no erasure route left.
        var live = new PluginConfiguration();
        live.OidConfigs["idp"] = new OidConfig
        {
            OidEndpoint = "https://idp/.well-known",
            CanonicalLinks = new SerializableDictionary<string, Guid> { ["sub-1"] = User },
            CanonicalLinkLastLogins = new SerializableDictionary<string, DateTime> { ["sub-1"] = Now },
        };
        var incoming = new PluginConfiguration();
        incoming.OidConfigs["idp"] = new OidConfig { OidEndpoint = "https://other-idp/.well-known" };

        ServerManagedFields.Preserve(incoming, live);

        Assert.Empty(incoming.OidConfigs["idp"].CanonicalLinks);
        Assert.Empty(incoming.OidConfigs["idp"].CanonicalLinkLastLogins);
    }

    [Fact]
    public void Stamps_AreOmittedFromJson_ButSurviveTheXmlRoundTrip()
    {
        // Server-managed exactly like the links: withheld from JSON so a config PUT can neither read a
        // subject's login history back out nor forge an entry, and persisted in the XML so the roster still
        // answers after a restart rather than resetting to never on every server bounce.
        var config = new OidConfig
        {
            OidClientId = "client",
            CanonicalLinkLastLogins = new SerializableDictionary<string, DateTime> { ["sub-secret"] = Now },
        };

        var json = System.Text.Json.JsonSerializer.Serialize(config);
        Assert.DoesNotContain("CanonicalLinkLastLogins", json, StringComparison.Ordinal);
        Assert.DoesNotContain("sub-secret", json, StringComparison.Ordinal);

        var serializer = new XmlSerializer(typeof(OidConfig));
        using var writer = new System.IO.StringWriter();
        serializer.Serialize(writer, config);
        var xml = writer.ToString();
        Assert.Contains("CanonicalLinkLastLogins", xml, StringComparison.Ordinal);

        using var reader = new System.IO.StringReader(xml);
        using var xmlReader = System.Xml.XmlReader.Create(
            reader,
            new System.Xml.XmlReaderSettings { DtdProcessing = System.Xml.DtdProcessing.Prohibit, XmlResolver = null });
        var back = (OidConfig)serializer.Deserialize(xmlReader)!;

        Assert.Equal(Now, back.CanonicalLinkLastLogins["sub-secret"].ToUniversalTime());
    }

    [Fact]
    public void TheRoster_CarriesTheStamp_AndReportsNeverAsNull()
    {
        // The reporting clause, including the half that is easy to get wrong: a link with no stamp has to come
        // out as null rather than as a default DateTime, which a client would render as a login in year one -
        // a fabricated date is worse than an admitted gap.
        var live = new PluginConfiguration();
        var config = new OidConfig { Enabled = true };
        live.OidConfigs["kc"] = config;
        config.CanonicalLinks["seen"] = User;
        config.CanonicalLinks["never"] = User;
        config.CanonicalLinkLastLogins["seen"] = Now;

        var document = LinkRoster.Build(live, _ => "alice");

        var links = Assert.Single(document.Accounts).Links;
        Assert.Equal(Now, Assert.Single(links, l => l.CanonicalName == "seen").LastSsoLoginUtc);
        Assert.Null(Assert.Single(links, l => l.CanonicalName == "never").LastSsoLoginUtc);
    }

    [Fact]
    public void ThePortableLinkExport_DoesNotCarryTheStamp()
    {
        // Deliberate, and pinned so it cannot drift in by someone adding the field to the shared walk. The
        // export exists to be re-applied to a rebuilt server: restoring a login instant would assert a login
        // that never happened there, and shipping it off the machine widens where the personal data travels
        // for nothing. The roster is a read of the live server and is the one document that reports it.
        var live = new PluginConfiguration();
        var config = new OidConfig { Enabled = true };
        live.OidConfigs["kc"] = config;
        config.CanonicalLinks["sub-1"] = User;
        config.CanonicalLinkLastLogins["sub-1"] = Now;

        var json = System.Text.Json.JsonSerializer.Serialize(LinkExport.Build(live, _ => "alice"));

        Assert.DoesNotContain("LastSsoLogin", json, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(Now.Year.ToString(System.Globalization.CultureInfo.InvariantCulture), json, StringComparison.Ordinal);
    }

    [Fact]
    public void AFailedConfigurationPersist_DoesNotEscapeIntoTheLogin()
    {
        // The availability arm, and the reason the write is wrapped at all. The stamp is written after the
        // session has been minted, so an exception out of the persist would turn a login that has ALREADY
        // succeeded into an error - on every login, for as long as the volume stays read-only or full. A stale
        // roster column is the correct price; SSO refusing every login on the server is not.
        var configuration = new PluginConfiguration();
        var config = new OidConfig { Enabled = true };
        configuration.OidConfigs["kc"] = config;
        config.CanonicalLinks["sub-1"] = User;
        var logger = new CapturingLogger();
        var service = new CanonicalLinkService(
            Substitute.For<IUserManager>(),
            new FakeCryptoProvider(),
            new ProviderConfigStore(() => configuration, _ => throw new System.IO.IOException("read-only volume"), logger),
            logger,
            clock: () => Now);

        service.RecordLastSsoLogin(ProviderMode.Oid, "kc", "sub-1");

        Assert.Contains(logger.Entries, e => e.Message.Contains("last SSO login", StringComparison.Ordinal));
    }

    [Fact]
    public void TheConfigExport_WithholdsTheStamp()
    {
        // Named by the Done-when. The export shares the live provider objects and relies entirely on the JSON
        // attributes to withhold the server-managed maps, so nothing in that file mentions this one - which is
        // exactly why the omission has to be pinned here rather than read out of the export's own source.
        var live = new PluginConfiguration();
        var config = new OidConfig { Enabled = true };
        live.OidConfigs["kc"] = config;
        config.CanonicalLinks["sub-1"] = User;
        config.CanonicalLinkLastLogins["sub-1"] = Now;

        var json = System.Text.Json.JsonSerializer.Serialize(ConfigExport.Build(live));

        Assert.DoesNotContain("CanonicalLinkLastLogins", json, StringComparison.Ordinal);
        Assert.DoesNotContain("sub-1", json, StringComparison.Ordinal);
    }

    [Fact]
    public void AConfigPut_CanNeitherSetNorReadTheStamp()
    {
        // The forge arm. The map is withheld in BOTH directions: a posted body naming it deserializes to
        // nothing, so an administrator - or anyone who reaches that route - cannot plant a login history for a
        // guessed subject, and cannot read one back out either.
        var posted = System.Text.Json.JsonSerializer.Deserialize<OidConfig>(
            """{"OidClientId":"client","CanonicalLinkLastLogins":{"sub-1":"2026-08-17T12:00:00Z"}}""");

        Assert.NotNull(posted);
        Assert.Empty(posted.CanonicalLinkLastLogins);
    }

    // --- helpers ---

    private static CanonicalLinkService LinkService(PluginConfiguration configuration, Func<DateTime> clock) =>
        new CanonicalLinkService(
            Substitute.For<IUserManager>(),
            new FakeCryptoProvider(),
            new ProviderConfigStore(() => configuration, _ => { }, new CapturingLogger()),
            new CapturingLogger(),
            clock: clock);

    private static AuthResponse Response() =>
        new AuthResponse { AppName = "app", AppVersion = "1", DeviceID = "d", DeviceName = "dev" };

    private static VerifiedIdentity Identity() =>
        TestIdentities.Oidc("kc", new OidcAuthorizeStateBuilder.OidcAuthorizeState(
            Username: "alice",
            Subject: "sub-1",
            Issuer: null,
            EmailVerified: null,
            Valid: true,
            Admin: false,
            EnableLiveTv: false,
            EnableLiveTvManagement: false,
            Folders: new List<string>(),
            AvatarUrl: null,
            ExpiresAtUtc: null));

    // The login service under test, plus the list every configuration persist lands in - the flush-policy test
    // counts that list rather than inspecting the code, so a write-through stamp reddens it.
    private static (LoginCompletionService Service, IUserManager Users, ISessionManager Sessions) BuildLogin(OidConfig config, out List<int> persists)
    {
        var configuration = new PluginConfiguration();
        configuration.OidConfigs["kc"] = config;
        var writes = new List<int>();
        persists = writes;
        var users = Substitute.For<IUserManager>();
        var sessions = Substitute.For<ISessionManager>();
        sessions.AuthenticateDirect(Arg.Any<AuthenticationRequest>()).Returns(new AuthenticationResult());
        var store = new ProviderConfigStore(() => configuration, _ => writes.Add(1), new CapturingLogger());
        var canonicalLinks = new CanonicalLinkService(users, new FakeCryptoProvider(), store, new CapturingLogger());
        var avatar = new AvatarService(users, Substitute.For<IProviderManager>(), Substitute.For<IServerConfigurationManager>(), new CapturingLogger(), "test-agent");
        var minter = new SessionMinter(users, avatar, sessions, new CapturingLogger());
        var ssoOnly = new SsoOnlyLoginService(users, store, new CapturingLogger());
        return (new LoginCompletionService(canonicalLinks, minter, ssoOnly, store, sessions, new CapturingLogger()), users, sessions);
    }
}
