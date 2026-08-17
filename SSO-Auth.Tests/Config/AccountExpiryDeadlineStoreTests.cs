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
/// The persisted half of between-logins expiry enforcement (#1145): where the deadline comes from, that it
/// survives a restart and a config-page save, and that it never outlives the link it keys off.
/// <para>
/// The store is the reason the sweep can work at all. Held in memory it would be lost on every restart, and
/// a time-limited account would quietly become an unlimited one after the first server bounce - a failure
/// with no error message anywhere.
/// </para>
/// <para>
/// It is also a WRITE surface worth guarding. A forged PAST instant for a guessed subject is a remote
/// disable of that account, so the map is withheld from JSON in both directions and the login path is its
/// only writer; <see cref="Deadlines_AreOmittedFromJson_ButKeptInXml"/> is what refuses the first half.
/// </para>
/// </summary>
public class AccountExpiryDeadlineStoreTests
{
    private static readonly Guid User = Guid.Parse("11111111-1111-1111-1111-111111111111");
    private static readonly DateTime Deadline = new(2999, 1, 1, 0, 0, 0, DateTimeKind.Utc);

    [Fact]
    public async Task ALoginCarryingAFutureDeadline_PersistsIt_AgainstTheLink()
    {
        // Where the store is filled from. Without this the sweep has nothing to read, and the deadline binds
        // only the users who come back - which is exactly what #1144 already did on its own.
        var config = new OidConfig { Enabled = true, AccountExpiryClaim = "access_expires" };
        var (service, users, _) = BuildLogin(config);
        var user = TestUsers.Named("alice", User);
        users.GetUserById(User).Returns(user);
        config.CanonicalLinks["sub-1"] = User;

        await service.CompleteAsync(Identity(Deadline), Response(), config, AdoptionGate.None, () => "203.0.113.9");

        Assert.Equal(Deadline, config.CanonicalLinkDeadlines["sub-1"]);
    }

    [Fact]
    public async Task ALoginCarryingNoDeadline_WritesNothing()
    {
        // A provider with the claim configured whose login carried no readable instant is refused by the
        // #1144 gate and must leave the store untouched: writing a guess here would let a transient identity
        // provider glitch schedule a disable for an account nothing was wrong with.
        var config = new OidConfig { Enabled = true, AccountExpiryClaim = "access_expires" };
        var (service, users, _) = BuildLogin(config);
        users.GetUserById(User).Returns(TestUsers.Named("alice", User));
        config.CanonicalLinks["sub-1"] = User;

        await service.CompleteAsync(Identity(null), Response(), config, AdoptionGate.None, () => "203.0.113.9");

        Assert.Empty(config.CanonicalLinkDeadlines);
    }

    [Fact]
    public void Preserve_ReinjectsLiveDeadlines_IntoAStaleIncomingSave()
    {
        // The Done-when's config-PUT regression, on both protocols. The map is withheld from JSON, so a
        // config-page save always arrives with it empty; without the re-injection every stored deadline is
        // erased by an unrelated settings change and every time-limited account silently becomes unlimited.
        var live = new PluginConfiguration();
        live.OidConfigs["idp"] = new OidConfig
        {
            OidEndpoint = "https://idp/.well-known",
            CanonicalLinks = new SerializableDictionary<string, Guid> { ["sub-1"] = User },
            CanonicalLinkDeadlines = new SerializableDictionary<string, DateTime> { ["sub-1"] = Deadline },
        };
        live.SamlConfigs["saml"] = new SamlConfig
        {
            CanonicalLinks = new SerializableDictionary<string, Guid> { ["nameid-1"] = User },
            CanonicalLinkDeadlines = new SerializableDictionary<string, DateTime> { ["nameid-1"] = Deadline },
        };

        var incoming = new PluginConfiguration();
        incoming.OidConfigs["idp"] = new OidConfig { OidEndpoint = "https://idp/.well-known" };
        incoming.SamlConfigs["saml"] = new SamlConfig();

        ServerManagedFields.Preserve(incoming, live);

        Assert.Equal(Deadline, incoming.OidConfigs["idp"].CanonicalLinkDeadlines["sub-1"]);
        Assert.Equal(Deadline, incoming.SamlConfigs["saml"].CanonicalLinkDeadlines["nameid-1"]);
    }

    [Fact]
    public void Preserve_OidEndpointChanged_ClearsTheDeadlinesWithTheLinks()
    {
        // The repoint belt (#186) reaches the deadlines too. The links it drops are the ones these deadlines
        // key off, so carrying them over would leave orphans that a different identity provider's subject
        // could inherit.
        var live = new PluginConfiguration();
        live.OidConfigs["idp"] = new OidConfig
        {
            OidEndpoint = "https://idp/.well-known",
            CanonicalLinks = new SerializableDictionary<string, Guid> { ["sub-1"] = User },
            CanonicalLinkDeadlines = new SerializableDictionary<string, DateTime> { ["sub-1"] = Deadline },
        };
        var incoming = new PluginConfiguration();
        incoming.OidConfigs["idp"] = new OidConfig { OidEndpoint = "https://other-idp/.well-known" };

        ServerManagedFields.Preserve(incoming, live);

        Assert.Empty(incoming.OidConfigs["idp"].CanonicalLinks);
        Assert.Empty(incoming.OidConfigs["idp"].CanonicalLinkDeadlines);
    }

    [Fact]
    public void RemovingALink_RemovesItsDeadline()
    {
        // An orphan deadline is worse than dead weight: it names a subject whose link is gone, so a re-link
        // of that same subject would arrive already expired and be disabled by the next tick.
        var configuration = new PluginConfiguration();
        var config = new OidConfig { Enabled = true };
        configuration.OidConfigs["kc"] = config;
        config.CanonicalLinks["sub-1"] = User;
        config.CanonicalLinkDeadlines["sub-1"] = Deadline;
        var service = LinkService(configuration);

        service.TryRemoveLink(ProviderMode.Oid, "kc", "sub-1", User);

        Assert.Empty(config.CanonicalLinkDeadlines);
    }

    [Fact]
    public void RevokingAUserEverywhere_PrunesTheirDeadlines_OnBothProtocols()
    {
        // The admin Unregister path removes the links directly rather than through TryRemoveLink, so it
        // needs its own prune; SAML has no issuer map to ride along with, which is why this covers both.
        var configuration = new PluginConfiguration();
        var oid = new OidConfig { Enabled = true };
        var saml = new SamlConfig { Enabled = true };
        configuration.OidConfigs["kc"] = oid;
        configuration.SamlConfigs["idp"] = saml;
        oid.CanonicalLinks["sub-1"] = User;
        oid.CanonicalLinkDeadlines["sub-1"] = Deadline;
        saml.CanonicalLinks["nameid-1"] = User;
        saml.CanonicalLinkDeadlines["nameid-1"] = Deadline;

        LinkService(configuration).RemoveUserEverywhere(User);

        Assert.Empty(oid.CanonicalLinkDeadlines);
        Assert.Empty(saml.CanonicalLinkDeadlines);
    }

    [Fact]
    public void ADeadlineIsNeverWritten_ForASubjectThatHasNoLink()
    {
        // The bound on the map's size, and the reason it cannot be used as a scratch space: an entry only
        // ever exists beside a live link, so the link map is the ceiling on this one.
        var configuration = new PluginConfiguration();
        var config = new OidConfig { Enabled = true };
        configuration.OidConfigs["kc"] = config;

        LinkService(configuration).RecordAccountDeadline(ProviderMode.Oid, "kc", "sub-unlinked", Deadline);

        Assert.Empty(config.CanonicalLinkDeadlines);
    }

    [Fact]
    public void Deadlines_AreOmittedFromJson_ButKeptInXml()
    {
        // Server-managed exactly like the links and the issuer bindings: withheld from JSON so a config PUT
        // can neither read the deadlines back nor forge one - a forged PAST instant for a guessed subject
        // would be a remote disable of that account - and persisted in the XML so the store survives a
        // restart, which is the Done-when's "not in-memory" clause.
        var config = new OidConfig
        {
            OidClientId = "client",
            CanonicalLinkDeadlines = new SerializableDictionary<string, DateTime> { ["sub-secret"] = Deadline },
        };

        var json = System.Text.Json.JsonSerializer.Serialize(config);
        Assert.DoesNotContain("CanonicalLinkDeadlines", json, StringComparison.Ordinal);
        Assert.DoesNotContain("sub-secret", json, StringComparison.Ordinal);

        var serializer = new XmlSerializer(typeof(OidConfig));
        using var writer = new System.IO.StringWriter();
        serializer.Serialize(writer, config);
        var xml = writer.ToString();
        Assert.Contains("CanonicalLinkDeadlines", xml, StringComparison.Ordinal);
        Assert.Contains("sub-secret", xml, StringComparison.Ordinal);

        using var reader = new System.IO.StringReader(xml);
        using var xmlReader = System.Xml.XmlReader.Create(
            reader,
            new System.Xml.XmlReaderSettings { DtdProcessing = System.Xml.DtdProcessing.Prohibit, XmlResolver = null });
        var back = (OidConfig)serializer.Deserialize(xmlReader)!;

        Assert.Equal(Deadline, back.CanonicalLinkDeadlines["sub-secret"].ToUniversalTime());
    }

    // --- helpers ---

    private static CanonicalLinkService LinkService(PluginConfiguration configuration) =>
        new CanonicalLinkService(
            Substitute.For<IUserManager>(),
            new FakeCryptoProvider(),
            new ProviderConfigStore(() => configuration, _ => { }, new CapturingLogger()),
            new CapturingLogger());

    private static AuthResponse Response() =>
        new AuthResponse { AppName = "app", AppVersion = "1", DeviceID = "d", DeviceName = "dev" };

    private static VerifiedIdentity Identity(DateTime? expiresAtUtc) =>
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
            ExpiresAtUtc: expiresAtUtc));

    private static (LoginCompletionService Service, IUserManager Users, ISessionManager Sessions) BuildLogin(OidConfig config)
    {
        var configuration = new PluginConfiguration();
        configuration.OidConfigs["kc"] = config;
        var users = Substitute.For<IUserManager>();
        var sessions = Substitute.For<ISessionManager>();
        sessions.AuthenticateDirect(Arg.Any<AuthenticationRequest>()).Returns(new AuthenticationResult());
        var store = new ProviderConfigStore(() => configuration, _ => { }, new CapturingLogger());
        var canonicalLinks = new CanonicalLinkService(users, new FakeCryptoProvider(), store, new CapturingLogger());
        var avatar = new AvatarService(users, Substitute.For<IProviderManager>(), Substitute.For<IServerConfigurationManager>(), new CapturingLogger(), "test-agent");
        var minter = new SessionMinter(users, avatar, sessions, new CapturingLogger());
        var ssoOnly = new SsoOnlyLoginService(users, store, new CapturingLogger());
        return (new LoginCompletionService(canonicalLinks, minter, ssoOnly, store, sessions, new CapturingLogger()), users, sessions);
    }
}
