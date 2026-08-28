// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Threading.Tasks;
using Jellyfin.Database.Implementations.Entities;
using Jellyfin.Plugin.SSO_Auth.Api.Linking;
using Jellyfin.Plugin.SSO_Auth.Api.Session;
using Jellyfin.Plugin.SSO_Auth.Config;
using MediaBrowser.Controller.Library;
using NSubstitute;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// The migration half of #1440: an SSO-linked Jellyfin account that carries no stored password accepts the
/// EMPTY password on the ordinary login form, so it is reachable by anybody on the network without the
/// identity provider. The boot-time sweep gives every such account an unguessable password.
/// <para>
/// THE POPULATION IS REAL AND THE CREATE ARM DOES NOT REACH IT. Every plugin release up to and including
/// v3.4.0.2 created the account and wrote no password; v3.5.0.0 was the first to mint one. Accounts from
/// before that are still on upgraded servers, and a fix at the point of creation only ever runs for accounts
/// that do not exist yet. Deleting the write in <see cref="PasswordlessLinkedAccountSweep.SweepAsync"/>
/// reddens most of this file.
/// </para>
/// <para>
/// THE TWO FAIL-SAFES are <see cref="AnAccountThatAlreadyHasAPassword_IsLeftExactlyAsItWas"/> and
/// <see cref="TheSweep_NeverRepointsAnAccountsLoginProvider"/>. Between them they are what stops a repair
/// that runs unattended at every boot from becoming the thing that decides how somebody else's users log in:
/// it may close an empty-password door and it may do nothing else. Removing the emptiness test, or adding a
/// provider-id write, turns exactly those rows red.
/// </para>
/// </summary>
public class PasswordlessLinkedAccountSweepTests
{
    private static readonly Guid Linked = Guid.Parse("11111111-1111-1111-1111-111111111111");
    private static readonly Guid Other = Guid.Parse("22222222-2222-2222-2222-222222222222");

    // The fixed part of the audit line SsoAudit.PasswordlessAccountsSealed emits, matched rather than
    // reproduced so a reworded message fails one place instead of six.
    private const string SealAuditMarker = "had no stored password";

    [Fact]
    public async Task ALinkedAccountWithNoPassword_IsGivenOne_AndTheAccountIsPersisted()
    {
        // The headline Done-when. Both halves are required and they fail differently: no password written
        // means the door is still open, and no persist means it is open again on the next read.
        var (sweep, config, users, crypto, audit) = Build();
        var user = LinkedUser(users, config, password: null);

        var sealedAccounts = await sweep.SweepAsync();

        Assert.Equal(1, sealedAccounts);
        Assert.False(string.IsNullOrEmpty(user.Password));
        await users.Received(1).UpdateUserAsync(user);
        Assert.Single(audit.Entries, e => e.Message.Contains(SealAuditMarker, StringComparison.Ordinal));
        Assert.Single(crypto.Hashed);
    }

    [Fact]
    public async Task ASealedAccountsPasswordCarriesRealEntropy_AndTwoOfThemDiffer()
    {
        // A sweep that sealed every account with one constant would read as sealed and be one guess from
        // open. 64 CSPRNG bytes base64-encoded is at least 64 characters of plaintext, which is what the
        // create arm has minted since v3.5.0.0 - the two writers share one helper precisely so this cannot
        // drift apart between them.
        var (sweep, config, users, crypto, _) = Build();
        LinkedUser(users, config, password: null);
        LinkedUser(users, config, password: null, id: Other, key: "sub-2", name: "bob");

        Assert.Equal(2, await sweep.SweepAsync());

        Assert.Equal(2, crypto.Hashed.Count);
        Assert.All(crypto.Hashed, plaintext => Assert.True(plaintext.Length >= 64, "provisioned password was too short: " + plaintext.Length.ToString(System.Globalization.CultureInfo.InvariantCulture)));
        Assert.NotEqual(crypto.Hashed[0], crypto.Hashed[1]);
    }

    [Fact]
    public async Task AnAccountThatAlreadyHasAPassword_IsLeftExactlyAsItWas()
    {
        // FAIL-SAFE. An administrator who deliberately set a real password on an SSO-linked account keeps
        // it; a sweep that overwrote one would lock that person out of their own account at a boot they did
        // not ask for, for a door that was already shut.
        var (sweep, config, users, crypto, audit) = Build();
        var user = LinkedUser(users, config, password: "an-administrator-set-this");

        Assert.Equal(0, await sweep.SweepAsync());

        Assert.Equal("an-administrator-set-this", user.Password);
        await users.DidNotReceive().UpdateUserAsync(Arg.Any<User>());
        Assert.Empty(crypto.Hashed);
        Assert.Empty(audit.Entries);
    }

    [Fact]
    public async Task TheSweep_NeverRepointsAnAccountsLoginProvider()
    {
        // FAIL-SAFE, and the near-miss somebody hardening this would actually make: also stamping the
        // SSO-managed provider id, on the reasoning that an SSO account should not have a password door at
        // all. That is this sweep deciding how another administrator's users log in, unattended, at boot,
        // for accounts they may have deliberately routed at a password provider. Writing the password shuts
        // the empty-password door on its own, which is the whole of what this is for.
        var (sweep, config, users, _, _) = Build();
        var user = LinkedUser(users, config, password: null);
        var routing = user.AuthenticationProviderId;

        Assert.Equal(1, await sweep.SweepAsync());

        Assert.Equal(routing, user.AuthenticationProviderId);
    }

    [Fact]
    public async Task AnAccountNoProviderLinksTo_IsLeftAlone()
    {
        // The link is the whole claim to act. A blank-password account an administrator made by hand is
        // theirs, not this plugin's to change, and a sweep that walked every user on the server would be
        // rewriting a password policy nobody asked it to hold.
        var (sweep, config, users, crypto, _) = Build();
        LinkedUser(users, config, password: null);
        var stranger = TestUsers.Named("carol", Other);
        users.GetUserById(Other).Returns(stranger);

        Assert.Equal(1, await sweep.SweepAsync());

        Assert.True(string.IsNullOrEmpty(stranger.Password));
        Assert.Single(crypto.Hashed);
    }

    [Fact]
    public async Task ASecondPass_WritesNothing()
    {
        // Idempotence, and it is what lets this run at every boot with no persisted "already done" flag.
        // The second pass finds the account holding the password the first one wrote and skips it.
        var (sweep, config, users, crypto, audit) = Build();
        LinkedUser(users, config, password: null);

        Assert.Equal(1, await sweep.SweepAsync());
        Assert.Equal(0, await sweep.SweepAsync());

        Assert.Single(crypto.Hashed);
        Assert.Single(audit.Entries, e => e.Message.Contains(SealAuditMarker, StringComparison.Ordinal));
    }

    [Fact]
    public async Task ALinkWhoseUserWasDeleted_SealsNobody_AndDoesNotStopThePass()
    {
        // A link can outlive the account it points at. That is nothing to do rather than something to force,
        // and it must not throw out of a pass that still has other accounts to walk after it.
        var (sweep, config, users, crypto, _) = Build();
        config.CanonicalLinks["sub-gone"] = Guid.Parse("33333333-3333-3333-3333-333333333333");
        var survivor = LinkedUser(users, config, password: null, id: Other, key: "sub-2", name: "bob");

        Assert.Equal(1, await sweep.SweepAsync());

        Assert.False(string.IsNullOrEmpty(survivor.Password));
        Assert.Single(crypto.Hashed);
    }

    [Fact]
    public async Task AnAccountLinkedFromTwoProviders_IsSealedOnce()
    {
        // One account, two identities. Two things make it one seal and they are worth separating, because
        // only one of them is visible in the count: the walk hands out a DEDUPLICATED set of ids, so the
        // account is resolved once - and even if it were not, the emptiness test would skip the second
        // visit. The resolve assertion below is what holds the first of those, since the seal count alone
        // cannot tell the two apart.
        var configuration = new PluginConfiguration();
        var oid = new OidConfig { Enabled = true };
        var saml = new SamlConfig { Enabled = true };
        configuration.OidConfigs["kc"] = oid;
        configuration.SamlConfigs["idp"] = saml;
        var (sweep, users, crypto, _) = BuildFor(configuration);
        var user = TestUsers.Named("alice", Linked);
        users.GetUserById(Linked).Returns(user);
        oid.CanonicalLinks["sub-1"] = Linked;
        saml.CanonicalLinks["nameid-1"] = Linked;

        Assert.Equal(1, await sweep.SweepAsync());

        Assert.Single(crypto.Hashed);
        await users.Received(1).UpdateUserAsync(user);
        users.Received(1).GetUserById(Linked);
    }

    [Fact]
    public async Task TheSamlPathIsSweptIdentically()
    {
        // One sweep over both protocols rather than one per protocol, so SAML cannot silently stop being
        // covered. This row is what would go red if the walk were ever narrowed to the OpenID providers.
        var configuration = new PluginConfiguration();
        var config = new SamlConfig { Enabled = true };
        configuration.SamlConfigs["idp"] = config;
        var (sweep, users, crypto, _) = BuildFor(configuration);
        var user = TestUsers.Named("bob", Linked);
        users.GetUserById(Linked).Returns(user);
        config.CanonicalLinks["nameid-1"] = Linked;

        Assert.Equal(1, await sweep.SweepAsync());

        Assert.False(string.IsNullOrEmpty(user.Password));
        Assert.Single(crypto.Hashed);
    }

    [Fact]
    public async Task ALinkOnADisabledProvider_IsStillSealed()
    {
        // The one deliberate difference from the expiry sweep, pinned so it cannot be "fixed" back. That one
        // ENDS access and refuses to do so unattended for a provider an administrator switched off. This one
        // only ever removes an empty-password door, and skipping a disabled provider would leave exactly the
        // accounts nobody is logging in through as the reachable ones.
        var (sweep, config, users, _, _) = Build();
        var user = LinkedUser(users, config, password: null);
        config.Enabled = false;

        Assert.Equal(1, await sweep.SweepAsync());

        Assert.False(string.IsNullOrEmpty(user.Password));
    }

    [Fact]
    public async Task TheAuditLine_CarriesACount_AndNothingThatNamesAnAccount()
    {
        // T-I1. An account that is currently reachable by anybody is the last thing to name in a log an
        // operator may paste into a bug report, so the line carries how many and nothing else.
        var (sweep, config, users, _, audit) = Build();
        LinkedUser(users, config, password: null);

        await sweep.SweepAsync();

        var line = Assert.Single(audit.Entries, e => e.Message.Contains(SealAuditMarker, StringComparison.Ordinal)).Message;
        Assert.Contains("1", line, StringComparison.Ordinal);
        Assert.DoesNotContain("alice", line, StringComparison.Ordinal);
        Assert.DoesNotContain("sub-1", line, StringComparison.Ordinal);
        Assert.DoesNotContain(Linked.ToString(), line, StringComparison.Ordinal);
    }

    [Fact]
    public async Task APassWithNothingToSeal_IsSilent()
    {
        // The shape of every server provisioned since v3.5.0.0, which is the overwhelming majority: the
        // sweep walks the links, finds every account already holding a password, and says nothing. A warning
        // on each of those boots would train an operator to ignore the one that matters.
        var (sweep, config, users, _, audit) = Build();
        LinkedUser(users, config, password: "already-sealed");

        Assert.Equal(0, await sweep.SweepAsync());
        Assert.Empty(audit.Entries);
    }

    // --- helpers ---

    private static (PasswordlessLinkedAccountSweep Sweep, OidConfig Config, IUserManager Users, RecordingCryptoProvider Crypto, CapturingLogger Audit) Build()
    {
        var configuration = new PluginConfiguration();
        var config = new OidConfig { Enabled = true };
        configuration.OidConfigs["kc"] = config;
        var (sweep, users, crypto, audit) = BuildFor(configuration);
        return (sweep, config, users, crypto, audit);
    }

    private static (PasswordlessLinkedAccountSweep Sweep, IUserManager Users, RecordingCryptoProvider Crypto, CapturingLogger Audit) BuildFor(PluginConfiguration configuration)
    {
        var users = Substitute.For<IUserManager>();
        var crypto = new RecordingCryptoProvider();
        var audit = new CapturingLogger();
        var store = new ProviderConfigStore(() => configuration, _ => { }, new CapturingLogger());
        var canonicalLinks = new CanonicalLinkService(users, crypto, store, new CapturingLogger());
        return (new PasswordlessLinkedAccountSweep(canonicalLinks, users, crypto, audit), users, crypto, audit);
    }

    // An account that already exists and is already linked - the state a login on an old plugin version left
    // behind. The sweep must never create or adopt anything; it only acts on what a login already wrote.
    private static User LinkedUser(IUserManager users, ProviderConfigBase config, string? password, Guid? id = null, string key = "sub-1", string name = "alice")
    {
        var userId = id ?? Linked;
        var user = TestUsers.Named(name, userId);
        user.Password = password;
        users.GetUserById(userId).Returns(user);
        config.CanonicalLinks[key] = userId;
        return user;
    }
}
