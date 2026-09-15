// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Jellyfin.Database.Implementations.Entities;
using Jellyfin.Plugin.SSO_Auth.Api.Linking;
using Jellyfin.Plugin.SSO_Auth.Api.Provider;
using Jellyfin.Plugin.SSO_Auth.Api.Session;
using Jellyfin.Plugin.SSO_Auth.Config;
using MediaBrowser.Controller.Library;
using NSubstitute;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// The manual-login door on an account this plugin provisions (#1440). Jellyfin creates a user with no
/// password, and a user with no password is reachable from the ordinary login form by submitting an empty
/// one - so an account created by an SSO login would be usable without the identity provider that is
/// supposed to be the only way in. <see cref="CanonicalLinkService"/> closes that door twice on the create
/// arm: it stamps an <c>AuthenticationProviderId</c> that resolves to no registered password provider, and
/// it stores a hash of 64 cryptographically random bytes. Both were unproven until these tests; each one
/// here reddens when its line is deleted, which is the only reason to believe either is load-bearing.
/// </summary>
public class ProvisionedAccountPasswordDoorTests
{
    private static readonly Guid Created = Guid.Parse("44444444-4444-4444-4444-444444444444");
    private static readonly Guid Second = Guid.Parse("55555555-5555-5555-5555-555555555555");

    private static (CanonicalLinkService Service, IUserManager Users, RecordingCryptoProvider Crypto) Build(Action<PluginConfiguration>? seed = null)
    {
        var cfg = new PluginConfiguration();
        seed?.Invoke(cfg);
        var store = new ProviderConfigStore(() => cfg, _ => { }, new CapturingLogger());
        var users = Substitute.For<IUserManager>();
        var crypto = new RecordingCryptoProvider();
        return (new CanonicalLinkService(users, crypto, store, new CapturingLogger()), users, crypto);
    }

    private static User ExpectCreate(IUserManager users, string name, Guid id)
    {
        var created = TestUsers.Named(name, id);
        users.GetUserByName(name).Returns((User?)null);
        users.CreateUserAsync(name).Returns(created);
        users.GetUserById(id).Returns(created);
        return created;
    }

    [Fact]
    public async Task NewAccount_IsStampedOffJellyfinsNativePasswordProvider()
    {
        // The first of the two doors. The stamped id is deliberately one that resolves to no registered
        // IAuthenticationProvider, so core substitutes its InvalidAuthenticationProvider and rejects every
        // password attempt on the account - including the empty one the login form will happily post.
        var (service, users, _) = Build(c => c.OidConfigs["kc"] = new OidConfig { Enabled = true });
        var created = ExpectCreate(users, "alice", Created);

        await service.ResolveOrCreateAsync(ProviderMode.Oid, "kc", "sub-1", "alice", allowExistingAccountLink: false);

        Assert.Equal(SsoManagedProviderId.Value, created.AuthenticationProviderId);
        Assert.False(SsoAuthenticationProviders.IsDefaultPasswordProvider(created.AuthenticationProviderId));
    }

    [Fact]
    public async Task NewAccount_GetsAStoredPasswordAndItIsNotTheEmptyOne()
    {
        // The second door, and the one that still holds if an administrator later points the account back
        // at the native password provider: the stored hash is of a long random string, so the empty
        // password that reaches the login form does not verify against it.
        var (service, users, crypto) = Build(c => c.OidConfigs["kc"] = new OidConfig { Enabled = true });
        var created = ExpectCreate(users, "alice", Created);

        await service.ResolveOrCreateAsync(ProviderMode.Oid, "kc", "sub-1", "alice", allowExistingAccountLink: false);

        var plaintext = Assert.Single(crypto.Hashed);
        Assert.False(string.IsNullOrWhiteSpace(plaintext));

        // 64 random bytes in base64. Asserted as a floor rather than as the exact length so a future move to
        // a different encoding of the same entropy does not redden a test about the door being shut.
        Assert.True(plaintext.Length >= 64, "provisioned password was " + plaintext.Length.ToString(System.Globalization.CultureInfo.InvariantCulture) + " characters");
        Assert.False(string.IsNullOrEmpty(created.Password));
    }

    [Fact]
    public async Task TwoNewAccounts_DoNotShareAPassword()
    {
        // A constant password would satisfy the test above and would be worth exactly nothing: one leak, or
        // one reading of the source, opens every account the plugin has ever created. This is the test that
        // separates "a password was set" from "a random password was set".
        var (service, users, crypto) = Build(c => c.OidConfigs["kc"] = new OidConfig { Enabled = true });
        var alice = ExpectCreate(users, "alice", Created);
        var bob = ExpectCreate(users, "bob", Second);

        await service.ResolveOrCreateAsync(ProviderMode.Oid, "kc", "sub-1", "alice", allowExistingAccountLink: false);
        await service.ResolveOrCreateAsync(ProviderMode.Oid, "kc", "sub-2", "bob", allowExistingAccountLink: false);

        Assert.Equal(2, crypto.Hashed.Count);
        Assert.NotEqual(crypto.Hashed[0], crypto.Hashed[1]);
        Assert.NotEqual(alice.Password, bob.Password);
    }

    [Fact]
    public async Task PendingApprovalAccount_IsPersistedWithBothDoorsAlreadyShut()
    {
        // The pending-approval arm (#737) short-circuits before the session minter and persists the account
        // itself, so it is the one arm where the plugin writes a brand-new account to the database and then
        // refuses the login. An account left sitting there for an administrator to approve must not be the
        // one that is reachable without the identity provider in the meantime.
        var (service, users, _) = Build(c => c.OidConfigs["kc"] = new OidConfig { Enabled = true });
        var created = ExpectCreate(users, "alice", Created);
        User? persisted = null;
        users.UpdateUserAsync(Arg.Do<User>(u => persisted = u)).Returns(Task.CompletedTask);

        await service.ResolveOrCreateAsync(ProviderMode.Oid, "kc", "sub-1", "alice", allowExistingAccountLink: false, provisionDisabled: true);

        Assert.Same(created, persisted);
        Assert.Equal(SsoManagedProviderId.Value, persisted!.AuthenticationProviderId);
        Assert.False(string.IsNullOrEmpty(persisted.Password));
    }

    [Fact]
    public async Task AlreadyLinkedAccount_KeepsItsOwnPasswordAndProviderRouting()
    {
        // The fail-safe in the other direction, and the reason the two writes live on the create arm rather
        // than on every login. An account that already exists may belong to an administrator who
        // deliberately left it on the native password provider; a login that resolves it must not lock that
        // owner out by re-routing it or by overwriting the password they chose.
        var (service, users, crypto) = Build(c => c.OidConfigs["kc"] = new OidConfig
        {
            Enabled = true,
            CanonicalLinks = new SerializableDictionary<string, Guid> { ["sub-1"] = Created },
        });
        var existing = TestUsers.Named("alice", Created);
        existing.AuthenticationProviderId = SsoAuthenticationProviders.DefaultPasswordProviderId;
        existing.Password = "the-hash-the-owner-chose";
        users.GetUserById(Created).Returns(existing);

        await service.ResolveOrCreateAsync(ProviderMode.Oid, "kc", "sub-1", "alice", allowExistingAccountLink: false);

        Assert.Empty(crypto.Hashed);
        Assert.Equal(SsoAuthenticationProviders.DefaultPasswordProviderId, existing.AuthenticationProviderId);
        Assert.Equal("the-hash-the-owner-chose", existing.Password);
        await users.DidNotReceive().CreateUserAsync(Arg.Any<string>());
    }

    // ---- #1733: which of the two identical-looking stored hashes this plugin wrote ----------------------
    //
    // Both doors above are about SHUTTING the account. These are about the plugin being able to say
    // afterwards that it was the one who shut it. Without that, a stored hash is a credential somebody
    // holds or a seal nobody can open, the bytes are the same either way, and every guard asking "does
    // this account have a password door" has to guess - which on a server whose provider DefaultProvider
    // names Jellyfin's own password provider means guessing wrong for every account the plugin made.

    [Fact]
    public async Task NewAccount_ItsMintedPasswordIsRecordedAgainstIt()
    {
        var (service, users, _, config) = BuildWithConfig(c => c.OidConfigs["kc"] = new OidConfig { Enabled = true });
        var created = ExpectCreate(users, "alice", Created);

        await service.ResolveOrCreateAsync(ProviderMode.Oid, "kc", "sub-1", "alice", allowExistingAccountLink: false);

        Assert.True(config.ProvisionedPasswords.ContainsKey(created.Id));
        Assert.True(service.HoldsOnlyAProvisionedPassword(created));
    }

    [Fact]
    public async Task AnAccountWhosePasswordWasReplacedAfterwards_StopsReadingAsSealed()
    {
        // THE REASON THE RECORD IS A FINGERPRINT AND NOT A FLAG, and the case that decides it. An owner who
        // sets a real password on an account this plugin provisioned holds a way in from that moment. A
        // flag saying "provisioned" would go on claiming otherwise for ever, and the guard reading it would
        // refuse a user who is in no danger at all - the cost #1733 declined to impose on anybody. Nothing
        // has to notice the password change for this to work: the recorded digest simply stops matching.
        var (service, users, _, _) = BuildWithConfig(c => c.OidConfigs["kc"] = new OidConfig { Enabled = true });
        var created = ExpectCreate(users, "alice", Created);

        await service.ResolveOrCreateAsync(ProviderMode.Oid, "kc", "sub-1", "alice", allowExistingAccountLink: false);
        Assert.True(service.HoldsOnlyAProvisionedPassword(created));

        created.Password = "the-hash-of-a-password-its-owner-chose";

        Assert.False(service.HoldsOnlyAProvisionedPassword(created));
    }

    [Fact]
    public void AnAccountTheRecordDoesNotName_ReadsAsHoldingItsOwnPassword()
    {
        // The residual, pinned rather than hidden: an account sealed by a plugin version that kept no
        // record reads exactly as it did before #1733. That is the safe direction - a refusal that does
        // not fire costs a user nothing they had, where a wrong refusal costs them their own control - and
        // it is the answer this test exists to keep from drifting into "unknown means sealed".
        var (service, _, _, _) = BuildWithConfig();
        var stranger = TestUsers.Named("carol", Second);
        stranger.Password = "some-hash-this-plugin-never-wrote";

        Assert.False(service.HoldsOnlyAProvisionedPassword(stranger));
    }

    [Fact]
    public void AnAccountWithNoStoredPasswordAtAll_IsNotRecordedAndDoesNotReadAsSealed()
    {
        // An empty password is an OPEN door rather than a sealed one - it is the exact state the boot-time
        // sweep exists to end - so neither half may treat it as a seal: nothing is recorded for it, and it
        // reads false even if a record somehow named it.
        var (service, _, _, config) = BuildWithConfig();
        var user = TestUsers.Named("dave", Created);

        service.UpdateProvisionedPasswords(new Dictionary<Guid, string> { [user.Id] = string.Empty }, Array.Empty<Guid>());

        Assert.False(config.ProvisionedPasswords.ContainsKey(user.Id));
        Assert.False(service.HoldsOnlyAProvisionedPassword(user));
    }

    [Fact]
    public void TheRecordIsDroppedWhenTheAccountIsForgotten()
    {
        // A record outliving its account would describe whichever account a recycled id names next, which
        // is the whole class #1649 closed for the link maps.
        var (service, _, _, config) = BuildWithConfig();
        var user = TestUsers.Named("erin", Created);
        user.Password = "hash";
        service.UpdateProvisionedPasswords(new Dictionary<Guid, string> { [user.Id] = user.Password }, Array.Empty<Guid>());
        Assert.True(service.HoldsOnlyAProvisionedPassword(user));

        Assert.True(service.ForgetProvisionedPassword(user.Id));

        Assert.False(config.ProvisionedPasswords.ContainsKey(user.Id));
        Assert.False(service.HoldsOnlyAProvisionedPassword(user));
    }

    [Fact]
    public void TheDeletionFootprint_AnswersBothQuestionsInOneConfigurationAcquisition()
    {
        // The no-write guard the deletion consumer depends on, and the reason both questions are asked
        // together. Most deleted accounts hold neither a link nor a record, and an unguarded forget would
        // turn every account deletion on the server into a configuration write; a SECOND read to find that
        // out would be paid by every deletion too. The counter below is the whole assertion.
        var acquisitions = 0;
        var cfg = new PluginConfiguration();
        cfg.OidConfigs["kc"] = new OidConfig { Enabled = true, CanonicalLinks = new SerializableDictionary<string, Guid> { ["sub-1"] = Created } };
        cfg.ProvisionedPasswords[Created] = "a-digest";
        var store = new ProviderConfigStore(
            () =>
            {
                acquisitions++;
                return cfg;
            },
            _ => { },
            new CapturingLogger());
        var service = new CanonicalLinkService(Substitute.For<IUserManager>(), new RecordingCryptoProvider(), store, new CapturingLogger());

        var linked = service.DeletionFootprint(Created);
        var stranger = service.DeletionFootprint(Second);

        Assert.True(linked.HoldsLink);
        Assert.True(linked.HoldsMintedPasswordRecord);
        Assert.False(stranger.HoldsLink);
        Assert.False(stranger.HoldsMintedPasswordRecord);
        Assert.Equal(2, acquisitions);
    }

    private static (CanonicalLinkService Service, IUserManager Users, RecordingCryptoProvider Crypto, PluginConfiguration Config) BuildWithConfig(Action<PluginConfiguration>? seed = null)
    {
        // The same rig as Build above, with the configuration handed back: the #1733 cases assert on what
        // the store now holds rather than only on what the account object carries.
        var cfg = new PluginConfiguration();
        seed?.Invoke(cfg);
        var store = new ProviderConfigStore(() => cfg, _ => { }, new CapturingLogger());
        var users = Substitute.For<IUserManager>();
        var crypto = new RecordingCryptoProvider();
        return (new CanonicalLinkService(users, crypto, store, new CapturingLogger()), users, crypto, cfg);
    }
}
