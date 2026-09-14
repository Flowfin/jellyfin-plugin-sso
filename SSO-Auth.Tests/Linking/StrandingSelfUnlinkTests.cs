// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using Jellyfin.Plugin.SSO_Auth.Api;
using Jellyfin.Plugin.SSO_Auth.Api.Linking;
using Jellyfin.Plugin.SSO_Auth.Api.Provider;
using Jellyfin.Plugin.SSO_Auth.Config;
using MediaBrowser.Controller.Library;
using NSubstitute;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// A holder may not strand their own account (#1720). On a server where the account's authentication
/// provider is this plugin's, Jellyfin refuses its password, so the links ARE the only way in - and the
/// self-service Delete removed the last one with no warning and no fallback, leaving the owner unable to
/// sign in by any means and recoverable only by an administrator. The removal now asks, inside the
/// transaction that removes, whether this is the last link on an account with no password door.
/// <para>
/// AN ADMINISTRATOR IS EXEMPT ONLY FOR SOMEBODY ELSE'S LINK (#1732, decided 2026-09-14). The page acts on
/// the caller's own account, so an administrator who opens it strands themselves exactly as a user does -
/// and where they are the last administrator who can sign in, the recovery the user's refusal points at is
/// them and the way back is editing the configuration file on disk. The exemption is therefore a pair of
/// facts: the caller is not the holder, or somebody else can still get in.
/// </para>
/// </summary>
/// <remarks>
/// EVERY REFUSAL ARM IS PAIRED WITH THE CASE THAT MUST STILL GO THROUGH. A guard on a destructive action
/// is as wrong when it refuses too much as when it refuses too little: this one sits on the only control a
/// user has for unlinking themselves, and a version that refused every self-unlink would take that control
/// away from every account on every server, most of which accept a password perfectly well.
/// </remarks>
public class StrandingSelfUnlinkTests
{
    private static readonly Guid Holder = Guid.Parse("22222222-2222-2222-2222-222222222222");
    private static readonly Guid Other = Guid.Parse("33333333-3333-3333-3333-333333333333");

    [Fact]
    public void TheHolderOfTheLastLink_OnAnAccountWithNoPassword_IsRefused_AndNothingIsTouched()
    {
        var (service, config) = Build();

        var removal = service.TryRemoveLink(ProviderMode.Oid, "kc", "sub-1", Holder, passwordLoginDisabled: true);

        Assert.Equal(CanonicalLinkRemoveResult.WouldStrandAccount, removal.Result);
        // A no-op outcome, so the retains flag is the undefined-and-false the record's contract names for
        // every outcome but Removed - the same shape the time-limited refusal beside it takes.
        Assert.False(removal.UserRetainsAnyLink);
        Assert.Equal(Holder, config.CanonicalLinks["sub-1"]);
    }

    [Fact]
    public void TheHolderOfTheLastLink_OnAnAccountThatTakesAPassword_StillRemovesIt()
    {
        // The bound of the rule, and the half that matters most: on an ordinary server the account keeps a
        // password, so unlinking the last provider is not a lockout and the control stays the user's.
        var (service, config) = Build();

        var removal = service.TryRemoveLink(ProviderMode.Oid, "kc", "sub-1", Holder, passwordLoginDisabled: false);

        Assert.Equal(CanonicalLinkRemoveResult.Removed, removal.Result);
        Assert.False(removal.UserRetainsAnyLink);
        Assert.False(config.CanonicalLinks.ContainsKey("sub-1"));
    }

    [Fact]
    public void TheHolderOfANonLastLink_OnAnAccountWithNoPassword_StillRemovesIt()
    {
        // A second link on another provider is a way in, so removing one of them strands nobody. Without
        // this arm the guard could refuse every self-unlink on an SSO-only server and still pass the first.
        var (service, config) = Build(second: true);

        var removal = service.TryRemoveLink(ProviderMode.Oid, "kc", "sub-1", Holder, passwordLoginDisabled: true);

        Assert.Equal(CanonicalLinkRemoveResult.Removed, removal.Result);
        Assert.True(removal.UserRetainsAnyLink);
        Assert.False(config.CanonicalLinks.ContainsKey("sub-1"));
    }

    [Fact]
    public void AnAdministrator_RemovesTheLastLinkOfSomebodyElsesPasswordlessAccount()
    {
        // An administrator removing SOMEBODY ELSE's last link is a deliberate act with a person behind it,
        // and the Unregister route beside it repoints that account back to password sign-in, so the way back
        // is one elevated call. That is the act #1720 decided the exemption for, and it is named in the
        // arguments now rather than assumed: the exemption is a pair of facts since #1732, and an arm that
        // left the second one to its default would be asserting the opposite case.
        var (service, config) = Build();

        var removal = service.TryRemoveLink(ProviderMode.Oid, "kc", "sub-1", Holder, callerIsAdministrator: true, passwordLoginDisabled: true, callerIsTheHolder: false);

        Assert.Equal(CanonicalLinkRemoveResult.Removed, removal.Result);
        Assert.False(config.CanonicalLinks.ContainsKey("sub-1"));
    }

    [Fact]
    public void AnAdministratorOnTheirOwnLastLink_WithNobodyElseAbleToSignIn_IsRefused()
    {
        // THE CASE #1732 DECIDED. `/SSOViews/linking` acts on the caller's own account, so an administrator
        // who opens it on an SSO-only server is one press from the lockout the guard exists for - with the
        // difference that the recovery the user's refusal points at IS them. Where they are the last
        // administrator who can sign in, what is left is editing the configuration file on disk.
        var (service, config) = Build();

        var removal = service.TryRemoveLink(ProviderMode.Oid, "kc", "sub-1", Holder, callerIsAdministrator: true, passwordLoginDisabled: true, callerIsTheHolder: true, anotherAdministratorKeepsAWayIn: false);

        Assert.Equal(CanonicalLinkRemoveResult.WouldStrandAccount, removal.Result);
        Assert.False(removal.UserRetainsAnyLink);
        Assert.Equal(Holder, config.CanonicalLinks["sub-1"]);
    }

    [Fact]
    public void AnAdministratorOnTheirOwnLastLink_WithAnotherAdministratorAbleToSignIn_StillRemovesIt()
    {
        // The bound of the narrowing, and the reason the other two shapes were declined on the issue. An
        // administrator is also the person who legitimately cleans up - a provider retired, a link moved to
        // a new issuer, a test account tidied away - and refusing every such removal would take that from
        // every server, including the ones where a second administrator stands ready. Without this arm the
        // rule could refuse every administrator's self-unlink and still pass the one above.
        var (service, config) = Build();

        var removal = service.TryRemoveLink(ProviderMode.Oid, "kc", "sub-1", Holder, callerIsAdministrator: true, passwordLoginDisabled: true, callerIsTheHolder: true, anotherAdministratorKeepsAWayIn: true);

        Assert.Equal(CanonicalLinkRemoveResult.Removed, removal.Result);
        Assert.False(config.CanonicalLinks.ContainsKey("sub-1"));
    }

    [Fact]
    public void AnAdministratorOnTheirOwnAccount_WhoKeepsAnotherLink_StillRemovesIt()
    {
        // The last-link half still governs the narrowed case. An administrator alone on the server who holds
        // a second link on an enabled provider is not stranding anybody, so the fact that nobody else can
        // sign in decides nothing here - without this arm the new condition could refuse every administrator
        // self-unlink on a single-administrator server, which is not what was decided.
        var (service, config) = Build(second: true);

        var removal = service.TryRemoveLink(ProviderMode.Oid, "kc", "sub-1", Holder, callerIsAdministrator: true, passwordLoginDisabled: true, callerIsTheHolder: true, anotherAdministratorKeepsAWayIn: false);

        Assert.Equal(CanonicalLinkRemoveResult.Removed, removal.Result);
        Assert.True(removal.UserRetainsAnyLink);
        Assert.False(config.CanonicalLinks.ContainsKey("sub-1"));
    }

    [Fact]
    public void AnAdministratorOnTheirOwnAccount_ThatTakesAPassword_StillRemovesIt()
    {
        // The password half governs the narrowed case too, and it is the same bound the holder's arm has.
        // An administrator whose own account accepts a password is not stranded by losing a link, however
        // alone they are on the server.
        var (service, config) = Build();

        var removal = service.TryRemoveLink(ProviderMode.Oid, "kc", "sub-1", Holder, callerIsAdministrator: true, passwordLoginDisabled: false, callerIsTheHolder: true, anotherAdministratorKeepsAWayIn: false);

        Assert.Equal(CanonicalLinkRemoveResult.Removed, removal.Result);
        Assert.False(config.CanonicalLinks.ContainsKey("sub-1"));
    }

    [Fact]
    public void AnAdministratorsDefault_IsTreatedAsActingOnTheirOwnAccountWithNobodyLeft()
    {
        // The two facts #1732 added default to the case that costs the server, the way the two before them
        // default to the case that costs the account. A call site that passes only `callerIsAdministrator`
        // is a call site that has not been told about this rule, and it refuses a removal rather than
        // performing a lockout nobody asked for.
        var (service, _) = Build();

        Assert.Equal(
            CanonicalLinkRemoveResult.WouldStrandAccount,
            service.TryRemoveLink(ProviderMode.Oid, "kc", "sub-1", Holder, callerIsAdministrator: true, passwordLoginDisabled: true).Result);
    }

    [Fact]
    public void AnotherAccountsLink_DoesNotCountAsThisHoldersWayIn()
    {
        // The count is per user. A busy provider holding many links must not read as "this account keeps
        // one", which is the arithmetic slip that would turn the guard off on exactly the servers where it
        // matters most.
        var (service, config) = Build(foreign: true);

        var removal = service.TryRemoveLink(ProviderMode.Oid, "kc", "sub-1", Holder, passwordLoginDisabled: true);

        Assert.Equal(CanonicalLinkRemoveResult.WouldStrandAccount, removal.Result);
        Assert.Equal(Holder, config.CanonicalLinks["sub-1"]);
        Assert.Equal(Other, config.CanonicalLinks["sub-2"]);
    }

    [Fact]
    public void ALinkOnADisabledProvider_IsNotAWayIn()
    {
        // THE ARM THAT PINNED THE OPPOSITE UNTIL THE REVIEW OF #1720. It said a remaining link counted
        // wherever it sat, on the any-link reading the revoke uses, and the case that refutes it is the
        // ordinary migration: an administrator stands up the new provider, switches the old one off
        // rather than deleting it, and the account now holds two links of which exactly one can sign
        // anybody in. Removing that one is the lockout this guard exists for, and the old reading let it
        // through while reporting that the holder still had a way in - which also skipped the last-link
        // revoke, so the session stayed alive and the lockout surfaced hours later at token expiry.
        var (service, config) = Build(second: true, secondEnabled: false);

        var removal = service.TryRemoveLink(ProviderMode.Oid, "kc", "sub-1", Holder, passwordLoginDisabled: true);

        Assert.Equal(CanonicalLinkRemoveResult.WouldStrandAccount, removal.Result);
        Assert.Equal(Holder, config.CanonicalLinks["sub-1"]);
    }

    [Fact]
    public void TheSoleLinkOnADisabledProvider_IsStillRemovable()
    {
        // The other direction of the same reading, and it fails the other way. A link that cannot sign
        // anybody in is not a way in, so removing it takes nothing away - refusing here would take the
        // documented disable-then-clean-up workflow (#380) away from exactly the accounts this rule
        // protects, and would tell them a removal costs them something they never had.
        var configuration = new PluginConfiguration();
        var off = new OidConfig { Enabled = false };
        off.CanonicalLinks["sub-old"] = Holder;
        configuration.OidConfigs["retired"] = off;

        var removal = ServiceFor(configuration).TryRemoveLink(ProviderMode.Oid, "retired", "sub-old", Holder, passwordLoginDisabled: true);

        Assert.Equal(CanonicalLinkRemoveResult.Removed, removal.Result);
        Assert.False(off.CanonicalLinks.ContainsKey("sub-old"));
    }

    [Fact]
    public void TheSamlArm_RefusesTheHolderIdentically()
    {
        // The rule is about the account, not about a protocol, so the SAML map is walked by the same count.
        var configuration = new PluginConfiguration();
        var saml = new SamlConfig { Enabled = true };
        saml.CanonicalLinks["nameid-1"] = Holder;
        configuration.SamlConfigs["idp"] = saml;

        var removal = ServiceFor(configuration).TryRemoveLink(ProviderMode.Saml, "idp", "nameid-1", Holder, passwordLoginDisabled: true);

        Assert.Equal(CanonicalLinkRemoveResult.WouldStrandAccount, removal.Result);
        Assert.Equal(Holder, saml.CanonicalLinks["nameid-1"]);
    }

    [Fact]
    public void TheRefusalComesAfterTheOwnershipCheck()
    {
        // A link registered to somebody else answers Mismatch rather than this refusal, so the guard cannot
        // become an oracle for "that account has no password" against a link the caller does not hold.
        var (service, _) = Build();

        var removal = service.TryRemoveLink(ProviderMode.Oid, "kc", "sub-1", Other, passwordLoginDisabled: true);

        Assert.Equal(CanonicalLinkRemoveResult.Mismatch, removal.Result);
    }

    [Fact]
    public void ALinkCarryingADeadline_StillAnswersTimeLimited()
    {
        // Both refusals apply to this removal and the deadline's answer is the one that survives, because
        // it names the thing an administrator has to act on. Pinned so a later edit cannot reorder the two
        // without saying so.
        var (service, config) = Build();
        config.CanonicalLinkDeadlines["sub-1"] = new DateTime(2026, 9, 20, 0, 0, 0, DateTimeKind.Utc);

        var removal = service.TryRemoveLink(ProviderMode.Oid, "kc", "sub-1", Holder, passwordLoginDisabled: true);

        Assert.Equal(CanonicalLinkRemoveResult.TimeLimited, removal.Result);
    }

    [Fact]
    public void TheDefault_Refuses()
    {
        // A caller that says nothing about the account's door is treated as the case that costs the
        // account, the way a caller that says nothing about being an administrator is treated as the
        // holder. A future call site that forgets the argument refuses a removal rather than performing a
        // lockout nobody asked for.
        var (service, _) = Build();

        Assert.Equal(CanonicalLinkRemoveResult.WouldStrandAccount, service.TryRemoveLink(ProviderMode.Oid, "kc", "sub-1", Holder).Result);
    }

    private static CanonicalLinkService ServiceFor(PluginConfiguration configuration)
    {
        var users = Substitute.For<IUserManager>();
        users.GetUserById(Holder).Returns(TestUsers.Named("alice", Holder));
        var store = new ProviderConfigStore(() => configuration, _ => { }, new CapturingLogger());
        return new CanonicalLinkService(users, new FakeCryptoProvider(), store, new CapturingLogger());
    }

    /// <summary>
    /// One OpenID provider holding the holder's only link, plus whichever neighbour an arm needs.
    /// </summary>
    private static (CanonicalLinkService Service, OidConfig Config) Build(bool second = false, bool secondEnabled = true, bool foreign = false)
    {
        var configuration = new PluginConfiguration();
        var config = new OidConfig { Enabled = true };
        config.CanonicalLinks["sub-1"] = Holder;
        if (foreign)
        {
            config.CanonicalLinks["sub-2"] = Other;
        }

        configuration.OidConfigs["kc"] = config;

        if (second)
        {
            var other = new OidConfig { Enabled = secondEnabled };
            other.CanonicalLinks["sub-elsewhere"] = Holder;
            configuration.OidConfigs["second"] = other;
        }

        return (ServiceFor(configuration), config);
    }
}
