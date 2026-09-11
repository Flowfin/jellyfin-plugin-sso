// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Threading.Tasks;
using Jellyfin.Data.Events.Users;
using Jellyfin.Plugin.SSO_Auth.Api.Linking;
using Jellyfin.Plugin.SSO_Auth.Config;
using MediaBrowser.Controller.Library;
using Microsoft.Extensions.Logging;
using NSubstitute;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// A deleted Jellyfin account takes its links with it (#1649). The host publishes its deletion, and this
/// plugin's consumer removes every link the account held on both protocols, with the deadline, the stamp
/// and the pending-approval record that hung off them, and writes one audit line naming the providers and
/// the account id and never the subject. Nothing it does may reach the host's delete: a store that throws
/// is a warning, not a failure the host sees.
/// </summary>
public class DeletedAccountLinkPrunerTests
{
    private static readonly Guid Gone = Guid.Parse("11111111-1111-1111-1111-111111111111");
    private static readonly Guid Other = Guid.Parse("22222222-2222-2222-2222-222222222222");
    private static readonly DateTime Now = new(2026, 9, 11, 9, 0, 0, DateTimeKind.Utc);

    [Fact]
    public async Task ADeletedAccount_LosesEveryLinkAndEverythingThatHungOffThem()
    {
        var (pruner, configuration, _) = Build();
        var oid = configuration.OidConfigs["kc"];
        var saml = configuration.SamlConfigs["idp"];

        await pruner.OnEvent(new UserDeletedEventArgs(TestUsers.Named("alice", Gone)));

        Assert.False(oid.CanonicalLinks.ContainsKey("sub-gone"));
        Assert.False(saml.CanonicalLinks.ContainsKey("nameid-gone"));
        Assert.Empty(oid.CanonicalLinkDeadlines);
        Assert.Empty(oid.CanonicalLinkLastLogins);
        Assert.Empty(oid.CanonicalLinkPendingApprovals);
        Assert.Empty(oid.CanonicalLinkIssuers);

        // The neighbour is untouched: this is keyed on the deleted account, not a sweep.
        Assert.Equal(Other, oid.CanonicalLinks["sub-other"]);
    }

    [Fact]
    public async Task TheAuditLine_NamesTheProvidersAndTheAccount_AndNotTheSubject()
    {
        var (pruner, _, audit) = Build();

        await pruner.OnEvent(new UserDeletedEventArgs(TestUsers.Named("alice", Gone)));

        var entry = Assert.Single(audit.Entries, e => e.Message.Contains("was deleted", StringComparison.Ordinal));
        Assert.Equal(LogLevel.Warning, entry.Level);
        Assert.Contains("[SSO Audit]", entry.Message, StringComparison.Ordinal);
        Assert.Contains(Gone.ToString(), entry.Message, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("its 2 SSO link(s) from", entry.Message, StringComparison.Ordinal);
        Assert.Contains("OpenID 'kc'", entry.Message, StringComparison.Ordinal);
        Assert.Contains("SAML 'idp'", entry.Message, StringComparison.Ordinal);
        Assert.DoesNotContain("sub-gone", entry.Message, StringComparison.Ordinal);
        Assert.DoesNotContain("nameid-gone", entry.Message, StringComparison.Ordinal);
        Assert.DoesNotContain("alice", entry.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task TheAuditLine_NamesWhatTheRemovalRemoved_NotWhatTheReadBeforeItSaw()
    {
        // The read before the removal is only the no-write guard; the names come from inside the removal's
        // own lock. Proven by moving the ground between the two: the store hands the configuration out once
        // per lock acquisition, the guard's read is the first, and every acquisition after it finds the
        // OpenID link gone - the way an administrator's Unregister racing the host's delete would take it.
        // The removal then finds one link, and that is the one the line must name; a line built from the
        // guard's read would name both providers here.
        var audit = new CapturingLogger();
        var configuration = Seeded();
        var acquisitions = 0;
        var store = new ProviderConfigStore(
            () =>
            {
                if (++acquisitions > 1)
                {
                    configuration.OidConfigs["kc"].CanonicalLinks.Remove("sub-gone");
                }

                return configuration;
            },
            _ => { },
            new CapturingLogger());
        var links = new CanonicalLinkService(Substitute.For<IUserManager>(), new FakeCryptoProvider(), store, new CapturingLogger(), clock: () => Now);
        var pruner = new DeletedAccountLinkPruner(() => links, audit);

        await pruner.OnEvent(new UserDeletedEventArgs(TestUsers.Named("alice", Gone)));

        // One read for the guard and one acquisition for the removal, and none of its own for the names: a
        // build that read them in between would produce this very line, and only the count tells it apart.
        Assert.Equal(2, acquisitions);
        var entry = Assert.Single(audit.Entries, e => e.Message.Contains("was deleted", StringComparison.Ordinal));
        Assert.Contains("its 1 SSO link(s) from SAML 'idp'.", entry.Message, StringComparison.Ordinal);
        Assert.DoesNotContain("kc", entry.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task AnAccountWithNoLinks_LeavesNoLineAndWritesNothing()
    {
        // Most deleted accounts never had an SSO link, and this plugin's own create arm deletes the account
        // it just made when a login fails after creating it. Neither may cost a configuration write, and
        // neither may leave a line: the store here throws on persist, so a write would surface as the
        // warning, and the assertion is on EVERY entry rather than on the audit marker alone.
        var audit = new CapturingLogger();
        var configuration = Seeded();
        var store = new ProviderConfigStore(() => configuration, _ => throw new System.IO.IOException("disk full"), new CapturingLogger());
        var links = new CanonicalLinkService(Substitute.For<IUserManager>(), new FakeCryptoProvider(), store, new CapturingLogger(), clock: () => Now);
        var pruner = new DeletedAccountLinkPruner(() => links, audit);

        await pruner.OnEvent(new UserDeletedEventArgs(TestUsers.Named("nobody", Guid.NewGuid())));

        Assert.Empty(audit.Entries);
        Assert.Equal(Gone, configuration.OidConfigs["kc"].CanonicalLinks["sub-gone"]);
    }

    [Fact]
    public async Task AStoreThatThrows_IsAWarning_AndNeverReachesTheHost()
    {
        // The host's delete has already happened. A persist that fails is bookkeeping the next login of
        // the same subject cleans up on its own, and the warning names the account id and nothing else.
        var audit = new CapturingLogger();
        var configuration = Seeded();
        var store = new ProviderConfigStore(() => configuration, _ => throw new System.IO.IOException("disk full"), new CapturingLogger());
        var links = new CanonicalLinkService(Substitute.For<IUserManager>(), new FakeCryptoProvider(), store, new CapturingLogger(), clock: () => Now);
        var pruner = new DeletedAccountLinkPruner(() => links, audit);

        await pruner.OnEvent(new UserDeletedEventArgs(TestUsers.Named("alice", Gone)));

        var warning = Assert.Single(audit.Entries, e => e.Message.Contains("Could not remove", StringComparison.Ordinal));
        Assert.Equal(LogLevel.Warning, warning.Level);
        Assert.DoesNotContain("alice", warning.Message, StringComparison.Ordinal);
        Assert.DoesNotContain("sub-gone", warning.Message, StringComparison.Ordinal);

        // Nothing was reported as removed, and the link is where it was: the store put its snapshot back
        // before rethrowing, which is what makes the warning's "its links stay" true.
        Assert.DoesNotContain(audit.Entries, e => e.Message.Contains("[SSO Audit]", StringComparison.Ordinal));
        Assert.Equal(Gone, configuration.OidConfigs["kc"].CanonicalLinks["sub-gone"]);
    }

    [Fact]
    public async Task WhileThePluginIsNotUp_NothingHappens()
    {
        var audit = new CapturingLogger();
        var pruner = new DeletedAccountLinkPruner(() => null, audit);

        await pruner.OnEvent(new UserDeletedEventArgs(TestUsers.Named("alice", Gone)));

        Assert.Empty(audit.Entries);
    }

    // One OpenID and one SAML provider, the deleted account linked on both with everything a link can
    // carry, and a neighbour on the OpenID provider that must survive.
    private static PluginConfiguration Seeded()
    {
        var configuration = new PluginConfiguration();
        var oid = new OidConfig { Enabled = true };
        oid.CanonicalLinks["sub-gone"] = Gone;
        oid.CanonicalLinks["sub-other"] = Other;
        oid.CanonicalLinkIssuers["sub-gone"] = "https://id.example.com";
        oid.CanonicalLinkDeadlines["sub-gone"] = Now + TimeSpan.FromHours(4);
        oid.CanonicalLinkLastLogins["sub-gone"] = Now;
        oid.CanonicalLinkPendingApprovals["sub-gone"] = new PendingApproval { UserId = Gone, SinceUtc = Now };
        configuration.OidConfigs["kc"] = oid;
        var saml = new SamlConfig { Enabled = true };
        saml.CanonicalLinks["nameid-gone"] = Gone;
        configuration.SamlConfigs["idp"] = saml;
        return configuration;
    }

    private static (DeletedAccountLinkPruner Pruner, PluginConfiguration Configuration, CapturingLogger Audit) Build()
    {
        var audit = new CapturingLogger();
        var configuration = Seeded();
        var store = new ProviderConfigStore(() => configuration, _ => { }, new CapturingLogger());
        var links = new CanonicalLinkService(Substitute.For<IUserManager>(), new FakeCryptoProvider(), store, new CapturingLogger(), clock: () => Now);
        return (new DeletedAccountLinkPruner(() => links, audit), configuration, audit);
    }
}
