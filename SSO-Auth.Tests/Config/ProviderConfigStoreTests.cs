// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Threading.Tasks;
using System.Xml.Linq;
using Jellyfin.Plugin.SSO_Auth.Config;
using MediaBrowser.Model.Plugins;
using Microsoft.Extensions.Logging;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// Tests for <see cref="ProviderConfigStore"/> - the owner of configuration reads, mutations, and the
/// validated save pipeline extracted from SSOPlugin (#318). The validation and preservation rules have
/// their own suite (ConfigPreservationTests); these pin the store's orchestration: what the pipeline
/// runs for a fresh incoming config, what it skips for the live object, and what reaches the persist
/// delegate. The store is exercised directly with local delegates, so no plugin instance is involved.
/// </summary>
public class ProviderConfigStoreTests
{
    private static readonly Guid User = Guid.Parse("44444444-4444-4444-4444-444444444444");

    private static (ProviderConfigStore Store, PluginConfiguration Live, List<BasePluginConfiguration> Persisted) CreateStore(ILogger? logger = null)
    {
        var live = new PluginConfiguration();
        var persisted = new List<BasePluginConfiguration>();
        return (new ProviderConfigStore(() => live, persisted.Add, logger!), live, persisted);
    }

    [Fact]
    public void Read_ReadsTheLiveConfiguration()
    {
        var (store, live, persisted) = CreateStore();
        live.OidConfigs["idp"] = new OidConfig { OidClientId = "client-1" };

        Assert.Equal("client-1", store.Read(c => c.OidConfigs["idp"].OidClientId));
        Assert.Empty(persisted); // A read never persists.
    }

    [Fact]
    public void Mutate_AppliesTheMutation_AndPersistsTheLiveObject()
    {
        var (store, live, persisted) = CreateStore();

        store.Mutate(c => c.OidConfigs["idp"] = new OidConfig());

        Assert.True(live.OidConfigs.ContainsKey("idp"));
        Assert.Same(live, Assert.Single(persisted));
    }

    [Fact]
    public void Mutate_WithResult_ReturnsIt_AndPersists()
    {
        var (store, live, persisted) = CreateStore();
        live.OidConfigs["idp"] = new OidConfig();

        var removed = store.Mutate(c => c.OidConfigs.Remove("idp"));

        Assert.True(removed);
        Assert.Same(live, Assert.Single(persisted));
    }

    [Fact]
    public void Save_FreshConfigWithMalformedOverride_Throws_AndPersistsNothing()
    {
        // The fail-closed gate (#139): a replacement config is validated BEFORE anything is persisted.
        var (store, _, persisted) = CreateStore();
        var incoming = new PluginConfiguration();
        incoming.OidConfigs["idp"] = new OidConfig { BaseUrlOverride = "not-a-url" };

        Assert.Throws<ArgumentException>(() => store.Save(incoming));

        Assert.Empty(persisted);
    }

    [Fact]
    public void Save_FreshConfig_PreservesServerManagedFields_AndPersistsIt()
    {
        // The stale-snapshot save (#157/#189): a posted config carrying neither links nor secret must
        // get both re-injected from the live config before it reaches the persist delegate.
        var (store, live, persisted) = CreateStore();
        live.OidConfigs["idp"] = new OidConfig
        {
            OidSecret = "live-secret",
            CanonicalLinks = new SerializableDictionary<string, Guid> { ["sub-1"] = User },
        };
        var incoming = new PluginConfiguration();
        incoming.OidConfigs["idp"] = new OidConfig();

        store.Save(incoming);

        Assert.Same(incoming, Assert.Single(persisted));
        Assert.Equal("live-secret", incoming.OidConfigs["idp"].OidSecret);
        Assert.Equal(User, incoming.OidConfigs["idp"].CanonicalLinks["sub-1"]);
    }

    [Fact]
    public void Save_FreshConfigWithNewReservedName_Throws_AndPersistsNothing()
    {
        // The registration gate (#336): a name absent from the live config is validated before
        // anything is persisted.
        var (store, _, persisted) = CreateStore();
        var incoming = new PluginConfiguration();
        incoming.OidConfigs["my/realm"] = new OidConfig();

        Assert.Throws<ArgumentException>(() => store.Save(incoming));

        Assert.Empty(persisted);
    }

    [Fact]
    public void Save_FreshConfigWithExistingReservedName_IsExempt_AndPersists()
    {
        // The store hands its live config to the validator, so a reserved-character name that is
        // already configured keeps saving - its callback-URL bytes are what the IdP has registered,
        // and blocking the save would strand the deployment behind a rename (#336).
        var (store, live, persisted) = CreateStore();
        live.OidConfigs["kc=prod"] = new OidConfig();
        var incoming = new PluginConfiguration();
        incoming.OidConfigs["kc=prod"] = new OidConfig();

        store.Save(incoming);

        Assert.Same(incoming, Assert.Single(persisted));
    }

    [Fact]
    public void Save_TheLiveObject_SkipsTheFreshConfigPipeline()
    {
        // Writes that reuse the live object (Mutate, login-path link writes) are intentionally never
        // revalidated: even a malformed override already sitting in the live config must not make the
        // save throw, so the login path can never be blocked by the config-page gate.
        var (store, live, persisted) = CreateStore();
        live.OidConfigs["idp"] = new OidConfig { BaseUrlOverride = "not-a-url" };

        store.Save(live);

        Assert.Same(live, Assert.Single(persisted));
    }

    [Fact]
    public void Save_FreshConfigWithInsecureOptions_PersistsAndAuditsThem()
    {
        // The #140 audit: saving a provider with a disabled security check emits a warning naming the
        // provider and the option - after the save, so a logging provider cannot fail a completed save.
        var logger = new CapturingLogger();
        var (store, _, persisted) = CreateStore(logger);
        var incoming = new PluginConfiguration();
        incoming.OidConfigs["corp"] = new OidConfig { DisableHttps = true };

        store.Save(incoming);

        Assert.Single(persisted);
        var entry = Assert.Single(logger.Entries);
        Assert.Equal(LogLevel.Warning, entry.Level);
        Assert.Contains("corp", entry.Message, StringComparison.Ordinal);
        Assert.Contains("DisableHttps", entry.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Save_FreshConfigWithInsecureSamlOptions_PersistsAndAuditsThem()
    {
        // The #672 SAML parity of the #140 audit: saving a SAML provider with DoNotValidateAudience set
        // emits a warning naming the provider and the option (protocol SAML), the same trace the OpenID
        // escape hatches leave.
        var logger = new CapturingLogger();
        var (store, _, persisted) = CreateStore(logger);
        var incoming = new PluginConfiguration();
        incoming.SamlConfigs["corp"] = new SamlConfig { DoNotValidateAudience = true };

        store.Save(incoming);

        Assert.Single(persisted);
        var entry = Assert.Single(logger.Entries);
        Assert.Equal(LogLevel.Warning, entry.Level);
        Assert.Contains("corp", entry.Message, StringComparison.Ordinal);
        Assert.Contains("DoNotValidateAudience", entry.Message, StringComparison.Ordinal);
        Assert.Contains("SAML", entry.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Save_WithoutALogger_StillPersistsInsecureOptions_WithoutThrowing()
    {
        // The audit is best-effort: a missing logger must never turn a valid save into a failure.
        var (store, _, persisted) = CreateStore(logger: null);
        var incoming = new PluginConfiguration();
        incoming.OidConfigs["corp"] = new OidConfig { DisableHttps = true };

        store.Save(incoming);

        Assert.Single(persisted);
    }

    [Fact]
    public async Task Mutate_ConcurrentReadModifyWrites_NeverLoseAnUpdate()
    {
        // Race regression for #412: the challenge flow now records the server-managed NewPath spelling
        // through Mutate instead of an unsynchronized field write, specifically so two concurrent
        // challenges cannot race a read-modify-write and lose one another's update. This pins the
        // general property that guarantee rests on: every Mutate call is a fully serialized
        // read-modify-write, so N concurrent increments through the store are never dropped - if the
        // store's lock were removed (or a caller bypassed it, as the pre-fix NewPath write did), some
        // increments would race and the final count would fall short of N.
        var (store, live, _) = CreateStore();
        live.RateLimitMaxAttempts = 0; // the constructor default (30) would otherwise fold into the count
        var ct = TestContext.Current.CancellationToken;

        const int concurrency = 64;
        var tasks = new Task[concurrency];
        for (var i = 0; i < concurrency; i++)
        {
            tasks[i] = Task.Run(() => store.Mutate(c => c.RateLimitMaxAttempts++), ct);
        }

        await Task.WhenAll(tasks);

        Assert.Equal(concurrency, live.RateLimitMaxAttempts);
    }

    [Fact]
    public async Task Mutate_ConcurrentChallengeStyleReadThenWrite_NeverThrows_AndSettlesOnADerivedSpelling()
    {
        // Mirrors ChallengeNewPathResolver.ResolveChallengeNewPath's shape (#412, unified in #670): a fast Read,
        // then a Mutate only when the derived spelling differs from what is stored - never a bare field
        // write outside the lock. Concurrent callers alternate between the two derivable spellings for
        // "kc" while OTHER concurrent callers add and remove UNRELATED provider entries - a genuine
        // structural dictionary mutation racing the "kc" reads. This is the exact hazard Read's own doc
        // comment cites (a Dictionary read-during-write is undefined behavior in .NET: throw, misread, or
        // a spin on a corrupted chain during a resize) - without the store's lock, THIS combination could
        // actually throw or corrupt state; a bool-only workload against a single already-live entry could
        // not, so it would pass whether or not the lock existed. With the lock, every call must complete
        // cleanly and the "kc" entry must survive untouched.
        var (store, live, _) = CreateStore();
        var seeded = new OidConfig { Enabled = true };
        live.OidConfigs["kc"] = seeded;
        var ct = TestContext.Current.CancellationToken;

        const int concurrency = 50;
        var tasks = new Task[concurrency * 2];
        for (var i = 0; i < concurrency; i++)
        {
            var derived = i % 2 == 0;
            tasks[i] = Task.Run(
                () =>
                {
                    var stored = store.Read(c => c.OidConfigs["kc"].NewPath);
                    if (stored != derived)
                    {
                        store.Mutate(c => c.OidConfigs["kc"].NewPath = derived);
                    }
                },
                ct);

            // Concurrent structural churn on an unrelated key, racing the "kc" reads/writes above on the
            // SAME dictionary - added and removed within the same task so the map ends the test with only
            // "kc" left in it.
            var churnKey = "churn-" + i;
            tasks[concurrency + i] = Task.Run(
                () =>
                {
                    store.Mutate(c => c.OidConfigs[churnKey] = new OidConfig());
                    store.Mutate(c => c.OidConfigs.Remove(churnKey));
                },
                ct);
        }

        await Task.WhenAll(tasks); // throws if any callback threw or the store deadlocked/corrupted the map

        // Either NewPath spelling is a legitimate race outcome, but the map itself must have survived the
        // structural churn intact: exactly the "kc" entry left (every churn key fully cleaned up, none
        // leaked or half-written), the SAME object instance (never replaced or duplicated by an
        // interleaved write), with every OTHER field untouched by the race.
        Assert.Equal(1, store.Read(c => c.OidConfigs.Count));
        Assert.Same(seeded, store.Read(c => c.OidConfigs["kc"]));
        Assert.True(store.Read(c => c.OidConfigs["kc"].Enabled));
    }

    [Fact]
    public void NullArguments_Throw()
    {
        var (store, _, _) = CreateStore();

        Assert.Throws<ArgumentNullException>(() => store.Save(null!));
        Assert.Throws<ArgumentNullException>(() => store.Read<bool>(null!));
        Assert.Throws<ArgumentNullException>(() => store.Mutate(null!));
        Assert.Throws<ArgumentNullException>(() => store.Mutate<bool>(null!));
    }

    [Fact]
    public void Mutate_PersistThrows_LeavesTheLiveConfigurationExactlyAsItWas()
    {
        // #1521: the failure the promise was false for. MutateConfiguration's own remarks and the
        // operator page both say a refused import leaves the server exactly as it was; that was true
        // for a mutation that threw and false for a PERSIST that threw - a full disk, a read-only
        // volume, exactly the conditions a freshly built migration target hits. The live object kept
        // every change while nothing reached the XML, so logins behaved as though the import had
        // succeeded until the process restarted, and the next unrelated save committed the changes
        // silently. Delete the rollback in Mutate and this test reads "hijacked" back out of the live
        // configuration.
        var live = new PluginConfiguration();
        live.OidConfigs["idp"] = new OidConfig { OidClientId = "client-1" };
        var store = new ProviderConfigStore(() => live, _ => throw new IOException("read-only volume"), new CapturingLogger());

        // What a restart would load out of the file, which is the state the rollback owes rather than
        // "the object as it stood": a round trip through the persisted form normalizes a null role-map
        // list to an empty one, so the live object and the file it came from are not byte-identical to
        // begin with. The equality below is therefore against the file's content, not against the
        // object's history - and without the rollback it reads "hijacked" and fails either way.
        var onDisk = live.DetachedCopy().ToPersistedForm();

        Assert.Throws<IOException>(() => store.Mutate(c =>
        {
            c.OidConfigs["idp"].OidClientId = "hijacked";
            c.OidConfigs["second"] = new OidConfig();
            c.DisablePasswordLogin = true;
        }));

        Assert.Equal(onDisk, live.ToPersistedForm());
        Assert.Equal("client-1", live.OidConfigs["idp"].OidClientId);
        Assert.False(live.OidConfigs.ContainsKey("second"));
        Assert.False(live.DisablePasswordLogin);
    }

    [Fact]
    public void Mutate_WithResult_PersistThrows_LeavesTheLiveConfigurationExactlyAsItWas()
    {
        // The result-returning overload is the one the removal endpoints and the link import use, so it
        // carries the same obligation: a removal that could not be written down did not happen.
        var live = new PluginConfiguration();
        live.OidConfigs["idp"] = new OidConfig();
        var store = new ProviderConfigStore(() => live, _ => throw new IOException("no space left on device"), new CapturingLogger());
        var onDisk = live.DetachedCopy().ToPersistedForm();

        Assert.Throws<IOException>(() => store.Mutate(c => c.OidConfigs.Remove("idp")));

        Assert.Equal(onDisk, live.ToPersistedForm());
        Assert.True(live.OidConfigs.ContainsKey("idp"));
    }

    [Fact]
    public void Mutate_PersistThrows_RollsBackWithoutSwappingTheLiveObject()
    {
        // The rollback restores the live configuration IN PLACE, and this is the half of that which is
        // load-bearing: the store hands the SAME configuration object out on every read, so a rollback
        // that swapped the reference would leave every holder of a read - the plugin's own
        // Configuration property among them - pointing at an object the store had abandoned.
        //
        // How far it reaches is stated rather than implied. The provider objects UNDER the
        // configuration are replaced by the restored ones, so a caller that took a reference to a
        // provider before this mutation keeps an object carrying the rejected values. That caller is
        // receiving this exception rather than carrying on, and the live configuration - which is what
        // the next login reads - is correct.
        var live = new PluginConfiguration();
        var provider = new OidConfig { OidClientId = "client-1" };
        live.OidConfigs["idp"] = provider;
        var store = new ProviderConfigStore(() => live, _ => throw new IOException("read-only volume"), new CapturingLogger());

        Assert.Throws<IOException>(() => store.Mutate(c => c.OidConfigs["idp"].OidClientId = "hijacked"));

        Assert.Same(live, store.Read(c => c));
        Assert.Equal("client-1", live.OidConfigs["idp"].OidClientId);
        Assert.NotSame(provider, live.OidConfigs["idp"]);
        Assert.Equal("hijacked", provider.OidClientId);
    }

    [Fact]
    public void Mutate_PersistReturns_KeepsTheChange()
    {
        // The positive control the three above need: the rollback fires on a failed write and on
        // nothing else. Without it, a Mutate that rolled back every time would pass all three.
        var (store, live, persisted) = CreateStore();

        store.Mutate(c => c.OidConfigs["idp"] = new OidConfig { OidClientId = "client-1" });

        Assert.Equal("client-1", live.OidConfigs["idp"].OidClientId);
        Assert.Same(live, Assert.Single(persisted));
    }

    [Fact]
    public void Save_PersistThrows_LeavesTheLiveConfigurationExactlyAsItWas()
    {
        // The config-page save carries the same promise and used to break it in a louder way: the base
        // class made the posted configuration live BEFORE serializing it, so a failed write left the
        // server running on settings that are not on disk.
        var live = new PluginConfiguration();
        live.OidConfigs["idp"] = new OidConfig { OidClientId = "client-1" };
        var store = new ProviderConfigStore(() => live, _ => throw new IOException("read-only volume"), new CapturingLogger());
        var onDisk = live.DetachedCopy().ToPersistedForm();

        var incoming = new PluginConfiguration();
        incoming.OidConfigs["idp"] = new OidConfig { OidClientId = "posted" };

        Assert.Throws<IOException>(() => store.Save(incoming));

        Assert.Equal(onDisk, live.ToPersistedForm());
        Assert.Equal("client-1", live.OidConfigs["idp"].OidClientId);
    }

    [Fact]
    public void Save_PersistThrows_UndoesWhatThePipelineDidToTheLiveObject()
    {
        // Why Save needs the rollback even though the posted object is a different one: the pipeline
        // hands the LIVE logout-session map to the posted configuration (ServerManagedFields.Preserve),
        // and the real persist delegate encrypts the secrets inside those shared objects in place. A
        // write that throws after that would leave the live configuration carrying state the file does
        // not have. Simulated here by a persist that mutates what it was handed and then fails, which is
        // the shape rather than the encryption itself.
        var live = new PluginConfiguration();
        live.LogoutSessions["session"] = new LogoutSession { IdToken = "plaintext" };
        var onDisk = live.DetachedCopy().ToPersistedForm();

        var store = new ProviderConfigStore(
            () => live,
            posted =>
            {
                ((PluginConfiguration)posted).LogoutSessions["session"].IdToken = "ssoenc:rewritten";
                throw new IOException("read-only volume");
            },
            new CapturingLogger());

        var incoming = new PluginConfiguration();

        Assert.Throws<IOException>(() => store.Save(incoming));

        Assert.Equal(onDisk, live.ToPersistedForm());
        Assert.Equal("plaintext", live.LogoutSessions["session"].IdToken);
    }

    [Fact]
    public void AdoptFrom_CarriesEveryPersistedField()
    {
        // AdoptFrom derives its field set from the type instead of listing it, and this is what makes
        // that derivation checkable: a property added to the configuration model tomorrow that the
        // reflection walk does not carry makes these two persisted forms differ, and the rollback above
        // would otherwise restore a configuration missing that field WITHOUT anything going red.
        var source = new PluginConfiguration
        {
            DisablePasswordLogin = true,
            EnableSingleLogout = true,
            ManageLoginPageButtons = true,
            EnableRateLimit = true,
            RateLimitMaxAttempts = 7,
            RateLimitWindowSeconds = 11,
            BreakGlassAdminUsername = "root",
        };
        source.OidConfigs["idp"] = new OidConfig { OidClientId = "client-1", Enabled = true };
        source.SamlConfigs["saml"] = new SamlConfig { SamlClientId = "sp" };
        source.ProvisioningProfiles["profile"] = new ProvisioningPolicyTemplate { MaxActiveSessions = 3 };
        source.SsoOnlyRepointedUserIds.Add(User);
        source.LogoutSessions["session"] = new LogoutSession();

        var target = new PluginConfiguration();
        target.AdoptFrom(source);

        Assert.Equal(source.ToPersistedForm(), target.ToPersistedForm());
    }

    [Fact]
    public void AdoptFrom_TheSameObject_IsANoOp()
    {
        // Save hands the live object to AdoptFrom when a caller posts it back, so self-adoption has to
        // be harmless rather than a walk that assigns every property to itself.
        var live = new PluginConfiguration();
        live.OidConfigs["idp"] = new OidConfig { OidClientId = "client-1" };
        var before = live.ToPersistedForm();

        live.AdoptFrom(live);

        Assert.Equal(before, live.ToPersistedForm());
    }

    [Fact]
    public void Mutate_MutationThrowsHalfWay_LeavesNothingBehind()
    {
        // The import endpoints promise their callers that a rejected document changes nothing, and
        // ConfigImport.Apply writes the provisioning profiles before it merges the providers - so a
        // throw in the second half used to leave the first half applied in memory with no undo. The
        // guarded region covers the mutation as well as the write, so it does not any more.
        var live = new PluginConfiguration();
        var store = new ProviderConfigStore(() => live, _ => { }, new CapturingLogger());
        var onDisk = live.DetachedCopy().ToPersistedForm();

        Assert.Throws<InvalidOperationException>(() => store.Mutate(c =>
        {
            c.ProvisioningProfiles["guest"] = new ProvisioningPolicyTemplate();
            throw new InvalidOperationException("the second half refused");
        }));

        Assert.Equal(onDisk, live.ToPersistedForm());
        Assert.Empty(live.ProvisioningProfiles);
    }

    [Fact]
    public void Mutate_SnapshotCannotBeTaken_StillWrites_AndSaysSo()
    {
        // The rollback is bought with a serialization, and that serializer refuses characters that can
        // reach a canonical-link key: neither LinkImport nor the login-path writer checks for them.
        // Refusing the write when the snapshot cannot be taken would make a configuration that once
        // reached this state permanently unwritable - including the DELETE that would repair it - so the
        // write goes ahead without an undo and the log carries the loss. Fail-open on the rollback,
        // deliberately, because the alternative is a write outage nothing can clear.
        // Built rather than written as a literal: a raw control byte in a source file is the kind of
        // thing an editor, a diff or a normalization step eats without saying so, and this test is
        // entirely about that byte.
        var unserializable = "sub" + (char)0x01 + "one";

        var live = new PluginConfiguration();
        var provider = new OidConfig();
        live.OidConfigs["idp"] = provider;
        provider.CanonicalLinks[unserializable] = User;
        Assert.ThrowsAny<Exception>(() => live.ToPersistedForm()); // the premise, read rather than assumed

        var logger = new CapturingLogger();
        var persisted = new List<BasePluginConfiguration>();
        var store = new ProviderConfigStore(() => live, persisted.Add, logger);

        store.Mutate(c => c.OidConfigs["idp"].CanonicalLinks.Remove(unserializable));

        Assert.Single(persisted);
        Assert.False(live.OidConfigs["idp"].CanonicalLinks.ContainsKey(unserializable));
        Assert.Contains(logger.Entries, e => e.Message.Contains("without a rollback", StringComparison.Ordinal));
    }

    [Fact]
    public void AdoptableSet_CoversEveryFieldTheSerializerPersists()
    {
        // The derivation-proof half of AdoptFrom_CarriesEveryPersistedField, which compares only fields a
        // test remembered to populate. This one asks the SERIALIZER what it persists - every top-level
        // element it emits - and refuses a name AdoptFrom's rule does not select, so a property added to
        // the configuration model tomorrow bites here without anybody remembering this test.
        //
        // What it does NOT prove is stated rather than implied: the rule is restated here rather than
        // read out of the production field, which is private. It catches a new PERSISTED property the
        // rule misses - a get-only collection is the shape that would - and not a change to the rule
        // itself, which the behavioural tests above are for.
        var persistedNames = XDocument
            .Parse(new PluginConfiguration().ToPersistedForm())
            .Root!
            .Elements()
            .Select(element => element.Name.LocalName)
            .ToHashSet(StringComparer.Ordinal);

        var adopted = typeof(PluginConfiguration)
            .GetProperties(BindingFlags.Public | BindingFlags.Instance)
            .Where(p => p.CanRead && p.CanWrite && p.GetIndexParameters().Length == 0)
            .Select(p => p.Name)
            .ToHashSet(StringComparer.Ordinal);

        Assert.NotEmpty(persistedNames);
        Assert.Empty(persistedNames.Except(adopted));
    }
}
