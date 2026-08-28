// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Jellyfin.Data;
using Jellyfin.Database.Implementations.Entities;
using Jellyfin.Database.Implementations.Enums;
using Jellyfin.Plugin.SSO_Auth.Api;
using Jellyfin.Plugin.SSO_Auth.Api.Linking;
using Jellyfin.Plugin.SSO_Auth.Api.Provider;
using Jellyfin.Plugin.SSO_Auth.Api.Session;
using Jellyfin.Plugin.SSO_Auth.Config;
using MediaBrowser.Controller.Library;
using NSubstitute;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// The two write sites #1450 found unproven, each asserted against what the user manager was ASKED TO SAVE
/// rather than against the object the test holds. That distinction is the whole of #1440: both writes were
/// present on the in-memory object the whole time, every unit test read them there, and neither reached the
/// database. A test that reads the object it constructed cannot tell a durable write from a lost one, so the
/// captures below take their values inside the <c>UpdateUserAsync</c> call - which reddens for a save that is
/// missing and for a save made before the field was set, and both are ways an account ends up stored wrong.
/// </summary>
public class PersistedUserMutationTests
{
    private static readonly Guid RootId = Guid.Parse("bbbbbbbb-0000-0000-0000-000000000001");
    private static readonly Guid AliceId = Guid.Parse("bbbbbbbb-0000-0000-0000-000000000002");
    private static readonly Guid CreatedId = Guid.Parse("bbbbbbbb-0000-0000-0000-000000000003");

    [Fact]
    public async Task DisablingTheMode_SavesTheRestoredPasswordRouting_NotOnlyTheObjectInHand()
    {
        // The one save site on this board that could be deleted with the whole suite staying green, measured
        // by deleting it: 3492 tests, 0 failed. What it restores is the ordinary password door for every
        // account the mode repointed, and the tracking set is cleared in the same method - so a restore that
        // is written and not saved leaves those accounts stamped at a provider with no password door AND
        // forgotten, which is an unrecoverable lockout of the whole repointed userbase by the off-switch
        // itself. The existing coverage read alice.AuthenticationProviderId on the object the test made.
        var root = PasswordAdmin("root", RootId);
        var alice = PasswordUser("alice", AliceId);
        var (service, _, users) = Build(new[] { root, alice });
        await service.TryEnableAsync("root");

        string? routingAtWrite = null;
        var writes = 0;
        users.UpdateUserAsync(Arg.Do<User>(u =>
        {
            if (u.Id == AliceId)
            {
                routingAtWrite = u.AuthenticationProviderId;
                writes++;
            }
        })).Returns(Task.CompletedTask);

        var restored = await service.DisableAsync();

        Assert.Equal(1, restored);
        Assert.Equal(1, writes);
        Assert.Equal(SsoAuthenticationProviders.DefaultPasswordProviderId, routingAtWrite);
    }

    [Fact]
    public async Task ProvisioningTemplate_ReachesTheObjectTheManagerIsAskedToSave()
    {
        // #1450's third clause, for the half that is about today. The template is applied at creation and only
        // at creation - the session mint does not re-apply it - so every field it writes depends on the create
        // arm's own save carrying it. Read at the write rather than after the call, and every field the
        // template can set is asserted, so a template field added later without reaching the save reddens here.
        var template = new ProvisioningPolicyTemplate
        {
            Permissions = new List<ProvisionedPermissionEntry>
            {
                new ProvisionedPermissionEntry { Permission = nameof(PermissionKind.EnableSyncTranscoding), Granted = true },
            },
            RemoteClientBitrateLimit = 3_000_000,
            MaxActiveSessions = 4,
            AudioLanguagePreference = "deu",
            SubtitleLanguagePreference = "eng",
            SubtitleMode = nameof(SubtitlePlaybackMode.Always),
            PlayDefaultAudioTrack = false,
            RememberAudioSelections = false,
            RememberSubtitleSelections = false,
        };

        var cfg = new PluginConfiguration();
        cfg.OidConfigs["kc"] = new OidConfig { Enabled = true, ProvisioningPolicyTemplate = template };
        var store = new ProviderConfigStore(() => cfg, _ => { }, new CapturingLogger());
        var users = Substitute.For<IUserManager>();
        var created = TestUsers.Named("alice", CreatedId);
        users.GetUserByName("alice").Returns((User?)null);
        users.CreateUserAsync("alice").Returns(created);
        users.GetUserById(CreatedId).Returns(created);

        User? saved = null;
        var snapshot = default((bool Transcoding, int? Bitrate, int? Sessions, string? Audio, string? Subtitle, SubtitlePlaybackMode Mode, bool PlayDefault, bool RememberAudio, bool RememberSubtitles));
        users.UpdateUserAsync(Arg.Do<User>(u =>
        {
            saved = u;
            snapshot = (
                u.HasPermission(PermissionKind.EnableSyncTranscoding),
                u.RemoteClientBitrateLimit,
                u.MaxActiveSessions,
                u.AudioLanguagePreference,
                u.SubtitleLanguagePreference,
                u.SubtitleMode,
                u.PlayDefaultAudioTrack,
                u.RememberAudioSelections,
                u.RememberSubtitleSelections);
        })).Returns(Task.CompletedTask);

        var service = new CanonicalLinkService(users, new RecordingCryptoProvider(), store, new CapturingLogger());
        await service.ResolveOrCreateAsync(ProviderMode.Oid, "kc", "sub-1", "alice", allowExistingAccountLink: false);

        Assert.Same(created, saved);
        Assert.True(snapshot.Transcoding);
        Assert.Equal(3_000_000, snapshot.Bitrate);
        Assert.Equal(4, snapshot.Sessions);
        Assert.Equal("deu", snapshot.Audio);
        Assert.Equal("eng", snapshot.Subtitle);
        Assert.Equal(SubtitlePlaybackMode.Always, snapshot.Mode);
        Assert.False(snapshot.PlayDefault);
        Assert.False(snapshot.RememberAudio);
        Assert.False(snapshot.RememberSubtitles);
    }

    private static User PasswordAdmin(string name, Guid id)
    {
        var user = new User(name, "SSO-Auth", "Default") { Id = id, Password = "hash-" + name };
        user.AuthenticationProviderId = SsoAuthenticationProviders.DefaultPasswordProviderId;
        user.SetPermission(PermissionKind.IsAdministrator, true);
        return user;
    }

    private static User PasswordUser(string name, Guid id)
    {
        var user = new User(name, "SSO-Auth", "Default") { Id = id, Password = "hash-" + name };
        user.AuthenticationProviderId = SsoAuthenticationProviders.DefaultPasswordProviderId;
        return user;
    }

    private static (SsoOnlyLoginService Service, PluginConfiguration Config, IUserManager Users) Build(IReadOnlyList<User> allUsers)
    {
        var cfg = new PluginConfiguration();
        var store = new ProviderConfigStore(() => cfg, _ => { }, new CapturingLogger());
        var users = Substitute.For<IUserManager>();
        users.GetUsers().Returns(allUsers);
        foreach (var user in allUsers)
        {
            users.GetUserByName(user.Username).Returns(user);
            users.GetUserById(user.Id).Returns(user);
        }

        return (new SsoOnlyLoginService(users, store, new CapturingLogger()), cfg, users);
    }
}
