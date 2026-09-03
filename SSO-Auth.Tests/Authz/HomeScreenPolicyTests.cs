// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using Jellyfin.Database.Implementations.Entities;
using Jellyfin.Database.Implementations.Enums;
using Jellyfin.Plugin.SSO_Auth.Api.Authz;
using Jellyfin.Plugin.SSO_Auth.Config;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// The home-screen seed (#1101) as a pure writer against an in-memory store: which document it writes, in
/// what shape, and what it refuses. The create arm around it - sequencing after the persist, isolation from
/// the login, the second login - is <see cref="HomeScreenProvisioningTests"/>.
/// </summary>
public class HomeScreenPolicyTests
{
    private static readonly Guid Alice = Guid.Parse("66666666-6666-6666-6666-666666666666");

    [Fact]
    public void TheDocumentIsTheOneTheWebClientAsksFor()
    {
        // Read out of jellyfin-web 10.11.11: userSettings.js asks for getDisplayPreferences('usersettings',
        // userId, 'emby') and homesections.js renders ten slots. The server turns the non-GUID id into MD5
        // over the UTF-16 bytes; computed here independently of the extension the policy uses, so a change
        // in either derivation is caught rather than shared.
        Assert.Equal("emby", HomeScreenPolicy.WebClient);
        Assert.Equal(10, HomeScreenPolicy.SlotCount);
#pragma warning disable CA5351 // the host keys the document by MD5; this reproduces its key, it protects nothing
        Assert.Equal(new Guid(MD5.HashData(Encoding.Unicode.GetBytes("usersettings"))), HomeScreenPolicy.UserSettingsItemId);
#pragma warning restore CA5351
    }

    [Fact]
    public void ALayout_IsWrittenAsTheWholeTenSlots_ConfiguredFirstThenNone()
    {
        // The client fills an ABSENT slot with its default for that position, so a list written short would
        // render the configured sections followed by defaults nobody configured. Ten slots, None in the
        // rest, is what the client's own settings page persists.
        var store = new FakeDisplayPreferencesManager();
        var template = new ProvisioningPolicyTemplate { HomeSections = ["SmallLibraryTiles", "Resume", "NextUp"] };

        var written = HomeScreenPolicy.ApplyAtProvisioning(store, Alice, template);

        Assert.Equal(3, written);
        var document = Assert.Single(store.Documents).Value;
        Assert.Equal((Alice, HomeScreenPolicy.UserSettingsItemId, "emby"), (document.UserId, document.ItemId, document.Client));
        Assert.Equal(Enumerable.Range(0, 10), document.HomeSections.Select(s => s.Order).OrderBy(o => o));
        Assert.Equal(
            new[]
            {
                HomeSectionType.SmallLibraryTiles, HomeSectionType.Resume, HomeSectionType.NextUp,
                HomeSectionType.None, HomeSectionType.None, HomeSectionType.None, HomeSectionType.None,
                HomeSectionType.None, HomeSectionType.None, HomeSectionType.None,
            },
            document.HomeSections.OrderBy(s => s.Order).Select(s => s.Type));
        Assert.Equal(1, store.Reads);
        Assert.Equal(1, store.Updates);
    }

    [Fact]
    public void EveryDeclaredSection_FillsTheTenSlotsExactly()
    {
        // Ten declared members, ten slots: the whole vocabulary fits with no padding. It also pins that the
        // two counts agree, so a member Jellyfin adds turns this red before the help text that lists them
        // reaches anybody with one missing.
        var names = Enum.GetNames<HomeSectionType>();
        Assert.Equal(HomeScreenPolicy.SlotCount, names.Length);
        var store = new FakeDisplayPreferencesManager();

        var written = HomeScreenPolicy.ApplyAtProvisioning(store, Alice, new ProvisioningPolicyTemplate { HomeSections = names.ToList() });

        Assert.Equal(HomeScreenPolicy.SlotCount, written);
        var document = Assert.Single(store.Documents).Value;
        Assert.Equal(Enum.GetValues<HomeSectionType>(), document.HomeSections.OrderBy(s => s.Order).Select(s => s.Type));
    }

    [Fact]
    public void ATemplateNamingNoLayout_NeverTouchesTheStore()
    {
        // Not even the read: the host's read CREATES the document when there is none, so "writes nothing"
        // has to mean no call at all, or an empty row would come into existence for every account.
        var store = new FakeDisplayPreferencesManager();

        Assert.False(HomeScreenPolicy.NamesLayout(null));
        Assert.False(HomeScreenPolicy.NamesLayout(new ProvisioningPolicyTemplate { MaxActiveSessions = 2 }));
        Assert.False(HomeScreenPolicy.NamesLayout(new ProvisioningPolicyTemplate { HomeSections = [] }));
        Assert.Equal(0, HomeScreenPolicy.ApplyAtProvisioning(store, Alice, null));
        Assert.Equal(0, HomeScreenPolicy.ApplyAtProvisioning(store, Alice, new ProvisioningPolicyTemplate { MaxActiveSessions = 2 }));
        Assert.Equal(0, HomeScreenPolicy.ApplyAtProvisioning(store, Alice, new ProvisioningPolicyTemplate { HomeSections = [] }));

        Assert.Equal(0, store.Reads);
        Assert.Empty(store.Documents);
    }

    [Theory]
    [InlineData("nextup")]
    [InlineData("7")]
    [InlineData("4")]
    [InlineData("Folders")]
    [InlineData("")]
    public void AnUnknownName_IsRefusedByName_AndTheWriterWritesNothing(string name)
    {
        // The lowercase row is the one-character mistake somebody actually makes, and the two numerals are
        // the two ways Enum.TryParse lets a number through: "7" parses to a declared member and "4" does
        // too, and either would pin the layout to the order upstream declares the enum in. A refused list
        // is refused WHOLE: a partial layout is a layout nobody configured.
        var accepted = HomeScreenPolicy.TryParseHomeSections(["Resume", name], out var sections, out var refusedName);

        Assert.False(accepted);
        Assert.Equal(name, refusedName);
        Assert.Empty(sections);

        var store = new FakeDisplayPreferencesManager();
        Assert.Equal(0, HomeScreenPolicy.ApplyAtProvisioning(store, Alice, new ProvisioningPolicyTemplate { HomeSections = ["Resume", name] }));
        Assert.Equal(0, store.Reads);
    }

    [Fact]
    public void ANullEntry_IsRefusedAsAnEmptyName()
    {
        // A hand-edited configuration can carry an empty element; it is named back as the empty string so
        // the refusal message has something to quote rather than a null.
        Assert.False(HomeScreenPolicy.TryParseHomeSections(new List<string?> { null }, out _, out var refusedName));
        Assert.Equal(string.Empty, refusedName);
    }

    [Fact]
    public void MoreSectionsThanSlots_AreRefusedForLength_WithNoNameBlamed()
    {
        var names = Enumerable.Repeat("Resume", HomeScreenPolicy.SlotCount + 1).ToList();

        Assert.False(HomeScreenPolicy.TryParseHomeSections(names, out var sections, out var refusedName));
        Assert.Null(refusedName);
        Assert.Empty(sections);

        var store = new FakeDisplayPreferencesManager();
        Assert.Equal(0, HomeScreenPolicy.ApplyAtProvisioning(store, Alice, new ProvisioningPolicyTemplate { HomeSections = names }));
        Assert.Equal(0, store.Reads);
    }

    [Fact]
    public void TheWrite_ReplacesWhatTheDocumentHeld_ThroughTheStoresOwnReadModifyWrite()
    {
        // The document the read returns is the one written back, with its previous sections gone - the
        // shape the server's own controller produces for a client save. A fresh document beside it would
        // leave two rows for one key, and appending would leave two sections in one slot.
        var store = new FakeDisplayPreferencesManager();
        var existing = store.GetDisplayPreferences(Alice, HomeScreenPolicy.UserSettingsItemId, HomeScreenPolicy.WebClient);
        existing.HomeSections.Add(new HomeSection { Order = 0, Type = HomeSectionType.LiveTv });

        HomeScreenPolicy.ApplyAtProvisioning(store, Alice, new ProvisioningPolicyTemplate { HomeSections = ["Resume"] });

        var document = Assert.Single(store.Documents).Value;
        Assert.Same(existing, document);
        Assert.Equal(HomeSectionType.Resume, document.HomeSections.Single(s => s.Order == 0).Type);
        Assert.DoesNotContain(document.HomeSections, s => s.Type == HomeSectionType.LiveTv);
        Assert.Equal(HomeScreenPolicy.SlotCount, document.HomeSections.Count);
    }
}
