// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Collections.Generic;
using Jellyfin.Plugin.SSO_Auth.Api.LoginButtons;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// What happens to a login disclaimer that already holds an opening fence this version no longer writes
/// (#1344). The fence is written into every installation's disclaimer and found again by an exact search on
/// the next sync, so an edit to the literal that is MATCHED stops the plugin recognising its own region: it
/// appends a second block beside the first, and no later action removes the first, because content outside
/// the fences is an admin's own disclaimer and is preserved on purpose. A typographic pass over this tree
/// made that edit and it shipped, so the state these tests describe can exist on disk.
///
/// The repair is that recognition reads only the stable token and never the parenthetical, so these tests
/// pin BOTH directions: an old fence is still recognised, and a fence whose parenthetical is something
/// nobody has written yet is recognised too. The second is what stops the next edit to that prose from
/// costing another release.
/// </summary>
public class LoginButtonFenceUpgradeTests
{
    // The literal as it stood before the typographic pass, with the one character that changed built from its
    // code point rather than typed. Typing it would put the character back into this tree, which is the thing
    // the pass removed, and the test needs the exact bytes rather than the exact source spelling.
    private static readonly string PreSweepBeginMarker =
        "<!-- SSO-LOGIN-BUTTONS:BEGIN (managed by jellyfin-plugin-sso "
        + char.ConvertFromUtf32(0x2014)
        + " do not edit inside) -->";

    private static IReadOnlyList<LoginButton> One(string name, string text)
        => new[] { new LoginButton(LoginButtonProtocol.Oidc, name, text) };

    [Fact]
    public void ThePreSweepFenceIsNotTheOneWrittenToday_WhichIsWhyTheseTestsExist()
    {
        // Guards the premise. If the two literals ever became equal again, every test below would still pass
        // while proving nothing, and this one would go red to say so.
        Assert.NotEqual(LoginButtonInjector.BeginMarker, PreSweepBeginMarker);
        Assert.StartsWith(LoginButtonInjector.BeginMarkerPrefix, PreSweepBeginMarker, StringComparison.Ordinal);
    }

    [Fact]
    public void ADisclaimerCarryingThePreSweepFence_SyncsToExactlyOneManagedBlock()
    {
        var disclaimer = "House rules apply.\n\n" + PreSweepBlock("keycloak", "Keycloak");

        var merged = LoginButtonInjector.Merge(disclaimer, LoginButtonInjector.BuildBlock(One("keycloak", "Keycloak")));

        Assert.Equal(1, CountBlocks(merged));
        Assert.DoesNotContain(PreSweepBeginMarker, merged, StringComparison.Ordinal);
        Assert.Contains("House rules apply.", merged, StringComparison.Ordinal);
    }

    [Fact]
    public void ADisclaimerCarryingThePreSweepFence_LeavesNoManagedBlockWhenTheButtonsAreTurnedOff()
    {
        var disclaimer = "House rules apply.\n\n" + PreSweepBlock("keycloak", "Keycloak");

        var merged = LoginButtonInjector.Merge(disclaimer, string.Empty);

        Assert.Equal(0, CountBlocks(merged));
        Assert.DoesNotContain(LoginButtonInjector.BeginMarkerPrefix, merged, StringComparison.Ordinal);
        Assert.Equal("House rules apply.", merged);
    }

    [Fact]
    public void AnInstallationAlreadyLeftHoldingTwoBlocks_ConvergesToOne()
    {
        // The state an installation reaches by upgrading and then syncing once under the unrepaired code: the
        // orphan first, the block the plugin now recognises second. Both have to end up as one.
        var disclaimer = PreSweepBlock("keycloak", "Old label")
            + "\n\n" + LoginButtonInjector.BuildBlock(One("keycloak", "Keycloak"));

        var merged = LoginButtonInjector.Merge(disclaimer, LoginButtonInjector.BuildBlock(One("keycloak", "Keycloak")));

        Assert.Equal(1, CountBlocks(merged));
        Assert.DoesNotContain("Old label", merged, StringComparison.Ordinal);
    }

    [Fact]
    public void AnInstallationAlreadyLeftHoldingTwoBlocks_LeavesNoneWhenTheButtonsAreTurnedOff()
    {
        // This is the arm that made the defect more than an upgrade artefact: under the unrepaired code the
        // orphan outlived the feature that created it, and only a hand edit removed it.
        var disclaimer = PreSweepBlock("keycloak", "Old label")
            + "\n\n" + LoginButtonInjector.BuildBlock(One("keycloak", "Keycloak"));

        var merged = LoginButtonInjector.Merge(disclaimer, string.Empty);

        Assert.Equal(0, CountBlocks(merged));
        Assert.Equal(string.Empty, merged);
    }

    [Fact]
    public void AdminContentAroundAndBetweenTwoBlocks_Survives()
    {
        var disclaimer = "Top notice.\n\n"
            + PreSweepBlock("keycloak", "Old label")
            + "\n\nMiddle notice.\n\n"
            + LoginButtonInjector.BuildBlock(One("keycloak", "Keycloak"))
            + "\n\nBottom notice.";

        var merged = LoginButtonInjector.Merge(disclaimer, LoginButtonInjector.BuildBlock(One("keycloak", "Keycloak")));

        Assert.Equal(1, CountBlocks(merged));
        Assert.Contains("Top notice.", merged, StringComparison.Ordinal);
        Assert.Contains("Middle notice.", merged, StringComparison.Ordinal);
        Assert.Contains("Bottom notice.", merged, StringComparison.Ordinal);
    }

    [Fact]
    public void AFenceWhoseParentheticalNobodyHasWrittenYet_IsStillRecognised()
    {
        // The forward half. The next edit to the prose inside the opening comment must cost nothing, which is
        // exactly what the previous one did cost.
        var future = LoginButtonInjector.BeginMarkerPrefix + " (anything at all, rewritten later) -->";
        var disclaimer = "Notice.\n\n" + future + "\n<div class=\"sso-login-buttons\">\n</div>\n" + LoginButtonInjector.EndMarker;

        Assert.Equal(1, CountBlocks(LoginButtonInjector.Merge(disclaimer, LoginButtonInjector.BuildBlock(One("k", "K")))));
        Assert.Equal("Notice.", LoginButtonInjector.Merge(disclaimer, string.Empty));
    }

    [Fact]
    public void ATypedFragmentWithNoCommentCloseOnItsLine_IsNotAnOpener_AndTheRealRegionBelowIsUntouched()
    {
        // An admin who typed the token by hand and never closed the comment must not have the text below it
        // swallowed when the region is replaced. The fences this type writes are whole lines, so an opener
        // whose comment close is on another line is not one.
        var fragment = LoginButtonInjector.BeginMarkerPrefix + " I was mid-sentence when\nI stopped.";
        var disclaimer = fragment + "\n\n" + LoginButtonInjector.BuildBlock(One("keycloak", "Old label"));

        var merged = LoginButtonInjector.Merge(disclaimer, LoginButtonInjector.BuildBlock(One("keycloak", "Keycloak")));

        Assert.Equal(1, CountBlocks(merged));
        Assert.Contains(fragment, merged, StringComparison.Ordinal);
        Assert.DoesNotContain("Old label", merged, StringComparison.Ordinal);
    }

    // The pre-sweep block is the block this version builds with its opening fence swapped for the one that
    // shipped before the pass, so the fixture cannot drift away from what an installation actually holds.
    private static string PreSweepBlock(string name, string text)
        => PreSweepBeginMarker + LoginButtonInjector.BuildBlock(One(name, text))[LoginButtonInjector.BeginMarker.Length..];

    // Counted on the CLOSING fence, which the sweep never touched, so the count is the same for an old block
    // and a new one.
    private static int CountBlocks(string disclaimer)
    {
        var count = 0;
        var at = disclaimer.IndexOf(LoginButtonInjector.EndMarker, StringComparison.Ordinal);
        while (at >= 0)
        {
            count++;
            at = disclaimer.IndexOf(LoginButtonInjector.EndMarker, at + LoginButtonInjector.EndMarker.Length, StringComparison.Ordinal);
        }

        return count;
    }
}
