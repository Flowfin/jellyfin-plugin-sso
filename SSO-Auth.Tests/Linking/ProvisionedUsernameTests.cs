// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using Jellyfin.Plugin.SSO_Auth.Api.Linking;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// Direct tests of <see cref="ProvisionedUsername"/> - the map from an IdP-supplied username to the name a
/// brand-new Jellyfin account is created under (#1137). The security-relevant half is what the map REFUSES
/// to hand back: an empty or all-dots result, because "." and ".." are inside the host's own accepted set
/// and are path traversal once a username reaches the per-user profile directory (#447). The rest pins the
/// allowlist itself, one rejected class at a time, so a widening is a deliberate edit with a red test in
/// front of it rather than a quiet one.
/// </summary>
public class ProvisionedUsernameTests
{
    [Theory]
    // The literal members of the host's set, which must survive untouched.
    [InlineData("alice", "alice")]
    [InlineData("alice.smith", "alice.smith")]
    [InlineData("alice-smith", "alice-smith")]
    [InlineData("alice_smith", "alice_smith")]
    [InlineData("alice+tag", "alice+tag")]
    [InlineData("alice@example.com", "alice@example.com")]
    [InlineData("Alice O'Hara", "Alice O'Hara")]
    [InlineData("user1234", "user1234")]
    public void TrySanitize_NameAlreadyAcceptable_IsReturnedByteForByte(string raw, string expected)
    {
        Assert.True(ProvisionedUsername.TrySanitize(raw, out var provisioned));
        Assert.Equal(expected, provisioned);
    }

    [Theory]
    // One rejected class per row, each around the same accepted stem so the diff is the class alone.
    [InlineData("al!ice", "alice")]                 // punctuation outside the set
    [InlineData("al#ice", "alice")]
    [InlineData("al$ice", "alice")]
    [InlineData("al%ice", "alice")]
    [InlineData("al&ice", "alice")]
    [InlineData("al*ice", "alice")]
    [InlineData("al(ice)", "alice")]
    [InlineData("al=ice", "alice")]
    [InlineData("al|ice", "alice")]
    [InlineData("al:ice", "alice")]
    [InlineData("al;ice", "alice")]
    [InlineData("al,ice", "alice")]
    [InlineData("al?ice", "alice")]
    [InlineData("al~ice", "alice")]
    [InlineData("<alice>", "alice")]
    [InlineData("\"alice\"", "alice")]
    [InlineData("al/ice", "alice")]                 // path separators, the profile-directory hazard
    [InlineData("al\\ice", "alice")]
    [InlineData("../alice", "..alice")]             // the slash goes; the dots are the host's own set
    [InlineData("al\nice", "alice")]                // control characters, including the log-forging pair
    [InlineData("al\rice", "alice")]
    [InlineData("al\tice", "alice")]
    [InlineData("al\0ice", "alice")]
    [InlineData("al\u00A0ice", "alice")]            // whitespace the set does not admit: no-break space
    [InlineData("al\u2003ice", "alice")]            // em space
    [InlineData("alice\U0001F600", "alice")]      // astral plane, reached as a surrogate pair
    public void TrySanitize_RejectedCharacter_IsDroppedRatherThanSubstituted(string raw, string expected)
    {
        Assert.True(ProvisionedUsername.TrySanitize(raw, out var provisioned));
        Assert.Equal(expected, provisioned);
    }

    [Theory]
    // The non-ASCII decision, recorded as tests rather than only as prose: Unicode letters, digits and
    // combining marks are inside .NET's \w and therefore inside the host's own set, so they are PRESERVED
    // and never transliterated. Transliterating would rename an account the host would have taken as sent.
    [InlineData("Jörg")]
    [InlineData("Ærlig")]
    [InlineData("Ярослав")]
    [InlineData("中村")]
    [InlineData("محمد")]
    [InlineData("Ωμέγα")]
    [InlineData("Nguyễn")]
    [InlineData("élodie")]
    public void TrySanitize_NonAsciiLetters_ArePreserved(string raw)
    {
        Assert.True(ProvisionedUsername.TrySanitize(raw, out var provisioned));
        Assert.Equal(raw, provisioned);
    }

    [Theory]
    // The host's anchors forbid leading and trailing whitespace. Space is the only whitespace the allowlist
    // admits, so the filter plus this trim is the whole of that rule; interior spaces stay.
    [InlineData(" alice ", "alice")]
    [InlineData("\talice\t", "alice")]
    [InlineData("  Alice O'Hara  ", "Alice O'Hara")]
    [InlineData("!alice!", "alice")]
    public void TrySanitize_LeadingAndTrailingWhitespace_IsRemoved(string raw, string expected)
    {
        Assert.True(ProvisionedUsername.TrySanitize(raw, out var provisioned));
        Assert.Equal(expected, provisioned);
    }

    [Theory]
    // The empty-result fallback. Nothing usable survived, so no name is offered and the caller refuses the
    // login; the all-dots rows are the ones that would otherwise pass the host's own check and then escape
    // the user-configuration directory at the profile path (#447).
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("!!!")]
    [InlineData("<>/\\")]
    [InlineData("\n\t")]
    [InlineData(".")]
    [InlineData("..")]
    [InlineData("...")]
    [InlineData("./..")]
    [InlineData("\U0001F600")]
    public void TrySanitize_NothingAcceptableSurvives_YieldsNoName(string? raw)
    {
        Assert.False(ProvisionedUsername.TrySanitize(raw, out var provisioned));
        Assert.Equal(string.Empty, provisioned);
    }

    [Theory]
    [InlineData("alice")]
    [InlineData(" al!ice ")]
    [InlineData("../alice")]
    [InlineData("Jörg\u00A0Müller")]
    [InlineData("a.b_c-d+e@f'g h")]
    public void TrySanitize_IsIdempotent(string raw)
    {
        Assert.True(ProvisionedUsername.TrySanitize(raw, out var once));
        Assert.True(ProvisionedUsername.TrySanitize(once, out var twice));
        Assert.Equal(once, twice);
    }

    [Fact]
    public void TrySanitize_EveryAcceptedPunctuationMember_SurvivesInsideAName()
    {
        // Derived from the constant the conformance rule pins against the recorded host regex, so widening
        // the allowlist without widening this cover is not possible: the loop grows with the constant.
        foreach (var member in ProvisionedUsername.AllowedPunctuation)
        {
            Assert.True(ProvisionedUsername.TrySanitize($"a{member}b", out var provisioned));
            Assert.Equal($"a{member}b", provisioned);
        }
    }
}
