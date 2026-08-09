// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Runtime.CompilerServices;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Duende.IdentityModel.OidcClient;
using Jellyfin.Plugin.SSO_Auth.Api.Oidc;
using Microsoft.Extensions.Logging;
using NSubstitute;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// Pins what a provider-authored member name may do to the refusal entry <see cref="RepeatedMemberScreen"/>
/// writes (#1195).
///
/// The name is the one value in that entry the provider chooses, and it is put there deliberately: it is what
/// identifies the defect to report, and nothing relaxes the refusal, so an entry without it leaves an operator
/// with a broken login and no lead. Putting it there is what creates the exposure these rows bound.
///
/// <c>ReplaceLineEndings</c>, which is all the entry beside it gets, is not enough for this value. It passes a
/// raw vertical tab and a raw NUL straight through - a console sink advances a line on the first, a C-string
/// consumer truncates its record on the second - and it does not touch a right-to-left override, which
/// reorders the rest of the entry as it is displayed rather than inserting anything into it. So three
/// character classes come off the name, and each row below names the mutation it kills.
///
/// The fourth class #1195 names, the unpaired surrogate, is answered by measurement rather than by an arm:
/// <see cref="AnUnpairedSurrogate_NeverBecomesARepeatedMemberName"/> shows a provider cannot get one into this
/// value at all, and <see cref="TheBoundNeverCutsThroughAnAstralPair"/> covers the one thing that could
/// manufacture one, which is the plugin's own truncation.
///
/// Every row asserts the REFUSAL and not merely the entry. A screen that logged the name and then handed the
/// document on would write an identical entry, so each read also checks that the library was given the
/// screen's constant reason instead of the document, and that the JWKS the refused document named was never
/// fetched.
/// </summary>
public class RefusalEntryMemberNameTests
{
    private const string Authority = "https://idp-name.example.com";

    // An ordinary member name, long enough to be unmistakable in an entry and made only of characters no
    // class below removes, so a row that finds it intact has found the filter passing what it must pass.
    private const string Marker = "zzMemberNamezz";

    // The segment the entry uses to introduce the name. Quoted from the production template so a row cannot
    // pass against an entry that stopped carrying the name at all.
    private const string NameLeadIn = "the repeated member is named";

    [Fact]
    public async Task AnOrdinaryMemberName_ReachesTheEntryWhole()
    {
        // Kills: tightening the bound to a stub, and any filter that drops more than the three classes. A
        // ceiling-only proof passes against a two-character bound, which would throw away the one thing the
        // operator reads this entry to find.
        //
        // The fixture is the longest name the OpenID discovery metadata registry actually defines, so the
        // floor is derived from what a real document carries rather than from the constant that bounds it.
        const string Longest = "authorization_response_iss_parameter_supported";

        var entry = await RefusalEntryFor(Longest);

        Assert.Contains(NameLeadIn + " \"" + Longest + "\"", entry, StringComparison.Ordinal);
        Assert.DoesNotContain("[truncated]", entry, StringComparison.Ordinal);
    }

    [Theory]
    // The two ReplaceLineEndings passes through, which is why this class exists at all.
    [InlineData("\\u0000")]
    [InlineData("\\u000b")]
    // The ones it does remove, so the class is a superset of the strip rather than a neighbour of it.
    [InlineData("\\r")]
    [InlineData("\\n")]
    [InlineData("\\u000c")]
    [InlineData("\\u0085")]
    // Both control blocks, so the row is not written against the C0 range alone.
    [InlineData("\\u007f")]
    [InlineData("\\u009f")]
    public async Task AControlCharacterInTheName_NeverReachesTheEntry(string escape)
        => await AssertNeutralisedAtEveryPosition(escape);

    [Theory]
    // A right-to-left override forges by rearranging what is displayed. It is the reason this class is here.
    [InlineData("\\u202e")]
    [InlineData("\\u202d")]
    // A left-to-right isolate does the same through the newer mechanism, and a zero-width space and a soft
    // hyphen hide a difference between two names that read alike.
    [InlineData("\\u2066")]
    [InlineData("\\u200b")]
    [InlineData("\\u00ad")]
    public async Task AFormatCharacterInTheName_NeverReachesTheEntry(string escape)
        => await AssertNeutralisedAtEveryPosition(escape);

    [Theory]
    [InlineData("\\u2028")]
    [InlineData("\\u2029")]
    public async Task ALineOrParagraphSeparatorInTheName_NeverReachesTheEntry(string escape)
        => await AssertNeutralisedAtEveryPosition(escape);

    [Fact]
    public async Task AnOverlongMemberName_IsBoundedInTheEntry()
    {
        // Kills: deleting the bound. Measured before it existed: an 800 KB name is what one anonymous
        // challenge can put in front of this call. The fixture is smaller than that and still far past any
        // name a working provider emits, so it reaches the truncation instead of sitting under it.
        var name = new string('m', 8192);

        var entry = await RefusalEntryFor(name);

        Assert.True(
            entry.Length < 1024,
            $"the refusal entry carries {entry.Length} characters against an {name.Length}-character provider-authored member name");
        Assert.Contains("[truncated]", entry, StringComparison.Ordinal);

        // And not merely shorter overall: a bound applied to the wrong operand still lets a long run through.
        Assert.DoesNotContain(new string('m', 1024), entry, StringComparison.Ordinal);
    }

    [Fact]
    public async Task AValidAstralMemberName_ReachesTheEntryIntact()
    {
        // Kills: filtering surrogates as a class. That would answer #1195's fourth class by mangling every
        // legitimate name outside the basic plane, which is a filter doing damage rather than preventing it.
        const string Astral = "zz\U0001F600zz";

        var entry = await RefusalEntryFor("zz\\ud83d\\ude00zz");

        Assert.Contains(NameLeadIn + " \"" + Astral + "\"", entry, StringComparison.Ordinal);
    }

    [Fact]
    public async Task TheBoundNeverCutsThroughAnAstralPair()
    {
        // Kills: cutting at the bound without stepping back off a high surrogate.
        //
        // The bound is the only thing on this path that can manufacture an unpaired surrogate, and a half
        // pair corrupts the entry it lands in - which is one of the four things #1195 says the name must not
        // be able to do. The offsets are swept rather than aimed at the constant, so the row is derived from
        // the input space and stays true if the bound moves.
        for (var lead = 1; lead <= 300; lead++)
        {
            var entry = await RefusalEntryFor(new string('m', lead) + "\\ud83d\\ude00" + "zz");
            AssertNoHalfSurrogatePair(entry, lead);
        }
    }

    [Fact]
    public async Task AnUnpairedSurrogate_NeverBecomesARepeatedMemberName()
    {
        // The measurement behind the missing fourth arm. A provider cannot put an unpaired surrogate into
        // this value: a RAW one has no UTF-8 encoding, so the walk refuses the document before it starts, and
        // an ESCAPED one is a name GetString will not complete, so the walk reports Unreadable. Either way it
        // never holds a name to report.
        //
        // This row is what turns "no arm is needed" from a belief into a fact, and it goes red the day the
        // walk starts decoding leniently - which is the day the arm becomes owed.
        var spellings = new[]
        {
            "\\ud800",          // lone high surrogate
            "\\udc00",          // lone low surrogate
            "\\udc00\\ud800",   // a reversed pair, which is two unpaired surrogates rather than one pair
        };

        foreach (var spelling in spellings)
        {
            var json = "{\"a" + spelling + "\":1,\"a" + spelling + "\":2}";
            var verdict = StrictJson.Inspect(json, out var reported);

            Assert.Equal(StrictJson.Verdict.Unreadable, verdict);
            Assert.Null(reported);
        }

        // The raw spelling, which does not even reach the reader.
        var rawVerdict = StrictJson.Inspect("{\"a\ud800\":1,\"a\ud800\":2}", out var rawReported);
        Assert.Equal(StrictJson.Verdict.Unreadable, rawVerdict);
        Assert.Null(rawReported);

        // And at the seam the entry carries no name at all rather than an empty or corrupted one, so nothing
        // downstream reads a name that was never established.
        var (entry, failClosed) = await RefusalEntryAndFailClosedFor("{\"a\\ud800\":1,\"a\\ud800\":2}");
        Assert.DoesNotContain(NameLeadIn, entry, StringComparison.Ordinal);
        Assert.Contains(RepeatedMemberScreen.UninspectableReason, entry, StringComparison.Ordinal);
        Assert.Contains(RepeatedMemberScreen.UninspectableReason, failClosed, StringComparison.Ordinal);
    }

    [Fact]
    public void TheNeutralisationLivesInTheMethodThatLogs()
    {
        // Kills: lifting the bound or the filter out of the method that writes the entry. The log-forging
        // sanitizer this repository relies on does not propagate across a method boundary, so a helper that
        // returns a clean string leaves the analyzer reading an unsanitised value at the call - and no
        // behavioural test can tell the two apart, because both produce the same entry.
        var source = File.ReadAllText(Path.Combine(RepoRoot(), "SSO-Auth", "Api", "Oidc", "RepeatedMemberScreen.cs"));

        var start = source.IndexOf("private HttpResponseMessage Refuse(", StringComparison.Ordinal);
        Assert.True(start >= 0, "the refusing method was renamed; this rule points at a method that no longer exists");

        // The next member declaration at class indentation ends the body. The sentinel below is what keeps a
        // mis-parse from producing a span that trivially contains everything.
        var end = source.IndexOf("\n    private static ", start, StringComparison.Ordinal);
        Assert.True(end > start, "the method after Refuse moved; the span this rule reads no longer terminates");
        Assert.True(
            end - start < source.Length / 2,
            "the span read as one method covers half the file, so it is not one method");

        var body = source.Substring(start, end - start);
        foreach (var token in new[] { "MaxLoggedMemberNameChars", "char.IsHighSurrogate(", "char.IsControl(", "UnicodeCategory.Format", "Array.FindAll(", "_logger.LogWarning(" })
        {
            Assert.Contains(token, body, StringComparison.Ordinal);
            Assert.Equal(
                CountOf(source, token),
                CountOf(body, token) + CountOf(source[..start], token));
        }

        // The count identity above passes vacuously if a token appears nowhere, so the presence assertion is
        // paired with a check that the tokens the constant declaration legitimately puts above the method are
        // the only ones there.
        Assert.Equal(1, CountOf(source[..start], "MaxLoggedMemberNameChars = "));
    }

    // Drives one repeated member name through the real seam and returns the refusal entry, having first
    // established that the read actually REFUSED: the library was handed the screen's constant reason in
    // place of the document, and the JWKS that document named was never fetched. A screen that logged and
    // passed the document on satisfies neither.
    private static async Task<string> RefusalEntryFor(string jsonMemberName)
    {
        var (entry, failClosed) = await RefusalEntryAndFailClosedFor(
            "{\"" + jsonMemberName + "\":\"a\",\"" + jsonMemberName + "\":\"b\",\"issuer\":\"" + Authority + "\"}");

        Assert.Contains(RepeatedMemberScreen.RefusalReason, entry, StringComparison.Ordinal);
        Assert.Contains(RepeatedMemberScreen.RefusalReason, failClosed, StringComparison.Ordinal);
        return entry;
    }

    private static async Task<(string Entry, string FailClosed)> RefusalEntryAndFailClosedFor(string discovery)
    {
        var logger = new CapturingLogger();
        var router = new Router(discovery);

        var factory = Substitute.For<IHttpClientFactory>();
        factory.CreateClient(Arg.Any<string>()).Returns(_ => new HttpClient(router));

        var options = new OidcClientOptions { Authority = Authority };
        options.Policy.Discovery.AdditionalEndpointBaseAddresses.Add(new Uri(Authority).GetLeftPart(UriPartial.Authority));
        options.Policy.Discovery.ValidateEndpoints = false;

        var result = await OidcDiscoveryReader.ReadAsync(options, "name", factory, logger);

        Assert.False(result.Available);

        // Nothing beyond the refused document was fetched, which is the fact a report-and-pass-through screen
        // cannot produce.
        Assert.Equal(1, router.Requests);

        var entry = Assert.Single(logger.Entries, e => e.Message.StartsWith("Refused the OpenID", StringComparison.Ordinal));
        Assert.Equal(LogLevel.Warning, entry.Level);
        var failClosed = Assert.Single(logger.Entries, e => e.Message.StartsWith("Could not read the OpenID discovery document", StringComparison.Ordinal));
        return (entry.Message, failClosed.Message);
    }

    // Runs one hostile character at each position it can occupy in a member name and asserts two things at
    // once: the character is gone, and everything around it survived. Without the second half a filter that
    // dropped the whole name would pass every row here.
    private static async Task AssertNeutralisedAtEveryPosition(string escape)
    {
        // Decoded with the same reader the walk uses, so the row cannot be about a character the fixture
        // never actually carried.
        var hostile = JsonSerializer.Deserialize<string>("\"" + escape + "\"")!;
        Assert.Equal(1, hostile.Length);

        var placements = new (string Label, string JsonName)[]
        {
            ("leading", escape + Marker),
            ("interior", Marker[..6] + escape + Marker[6..]),
            ("trailing", Marker + escape),
        };

        foreach (var (label, jsonName) in placements)
        {
            var entry = await RefusalEntryFor(jsonName);

            Assert.DoesNotContain(hostile, entry, StringComparison.Ordinal);
            Assert.True(
                entry.Contains(NameLeadIn + " \"" + Marker + "\"", StringComparison.Ordinal),
                label + ": the entry does not carry the name the filter should have left behind: " + entry);
        }
    }

    private static void AssertNoHalfSurrogatePair(string entry, int lead)
    {
        for (var i = 0; i < entry.Length; i++)
        {
            if (char.IsHighSurrogate(entry[i]))
            {
                Assert.True(
                    i + 1 < entry.Length && char.IsLowSurrogate(entry[i + 1]),
                    $"a high surrogate stands alone in the entry at lead {lead}");
                i++;
                continue;
            }

            Assert.False(char.IsLowSurrogate(entry[i]), $"a low surrogate stands alone in the entry at lead {lead}");
        }
    }

    private static int CountOf(string haystack, string needle)
    {
        var count = 0;
        for (var i = haystack.IndexOf(needle, StringComparison.Ordinal); i >= 0; i = haystack.IndexOf(needle, i + needle.Length, StringComparison.Ordinal))
        {
            count++;
        }

        return count;
    }

    private static string RepoRoot([CallerFilePath] string thisFilePath = "") =>
        Directory.GetParent(Directory.GetParent(Path.GetDirectoryName(thisFilePath)!)!.FullName)!.FullName;

    // Serves the fixture for the well-known document and counts every outbound request, so a row can assert
    // the JWKS leg was never reached.
    private sealed class Router : HttpMessageHandler
    {
        private readonly string _discovery;

        internal Router(string discovery) => _discovery = discovery;

        internal int Requests { get; private set; }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Requests++;
            var url = request.RequestUri!.AbsoluteUri;
            var body = url.EndsWith("/.well-known/openid-configuration", StringComparison.Ordinal)
                ? _discovery
                : "{\"keys\":[]}";

            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(body, Encoding.UTF8, "application/json"),
                RequestMessage = request,
            });
        }
    }
}
