// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using Duende.IdentityModel.OidcClient;
using Jellyfin.Plugin.SSO_Auth.Api.Oidc;
using Microsoft.Extensions.Logging;
using NSubstitute;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// The repeated-member screen on the role-claim path (#1324), phase 2 of #1053. That issue settled what an
/// unreadable role claim means - it establishes nothing, so nothing the document says is used - and left the
/// code to this one. The substance is the clause about the second parser: the round-2 finding on PR #1032 was
/// not that an unreadable document produced no roles, it was that it produced "proceed" and the walk then fell
/// through to Newtonsoft, which granted the attacker's last-occurrence roles.
/// <para>
/// The screen is narrowed to the object scopes the configured path enters, and that narrowing is an
/// availability decision with a security bound. Every member of an entered scope is still compared, because
/// which members the reader indexes inside a scope is not something the screen can know; but a repeat in a
/// sibling the reader never opens is admitted, because it changes nothing the reader reads and refusing it
/// would let an unrelated vendor extension in the provider's own claim deny every login.
/// </para>
/// <para>
/// Every refusing row here has a control beside it - the same document without the repeat, resolving to a
/// named role set. A screen that refused everything would satisfy the refusals on their own, and the price of
/// this change is paid in logins, so a false refusal is the failure to guard against as much as a false pass.
/// </para>
/// </summary>
public class RoleClaimScopeScreenTests
{
    // The paths the rows are read along. Segment 0 names the claim; the rest is the walk into its value.
    private static readonly string[] TwoSegment = { "realm_access", "roles" };
    private static readonly string[] FourSegment = { "claim", "resource_access", "jellyfin", "roles" };

    private const string Authority = "https://idp-scope-screen.example.com";

    public static TheoryData<string> RefusedRepeats() => new()
    {
        "the role member named twice at the root of the claim value",
        "a repeat in an intermediate segment's object",
        "a repeat inside the terminal object, in object-map mode",
        "a repeat spelled with a unicode escape on one of its two occurrences",
    };

    public static TheoryData<string> AdmittedDocuments() => new()
    {
        "a repeat in a sibling object the configured path never enters",
        "sibling scopes legitimately reusing a name",
        "a member name differing from another only in case",
        "a repeat inside an object carried by an on-path array",
        "the ordinary document, two-segment array path",
        "the ordinary document, four-segment array path",
        "the ordinary document, one-segment object map",
        "the ordinary document, two-segment object map",
        "the ordinary document, one-segment verbatim value",
    };

    [Theory]
    [MemberData(nameof(RefusedRepeats))]
    public void RoleClaimScreen_RefusesARepeatInAScopeTheReaderEnters(string shape)
    {
        var (path, objectMap, repeated, control, controlRoles) = Row(shape);

        var refused = OidcRoleExtractor.ExtractRoles(path, repeated, objectMap);

        Assert.Equal(OidcRoleExtractor.Outcome.RepeatedMember, refused.Outcome);
        Assert.Empty(refused.Roles);

        // The positive control. Without it the row above passes on a screen that refuses every document, and
        // on a fixture whose path never resolved in the first place.
        var resolved = OidcRoleExtractor.ExtractRoles(path, control, objectMap);

        Assert.Equal(OidcRoleExtractor.Outcome.Resolved, resolved.Outcome);
        Assert.Equal(controlRoles, resolved.Roles);
    }

    [Theory]
    [MemberData(nameof(AdmittedDocuments))]
    public void RoleClaimScreen_AdmitsWhatTheReaderNeverReads(string shape)
    {
        var (path, objectMap, _, document, roles) = Row(shape);

        var result = OidcRoleExtractor.ExtractRoles(path, document, objectMap);

        Assert.Equal(OidcRoleExtractor.Outcome.Resolved, result.Outcome);
        Assert.Equal(roles, result.Roles);
    }

    [Fact]
    public void ARepeatUnderAnOnPathArray_IsNotRefusedAsARepeat()
    {
        // The array frame ends the descent, so the objects an array carries are not the scope the next key
        // names. Without that, a provider whose intermediate segment holds a list of objects would have every
        // one of them screened as if it sat on the path.
        //
        // Its own row because the outcome is neither a refusal nor a resolution: the reader wants an object at
        // "resource_access" and finds an array, which is PathNotResolved. Folded into the admitted table it
        // would have had to assert Resolved, and it would have been dropped instead of stated.
        var value = "{\"resource_access\":[{\"jellyfin\":1,\"jellyfin\":2}]}";

        var result = OidcRoleExtractor.ExtractRoles(FourSegment, value, false);

        Assert.Equal(OidcRoleExtractor.Outcome.PathNotResolved, result.Outcome);
        Assert.Empty(result.Roles);
    }

    // Rows rather than InlineData, because one of them cannot survive an attribute: a raw unpaired surrogate
    // in an attribute argument comes back out of metadata as replacement characters, which is a perfectly
    // readable document and would have made that row assert the opposite of what it is for. Measured - the row
    // failed exactly that way before it moved here.
    public static TheoryData<string> UnreadableGrammars() => new()
    {
        string.Empty,
        "   ",
        "not-json",
        "{\"roles\":[\"admin\"]",
        "17",
        "[1,2,3]",
        "{\"roles\":[\"admin\"],\"a\\ud800\":1}",
        "{\"roles\":[\"admin\"],\"a\uD800\":1}",
    };

    [Theory]
    [MemberData(nameof(UnreadableGrammars))]
    public void EveryUnreadableGrammar_YieldsNoRolesWithoutConsultingTheSecondParser(string claimValue)
    {
        // One row per grammar the #1053 table calls Unreadable, including the two the reader used to read
        // perfectly well - the escaped and the raw unpaired surrogate, which resolved with roles before this.
        var result = OidcRoleExtractor.ExtractRoles(TwoSegment, claimValue, false);

        Assert.Equal(OidcRoleExtractor.Outcome.Unreadable, result.Outcome);
        Assert.Empty(result.Roles);

        // That Newtonsoft was not consulted is what the reason says, and it says it by being this one.
        // ValueNotJson is returned only from inside the try that runs the parser, so a fall-through would
        // report that or a resolution, never Unreadable.
        Assert.NotEqual(OidcRoleExtractor.Outcome.ValueNotJson, result.Outcome);
    }

    [Fact]
    public async Task BothCallersTreatUnreadableTheSameWay()
    {
        // The same bytes, to the two places this walk sits on: the discovery read, where it screens a provider
        // response before the identity library parses it, and the role path, where it screens a claim value
        // before Newtonsoft does. A document neither can read must be used by neither.
        //
        // The CONSEQUENCES differ, and that is a property rather than a discrepancy, so the test says which
        // and why. The discovery document decides the login anchor and the validation keys, so a read that
        // establishes nothing leaves nothing to log in against and the whole read is unavailable. The role
        // claim decides privileges on top of a token that has already been validated, so a claim that
        // establishes nothing grants no roles and the login is decided by whatever the configuration says
        // about a user with none. One refusal ends the read; the other ends the grant.
        const string Unreadable = "{\"a\\ud800\":1}";

        var http = new StubFactory(Unreadable);
        var logger = new CapturingLogger();

        var discovery = await OidcDiscoveryReader.ReadAsync(OptionsFor(Authority), "kc", http.Factory, logger);

        Assert.False(discovery.Available);
        Assert.Equal(OidcDiscoveryRefusal.Uninspectable, discovery.Refusal);
        Assert.Contains(
            logger.Entries,
            e => e.Message.Contains(RepeatedMemberScreen.UninspectableReason, StringComparison.Ordinal));

        var roles = OidcRoleExtractor.ExtractRoles(TwoSegment, Unreadable, false);

        Assert.Equal(OidcRoleExtractor.Outcome.Unreadable, roles.Outcome);
        Assert.Empty(roles.Roles);

        // Neither used anything the document said. On the discovery side that means the JWKS URL it named was
        // never requested - one fetch, the document itself - and on the role side it means no role reached the
        // caller from a value nothing could read.
        Assert.Equal(1, http.Requests);
    }

    // shape -> (path, object-map mode, the repeating document, the control document, the control's roles).
    // One source for both theories so a shape cannot be asserted under one name and defined under another.
    private static (string[] Path, bool ObjectMap, string Repeated, string Control, List<string> Roles) Row(string shape) => shape switch
    {
        "the role member named twice at the root of the claim value" =>
            (TwoSegment, false, "{\"roles\":[\"admin\"],\"roles\":[\"user\"]}", "{\"roles\":[\"admin\"]}", new List<string> { "admin" }),

        "a repeat in an intermediate segment's object" =>
            (FourSegment,
             false,
             "{\"resource_access\":{\"jellyfin\":{\"roles\":[\"media\"]},\"jellyfin\":{\"roles\":[\"admin\"]}}}",
             "{\"resource_access\":{\"jellyfin\":{\"roles\":[\"media\"]}}}",
             new List<string> { "media" }),

        "a repeat inside the terminal object, in object-map mode" =>
            (TwoSegment,
             true,
             "{\"roles\":{\"media\":{\"org\":\"a\"},\"media\":{\"org\":\"b\"}}}",
             "{\"roles\":{\"media\":{\"org\":\"a\"}}}",
             new List<string> { "media" }),

        // \u0072 is "r", so the two names are the same name once unescaped. A screen comparing raw spellings
        // would see two members and admit the document.
        "a repeat spelled with a unicode escape on one of its two occurrences" =>
            (TwoSegment, false, "{\"roles\":[\"admin\"],\"\\u0072oles\":[\"user\"]}", "{\"\\u0072oles\":[\"admin\"]}", new List<string> { "admin" }),

        // The narrowing itself: "vendor" is not on the path, so the reader never opens it.
        "a repeat in a sibling object the configured path never enters" =>
            (TwoSegment, false, string.Empty, "{\"roles\":[\"admin\"],\"vendor\":{\"x\":1,\"x\":2}}", new List<string> { "admin" }),

        // Two scopes reusing one name is the ordinary shape of a document, not a repeat - and neither of these
        // is entered anyway.
        "sibling scopes legitimately reusing a name" =>
            (TwoSegment, false, string.Empty, "{\"roles\":[\"admin\"],\"p\":{\"kid\":1},\"q\":{\"kid\":2}}", new List<string> { "admin" }),

        // Ordinal, matching the discovery screen's decision (#1191): every reader on this path indexes a name
        // it spells itself, so folding case would refuse documents nothing misreads.
        "a member name differing from another only in case" =>
            (TwoSegment, false, string.Empty, "{\"roles\":[\"admin\"],\"ROLES\":[\"user\"]}", new List<string> { "admin" }),

        // An array under the terminal key carries objects the reader skips (only string elements are taken),
        // so a repeat inside one is not a scope anything reads.
        "a repeat inside an object carried by an on-path array" =>
            (TwoSegment, false, string.Empty, "{\"roles\":[\"admin\",{\"x\":1,\"x\":2}]}", new List<string> { "admin" }),

        "the ordinary document, two-segment array path" =>
            (TwoSegment, false, string.Empty, "{\"roles\":[\"admin\",\"user\"]}", new List<string> { "admin", "user" }),

        "the ordinary document, four-segment array path" =>
            (FourSegment, false, string.Empty, "{\"resource_access\":{\"jellyfin\":{\"roles\":[\"media\"]}}}", new List<string> { "media" }),

        "the ordinary document, one-segment object map" =>
            (new[] { "urn:zitadel:iam:org:project:roles" }, true, string.Empty, "{\"admin\":{\"org\":\"a\"},\"user\":{\"org\":\"a\"}}", new List<string> { "admin", "user" }),

        "the ordinary document, two-segment object map" =>
            (TwoSegment, true, string.Empty, "{\"roles\":{\"admin\":{\"org\":\"a\"}}}", new List<string> { "admin" }),

        // A one-segment path in array mode never parses the value at all, so the screen must not turn a plain
        // role string into an unreadable document.
        "the ordinary document, one-segment verbatim value" =>
            (new[] { "Role" }, false, string.Empty, "jellyfin-admin", new List<string> { "jellyfin-admin" }),

        _ => throw new ArgumentOutOfRangeException(nameof(shape), shape, "No row is defined for this shape."),
    };

    private static OidcClientOptions OptionsFor(string authority)
    {
        var options = new OidcClientOptions { Authority = authority };
        options.Policy.Discovery.AdditionalEndpointBaseAddresses.Add(new Uri(authority).GetLeftPart(UriPartial.Authority));
        options.Policy.Discovery.RequireHttps = true;
        options.Policy.Discovery.ValidateIssuerName = true;
        options.Policy.Discovery.ValidateEndpoints = true;
        return options;
    }

    // Serves one body to everything and counts what was asked for, so "the document's own URLs were never
    // dereferenced" is an observation rather than an inference.
    private sealed class StubFactory
    {
        private readonly string _body;

        internal StubFactory(string body)
        {
            _body = body;
            var factory = Substitute.For<IHttpClientFactory>();
            factory.CreateClient(Arg.Any<string>()).Returns(_ => new HttpClient(new StubHttpMessageHandler(Handle)));
            Factory = factory;
        }

        internal IHttpClientFactory Factory { get; }

        internal int Requests { get; private set; }

        private HttpResponseMessage Handle(HttpRequestMessage request)
        {
            Requests++;
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(_body, Encoding.UTF8, "application/json"),
            };
        }
    }
}
