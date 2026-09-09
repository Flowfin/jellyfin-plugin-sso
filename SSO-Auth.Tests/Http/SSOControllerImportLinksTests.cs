// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Collections.ObjectModel;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using Jellyfin.Extensions.Json;
using Jellyfin.Plugin.SSO_Auth.Config;
using Microsoft.AspNetCore.Mvc;
using NSubstitute;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// In-process tests of what the link-import endpoint ANSWERS (#1520). The importer's own rules are covered
/// in <see cref="LinkImportTests"/>; what these pin is the property that surface had none of - a restore
/// that rebound nothing must not be indistinguishable from one that rebound everything.
///
/// It stood indistinguishable long enough to matter. The endpoint answered <c>204 No Content</c> whatever
/// the number was, so #1517 - a document arriving with its entries dropped - restored nothing, answered
/// success and left every account unlinked from <c>4.3.0-beta.43</c> onward, with the count reaching only
/// an audit line nobody reads mid-migration. These assertions are on the answer for that reason: an
/// operator holding the backup file must be able to see the number without the server log.
/// </summary>
[Collection("SSOController")]
public class SSOControllerImportLinksTests
{
    private static readonly Guid TargetAlice = Guid.Parse("7a19e700-0000-0000-0000-00000000000a");
    private static readonly Guid TargetBob = Guid.Parse("7a19e700-0000-0000-0000-00000000000b");
    private static readonly Guid TargetCarol = Guid.Parse("7a19e700-0000-0000-0000-00000000000c");

    [Fact]
    public async Task TheImport_AnswersHowManyLinksItRebound()
    {
        var harness = Harness();

        var result = Restore(await harness.Controller.ImportLinks(TwoLinks()).ConfigureAwait(true));

        Assert.Equal(2, result.Restored);
        Assert.Equal(
            new[] { "OpenID/idp:1", "SAML/adfs:1" },
            result.Providers.Select(entry => $"{entry.Protocol}/{entry.Provider}:{entry.Links}").ToArray());

        // The count is of restored entries, and the stored table is read back beside it because that is the
        // part the number cannot prove on its own: a body claiming two while the map holds none is the exact
        // failure #1517 was, one field further along. The two agree here because no entry repeats; a
        // document repeating one identical entry counts it twice and writes one link, which is the same
        // count the audit line has carried since #1129.
        Assert.Equal(TargetAlice, harness.Configuration.OidConfigs["idp"].CanonicalLinks["sub-alice"]);
        Assert.Equal(TargetBob, harness.Configuration.SamlConfigs["adfs"].CanonicalLinks["nameid-bob"]);
    }

    [Fact]
    public async Task TheTotal_IsTheLINKS_NotTheProvidersTheyArrivedOn()
    {
        // Written because the suite could not tell the two apart. Every other case here carries one link
        // per provider, so the sum of the links, the number of providers and the number of entries are the
        // same number, and a total built as `+= 1` per provider passed all 3683 tests. Three links on two
        // providers separates them: a total of 3 is the links, a total of 2 would be the providers.
        var harness = Harness();
        var document = TwoLinks();
        document.Links.Add(new LinkExportEntry
        {
            Protocol = LinkExport.OpenIdProtocol,
            Provider = "idp",
            CanonicalName = "sub-carol",
            Username = "carol",
        });
        harness.UserManager.GetUserByName("carol").Returns(TestUsers.Named("carol", TargetCarol));

        var result = Restore(await harness.Controller.ImportLinks(document).ConfigureAwait(true));

        Assert.Equal(3, result.Restored);
        Assert.Equal(
            new[] { "OpenID/idp:2", "SAML/adfs:1" },
            result.Providers.Select(entry => $"{entry.Protocol}/{entry.Provider}:{entry.Links}").ToArray());
    }

    [Fact]
    public void TheAnswer_SurvivesTheJsonBoundaryTheCallerReadsItAcross()
    {
        // The count is read by a browser rather than by C#, so the shape that matters is the serialized
        // one. #1517 was exactly a wire-shape defect that every in-process test passed straight through,
        // and Providers here is a get-only collection - safe only in the write direction. A zero total has
        // to survive too: dropped as a default it would reach the page as no count at all, and the page
        // would then report the #1517 case as an answer that said nothing.
        var json = JsonSerializer.Serialize(
            LinkImportResultDocument.Of(new[] { new LinkImportCount(LinkExport.OpenIdProtocol, "idp", 2) }),
            JsonDefaults.PascalCaseOptions);

        Assert.Equal(
            "{\"Restored\":2,\"Providers\":[{\"Protocol\":\"OpenID\",\"Provider\":\"idp\",\"Links\":2}]}",
            json);

        Assert.Equal(
            "{\"Restored\":0,\"Providers\":[]}",
            JsonSerializer.Serialize(LinkImportResultDocument.Of(Array.Empty<LinkImportCount>()), JsonDefaults.PascalCaseOptions));
    }

    [Fact]
    public async Task AnImportThatRestoredNothing_IsDistinguishableFromOneThatRestoredEverything()
    {
        // The whole point of the issue, asserted as the comparison rather than as two separate numbers:
        // before this change both calls produced a 204 with an empty body, so no caller could tell them
        // apart and the settings page printed one fixed sentence over both.
        var harness = Harness();

        var everything = Restore(await harness.Controller.ImportLinks(TwoLinks()).ConfigureAwait(true));
        var nothing = Restore(await harness.Controller.ImportLinks(new LinkExportDocument { FormatVersion = LinkExport.FormatVersion }).ConfigureAwait(true));

        Assert.Equal(2, everything.Restored);
        Assert.Equal(0, nothing.Restored);
        Assert.Empty(nothing.Providers);
        Assert.NotEqual(everything.Restored, nothing.Restored);
    }

    [Fact]
    public async Task AConfigurationExportPostedHere_AnswersThatItRestoredNothing()
    {
        // One of the three inputs #1520 measured against a running server. The two documents both declare
        // FormatVersion 1 and nothing else separates them, so the version gate passes and the wrong file
        // is applied as an empty one. The import is still right to apply it - it contradicts nothing - and
        // the zero in the answer is the only thing that tells the operator they posted the wrong export.
        var harness = Harness();

        var result = Restore(await harness.Controller.ImportLinks(new LinkExportDocument { FormatVersion = ConfigExport.FormatVersion }).ConfigureAwait(true));

        Assert.Equal(0, result.Restored);
        Assert.Empty(harness.Configuration.OidConfigs["idp"].CanonicalLinks);
    }

    [Fact]
    public async Task AnIssuerTheProviderDoesNotIssue_IsRefused_NamingBothIssuers()
    {
        // #1518 end to end, at the surface an operator actually uses. The importer's own rules are pinned in
        // LinkImportTests; what this row pins is that the endpoint READS what the provider issues before it
        // decides - a check that exists but is never wired reaches nobody. The server here is configured for
        // the provider as it is TODAY, and the backup names the address it had before the migration.
        var fixture = new OidcTokenFixture(MovedTo, "jf");
        using (fixture)
        {
            var harness = HarnessServing(fixture);

            var answer = await harness.Controller.ImportLinks(OneStaleIssuer()).ConfigureAwait(true);

            var refusal = Assert.IsType<BadRequestObjectResult>(answer);
            var message = Assert.IsType<string>(refusal.Value);
            Assert.Contains(WasAt, message, StringComparison.Ordinal);
            Assert.Contains(MovedTo, message, StringComparison.Ordinal);
            Assert.Empty(harness.Configuration.OidConfigs["idp"].CanonicalLinks);
            Assert.Empty(harness.Configuration.OidConfigs["idp"].CanonicalLinkIssuers);
        }
    }

    [Fact]
    public async Task AnIssuerTheProviderDoesIssue_IsRestoredWithItsBinding()
    {
        // The other half, and the one that decides whether the guard is usable rather than merely safe: the
        // ordinary restore - the file and the provider agree - still works, and the binding still travels
        // with the link. A guard that refused this would have made every migration worse than the bug.
        var fixture = new OidcTokenFixture(WasAt, "jf");
        using (fixture)
        {
            var harness = HarnessServing(fixture);

            var result = Restore(await harness.Controller.ImportLinks(OneStaleIssuer()).ConfigureAwait(true));

            Assert.Equal(1, result.Restored);
            Assert.Equal(TargetAlice, harness.Configuration.OidConfigs["idp"].CanonicalLinks["sub-alice"]);
            Assert.Equal(WasAt, harness.Configuration.OidConfigs["idp"].CanonicalLinkIssuers["sub-alice"]);
        }
    }

    [Fact]
    public async Task AnIssuerCarryingEntry_WithTheProviderUnreachable_IsRefusedRatherThanStoredUnverified()
    {
        // Fail closed when the check cannot be made. With no responder the harness's client factory hands
        // back nothing, so discovery fails exactly as an unreachable identity provider would. Storing the
        // file's issuer anyway is the defect this issue is named after, so the answer is a refusal that
        // says the comparison could not be made - not a success that looks like every other one.
        var harness = Harness();

        var answer = await harness.Controller.ImportLinks(OneStaleIssuer()).ConfigureAwait(true);

        var refusal = Assert.IsType<BadRequestObjectResult>(answer);
        Assert.Contains("could not be read to compare it against", Assert.IsType<string>(refusal.Value), StringComparison.Ordinal);
        Assert.Empty(harness.Configuration.OidConfigs["idp"].CanonicalLinks);
    }

    [Fact]
    public async Task ADocumentCarryingNoIssuer_ReadsNothingAndStillRestores()
    {
        // The availability half at the endpoint. TwoLinks() carries no issuer, and this harness has no
        // responder, so a restore that had to reach the identity provider first would fail here. It does
        // not: a document from before the binding existed, or one exported from a SAML-only server, is
        // restorable with the identity provider down.
        var harness = Harness();

        var result = Restore(await harness.Controller.ImportLinks(TwoLinks()).ConfigureAwait(true));

        Assert.Equal(2, result.Restored);
    }

    [Fact]
    public async Task ARestoreThatWroteIssuersWithoutComparingThem_SaysSoInTheAuditTrail()
    {
        // A restore that compared every issuer and one that compared none produce the same answer and the
        // same count, so the audit trail is the only place that difference survives an incident. The
        // templated provider is the one arm where issuers are written on the file's word, and the line that
        // reports it is the same one the configuration import uses when a toggle switches a default-on
        // protection off - a shape an operator already knows how to grep for.
        var fixture = new OidcTokenFixture(WasAt, "jf");
        using (fixture)
        {
            var harness = new SsoControllerHarness(
                configuration =>
                {
                    configuration.OidConfigs["idp"] = new OidConfig
                    {
                        Enabled = true,
                        OidEndpoint = fixture.Issuer,
                        DoNotValidateIssuerName = true,
                    };
                },
                httpResponder: request =>
                {
                    var url = request.RequestUri!.AbsoluteUri;
                    if (url == fixture.DiscoveryUrl)
                    {
                        return Json(fixture.Discovery().Replace("\"issuer\":\"" + fixture.Issuer + "\"", "\"issuer\":\"" + fixture.Issuer + "/{tenantid}\"", StringComparison.Ordinal));
                    }

                    return url == fixture.JwksUrl ? Json(fixture.Jwks()) : new HttpResponseMessage(HttpStatusCode.NotFound);
                });
            harness.UserManager.GetUserByName("alice").Returns(TestUsers.Named("alice", TargetAlice));

            var result = Restore(await harness.Controller.ImportLinks(OneStaleIssuer()).ConfigureAwait(true));

            Assert.Equal(1, result.Restored);
            Assert.Equal(WasAt, harness.Configuration.OidConfigs["idp"].CanonicalLinkIssuers["sub-alice"]);
            Assert.Contains(
                harness.ControllerLog.Entries,
                e => e.Message.Contains("[SSO Audit]", StringComparison.Ordinal)
                    && e.Message.Contains("were not compared", StringComparison.Ordinal)
                    && e.Message.Contains("idp", StringComparison.Ordinal));
        }
    }

    [Fact]
    public async Task AProviderWhoseJwksLegFails_RefusesTheRestore()
    {
        // A probe of what the discovery read actually depends on, kept as a row because the answer is the
        // opposite of what is easy to assume. The library fetches jwks_uri whenever the document advertises
        // one and errors the whole discovery response when that leg fails, so a healthy discovery host and
        // a sick key host still refuses the operator's entire restore. Relaxing RequireKeySet does NOT buy
        // tolerance of a failing fetch - it only accepts a document that advertises no key set at all -
        // which is why this change does not relax it and the migration document names the key host.
        var fixture = new OidcTokenFixture(WasAt, "jf");
        using (fixture)
        {
            var harness = new SsoControllerHarness(
                configuration =>
                {
                    configuration.OidConfigs["idp"] = new OidConfig { Enabled = true, OidEndpoint = fixture.Issuer };
                    configuration.SamlConfigs["adfs"] = new SamlConfig { Enabled = true };
                },
                httpResponder: request =>
                {
                    var url = request.RequestUri!.AbsoluteUri;
                    if (url == fixture.DiscoveryUrl)
                    {
                        return Json(fixture.Discovery());
                    }

                    return new HttpResponseMessage(HttpStatusCode.InternalServerError);
                });
            harness.UserManager.GetUserByName("alice").Returns(TestUsers.Named("alice", TargetAlice));

            var answer = await harness.Controller.ImportLinks(OneStaleIssuer()).ConfigureAwait(true);

            var refusal = Assert.IsType<BadRequestObjectResult>(answer);
            Assert.Contains("could not be read to compare it against", Assert.IsType<string>(refusal.Value), StringComparison.Ordinal);
            Assert.Empty(harness.Configuration.OidConfigs["idp"].CanonicalLinks);
        }
    }

    // The two addresses of one identity provider across an ordinary migration: the backup names the first,
    // the server is configured for the second.
    private const string WasAt = "https://idp-import-was.example.test";
    private const string MovedTo = "https://idp-import-now.example.test";

    private static LinkExportDocument OneStaleIssuer() => new()
    {
        FormatVersion = LinkExport.FormatVersion,
        Links = new Collection<LinkExportEntry>
        {
            new() { Protocol = LinkExport.OpenIdProtocol, Provider = "idp", CanonicalName = "sub-alice", Username = "alice", Issuer = WasAt },
        },
    };

    private static SsoControllerHarness HarnessServing(OidcTokenFixture fixture)
    {
        var harness = new SsoControllerHarness(
            configuration =>
            {
                configuration.OidConfigs["idp"] = new OidConfig { Enabled = true, OidEndpoint = fixture.Issuer };
                configuration.SamlConfigs["adfs"] = new SamlConfig { Enabled = true };
            },
            httpResponder: request =>
            {
                var url = request.RequestUri!.AbsoluteUri;
                if (url == fixture.DiscoveryUrl)
                {
                    return Json(fixture.Discovery());
                }

                return url == fixture.JwksUrl ? Json(fixture.Jwks()) : new HttpResponseMessage(HttpStatusCode.NotFound);
            });

        harness.UserManager.GetUserByName("alice").Returns(TestUsers.Named("alice", TargetAlice));
        harness.UserManager.GetUserByName("bob").Returns(TestUsers.Named("bob", TargetBob));
        return harness;
    }

    private static HttpResponseMessage Json(string body) => new HttpResponseMessage(HttpStatusCode.OK)
    {
        Content = new StringContent(body, Encoding.UTF8, "application/json"),
    };

    private static LinkImportResultDocument Restore(ActionResult answer) =>
        Assert.IsType<LinkImportResultDocument>(Assert.IsType<OkObjectResult>(answer).Value);

    private static LinkExportDocument TwoLinks() => new()
    {
        FormatVersion = LinkExport.FormatVersion,
        Links = new Collection<LinkExportEntry>
        {
            new() { Protocol = LinkExport.OpenIdProtocol, Provider = "idp", CanonicalName = "sub-alice", Username = "alice" },
            new() { Protocol = LinkExport.SamlProtocol, Provider = "adfs", CanonicalName = "nameid-bob", Username = "bob" },
        },
    };

    private static SsoControllerHarness Harness()
    {
        var harness = new SsoControllerHarness(configuration =>
        {
            configuration.OidConfigs["idp"] = new OidConfig { Enabled = true };
            configuration.SamlConfigs["adfs"] = new SamlConfig { Enabled = true };
        });

        harness.UserManager.GetUserByName("alice").Returns(TestUsers.Named("alice", TargetAlice));
        harness.UserManager.GetUserByName("bob").Returns(TestUsers.Named("bob", TargetBob));
        return harness;
    }
}
