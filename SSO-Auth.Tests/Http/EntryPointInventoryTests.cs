// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Linq;
using Microsoft.AspNetCore.Mvc;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// Pins <see cref="EntryPointInventory"/>, the substrate the per-field route rules consume (#1159). It is
/// built and proved first for one reason: every rule built on it asserts something about EVERY route a field
/// arrives on, so an inventory that quietly stops seeing a route does not make those rules fail. It makes
/// them pass, over a smaller surface, in silence. That is the failure this file exists to make loud.
/// <para>
/// Three kinds of assertion, and they are not interchangeable. The fixture pair pins what the walk must and
/// must not report, over test-local controllers whose whole content is visible here. The sentinel pins the
/// walk against the REAL assembly, so a walk that matches fixtures and nothing else fails. The pinned
/// examples name actions and parameters that exist today, so a rename is caught rather than absorbed.
/// </para>
/// </summary>
public class EntryPointInventoryTests
{
    // The must-catch fixture. Both parameters of Get are shapes an attribute-only reader gets wrong: one is
    // explicit, the other carries nothing at all and binds from the route by name - the shape OidChallenge
    // and SamlChallenge use for `provider`, which is the most route-multiplied field in the plugin.
    [Route("[controller]")]
    private sealed class FixtureController : ControllerBase
    {
        [HttpGet("thing/{id}")]
        public ActionResult Get(string id, [FromQuery] string filter) => Ok($"{id}{filter}");

        [HttpPost("thing/{id}")]
        [HttpPost("thing/alt/{id}")]
        public ActionResult Post(string id, [FromBody] FixturePayload payload) => Ok($"{id}{payload.Value}");

        // A public method on a controller that is not reachable over HTTP. It carries no verb attribute, so
        // it is not an action, and it must not appear in the inventory.
        public string HelperThatIsNotAnAction(string anything) => anything;

        // A method that carries a verb attribute and is still excluded from routing.
        [HttpGet("never")]
        [NonAction]
        public ActionResult NotRouted() => Ok();
    }

    private sealed class FixturePayload
    {
        public string Value { get; init; } = string.Empty;
    }

    // The adjacent must-not-catch fixture: same attribute, same method name, one difference - it is not a
    // controller.
    private sealed class NotAControllerAtAll
    {
        [HttpGet("thing/{id}")]
        public string Get(string id) => id;
    }

    [Fact]
    public void TheWalk_ReportsAnExplicitAndAnImplicitlyBoundParameter()
    {
        var entry = Assert.Single(EntryPointInventory.Of([typeof(FixtureController)]), e => e.Action == "Get");

        Assert.Equal("GET", entry.Method);
        Assert.Equal("thing/{id}", entry.Template);

        var id = Assert.Single(entry.Parameters, p => p.Name == "id");
        Assert.Equal(EntryPointSource.Route, id.Source);
        Assert.False(id.IsExplicit, "the route bind must be derived from the template, not from an attribute that is not there");

        var filter = Assert.Single(entry.Parameters, p => p.Name == "filter");
        Assert.Equal(EntryPointSource.Query, filter.Source);
        Assert.True(filter.IsExplicit);
    }

    [Fact]
    public void TheWalk_YieldsOneEntryPointPerRouteAttribute_NotOnePerAction()
    {
        // Two URLs a caller can arrive on is two entry points. Collapsing them to one would let a rule pass
        // by checking whichever of the two the walk happened to keep, and the plugin has four such pairs on
        // the login path alone (OID/r + OID/redirect, OID/p + OID/start, SAML/p + SAML/post, SAML/p + SAML/start).
        var posts = EntryPointInventory.Of([typeof(FixtureController)]).Where(e => e.Action == "Post").ToList();

        Assert.Equal(2, posts.Count);
        Assert.Equal(["thing/alt/{id}", "thing/{id}"], posts.Select(p => p.Template).Order(StringComparer.Ordinal));
        Assert.All(posts, p => Assert.Equal("POST", p.Method));
        Assert.All(posts, p => Assert.Equal(EntryPointSource.Body, Assert.Single(p.Parameters, x => x.Name == "payload").Source));
    }

    [Fact]
    public void TheWalk_ReportsNeitherANonActionMethodNorANonControllerType()
    {
        var fromController = EntryPointInventory.Of([typeof(FixtureController)]);
        var fromNonController = EntryPointInventory.Of([typeof(NotAControllerAtAll)]);

        Assert.DoesNotContain(fromController, e => e.Action == "HelperThatIsNotAnAction");
        Assert.DoesNotContain(fromController, e => e.Action == "NotRouted");
        Assert.Empty(fromNonController);

        // And the must-catch half of the same walk is still reported, so the two exclusions above are a real
        // decision rather than a walk that reports nothing at all.
        Assert.NotEmpty(fromController);
    }

    [Fact]
    public void TheWalk_OverTheRealAssembly_IsNonEmpty_AndMeetsItsFloor()
    {
        // The sentinel. A walk that stops matching - a changed base type, a controller moved out of the
        // assembly, an attribute namespace that no longer resolves - would otherwise turn every rule built
        // on this into a vacuous pass over an empty set.
        //
        // The floor is deliberately well under the real count rather than equal to it: this must fail when
        // the walk BREAKS, and never merely because an endpoint was legitimately added or removed. A test
        // that has to be edited on every ordinary change gets edited without being read.
        var entries = EntryPointInventory.OfThePlugin();

        Assert.NotEmpty(EntryPointInventory.ControllerTypes());
        Assert.True(
            entries.Count >= 30,
            $"The entry-point walk found only {entries.Count} entry points on the plugin assembly; it has stopped matching the real controllers, and every rule built on it would now pass over a surface that is too small (#1159).");
    }

    [Fact]
    public void TheWalk_OverTheRealAssembly_PinsANamedActionAndItsImplicitlyBoundParameter()
    {
        // The floor above proves the walk found SOMETHING. This proves it found the right thing, and it is
        // pinned on the shape a floor cannot see: OidChallenge's `provider` carries no binding attribute, so
        // an inventory that read attributes only would report this action with one parameter instead of two
        // and still clear any count-based sentinel.
        var challenges = EntryPointInventory.OfThePlugin().Where(e => e.Action == "OidChallenge").ToList();

        Assert.Equal(2, challenges.Count); // OID/p/{provider} and OID/start/{provider}
        Assert.All(challenges, e =>
        {
            var provider = Assert.Single(e.Parameters, p => p.Name == "provider");
            Assert.Equal(EntryPointSource.Route, provider.Source);
            Assert.False(provider.IsExplicit);
            Assert.Equal(typeof(string), provider.ParameterType);
        });
    }

    [Fact]
    public void TheWalk_OverTheRealAssembly_SeesEveryBindingSourceTheControllersActuallyUse()
    {
        // Each of these is a distinct way an attacker-influenced value enters the plugin, and a rule that
        // asks "every route this field arrives on" is wrong if the walk is blind to one of them. Asserted as
        // presence rather than as a count, so adding an endpoint does not move it.
        var sources = EntryPointInventory.OfThePlugin()
            .SelectMany(e => e.Parameters)
            .Select(p => p.Source)
            .Distinct()
            .ToList();

        Assert.Contains(EntryPointSource.Route, sources);
        Assert.Contains(EntryPointSource.Query, sources);
        Assert.Contains(EntryPointSource.Body, sources);
    }
}
