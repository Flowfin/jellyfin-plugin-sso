// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Diagnostics;
using System.Linq;
using System.Threading.Tasks;
using Jellyfin.Plugin.SSO_Auth.Api.Events;
using MediaBrowser.Controller.Events;
using MediaBrowser.Controller.Events.Authentication;
using NSubstitute;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// Unit tests for <see cref="SsoLoginEvents"/> (#1142), the publisher that puts an SSO role-mapping denial
/// on Jellyfin's own event bus. The payload rules are the security-relevant half: a webhook destination
/// receives whatever is in these fields and it leaves the machine, so the tests pin what the event carries
/// and - more importantly - what it must never carry.
/// </summary>
public class SsoLoginEventsTests
{
    [Fact]
    public async Task PublishRoleDenied_CarriesTheProviderAndTheFixedReason()
    {
        var bus = Substitute.For<IEventManager>();
        var events = new SsoLoginEvents(bus, new CapturingLogger());

        await events.PublishRoleDeniedAsync("keycloak", "203.0.113.9");

        var published = SinglePublished(bus);
        Assert.Equal("SSO/keycloak", published.App);
        Assert.Equal(SsoLoginEvents.RoleDeniedReason, published.DeviceName);
        Assert.Equal("203.0.113.9", published.RemoteEndPoint);
    }

    [Fact]
    public async Task PublishUnresolvedUsernameDenied_CarriesItsOwnReason()
    {
        // The two refusals that share the OpenID denial arm must be distinguishable at the destination: one
        // is a provider policy decision, the other a missing claim or scope, and they ask an operator for
        // different things.
        var bus = Substitute.For<IEventManager>();
        var events = new SsoLoginEvents(bus, new CapturingLogger());

        await events.PublishUnresolvedUsernameDeniedAsync("keycloak", "203.0.113.9");

        var published = SinglePublished(bus);
        Assert.Equal(SsoLoginEvents.UnresolvedUsernameReason, published.DeviceName);
        Assert.NotEqual(SsoLoginEvents.RoleDeniedReason, SsoLoginEvents.UnresolvedUsernameReason);
        Assert.Equal(string.Empty, published.Username);
    }

    [Fact]
    public async Task PublishRoleDenied_NamesNobody()
    {
        // T-I1, applied harder than to the audit trail because this payload LEAVES the machine: the OpenID
        // denial has a claim-derived username to hand and the SAML denial a NameID, and neither may travel.
        // The field is empty on both protocols rather than on whichever happens to have less to say, so the
        // payload shape does not depend on which protocol refused.
        var bus = Substitute.For<IEventManager>();
        var events = new SsoLoginEvents(bus, new CapturingLogger());

        await events.PublishRoleDeniedAsync("keycloak", "203.0.113.9");

        var published = SinglePublished(bus);
        Assert.Equal(string.Empty, published.Username);
        Assert.True(published.UserId is null || published.UserId == Guid.Empty);
    }

    [Fact]
    public async Task PublishRoleDenied_WithNoBus_PublishesNothingAndDoesNotThrow()
    {
        // A host that supplies no event manager must leave the login path exactly as it was.
        var events = new SsoLoginEvents(events: null, new CapturingLogger());

        await events.PublishRoleDeniedAsync("keycloak", "203.0.113.9");
    }

    [Fact]
    public async Task PublishRoleDenied_WhenTheBusThrows_SwallowsAndLogs()
    {
        // A denial's answer must never depend on a notification. Jellyfin's own EventManager already catches
        // each consumer's exception, but the bus is an interface: this pins that a throwing implementation
        // cannot turn a clean 401 into a 500.
        var log = new CapturingLogger();
        var bus = Substitute.For<IEventManager>();
        bus.PublishAsync(Arg.Any<AuthenticationRequestEventArgs>())
            .Returns<Task>(_ => throw new InvalidOperationException("the bus is down"));
        var events = new SsoLoginEvents(bus, log);

        await events.PublishRoleDeniedAsync("keycloak", "203.0.113.9");

        Assert.Contains(log.Entries, e => e.Message.Contains("Could not publish", StringComparison.Ordinal));
    }

    [Fact]
    public async Task PublishRoleDenied_WhenTheBusNeverReturns_GivesUpWithinItsBudget()
    {
        // The case a catch cannot reach. The webhook consumer makes an outbound HTTP call to an
        // operator-configured destination on a client the host gives no timeout, and PublishAsync awaits
        // every consumer in turn - so a black-holed destination would hold a refusal that was already
        // decided. The budget is what keeps the 401 prompt; without it this test never returns.
        //
        // THE PATH IS WALKED ONCE BEFORE THE CLOCK STARTS AND THE WARM-UP IS NOT TIMED (#1591). The clock
        // reads wall time, so whatever the first call in a process touches for the first time - the event
        // argument types, the substituted bus, the logger's formatter - is charged to the budget under
        // assertion. On a cold process here that first touch reached 25.7 seconds against a 50 ms budget,
        // and the row failed on the first invocation and passed on the next one with nothing else changed.
        // The warm-up spends it outside the measurement. The five-second bound stays where it was, because
        // a row that answered a cold process by widening its own bound would stop proving what it names.
        var warmUpBus = Substitute.For<IEventManager>();
        warmUpBus.PublishAsync(Arg.Any<AuthenticationRequestEventArgs>()).Returns(new TaskCompletionSource().Task);
        await new SsoLoginEvents(warmUpBus, new CapturingLogger(), TimeSpan.FromMilliseconds(50)).PublishRoleDeniedAsync("keycloak", "203.0.113.9");


        var log = new CapturingLogger();
        var bus = Substitute.For<IEventManager>();
        var neverCompletes = new TaskCompletionSource();
        bus.PublishAsync(Arg.Any<AuthenticationRequestEventArgs>()).Returns(neverCompletes.Task);
        var events = new SsoLoginEvents(bus, log, TimeSpan.FromMilliseconds(50));

        var clock = Stopwatch.StartNew();
        await events.PublishRoleDeniedAsync("keycloak", "203.0.113.9");
        clock.Stop();


        Assert.True(clock.Elapsed < TimeSpan.FromSeconds(5), $"the publish held the refusal for {clock.Elapsed}");
        Assert.Contains(log.Entries, e => e.Message.Contains("Could not publish", StringComparison.Ordinal));
    }

    [Fact]
    public void TheProductionBudgetIsShortEnoughToReadAsASlowPageRatherThanAHungOne()
    {
        // The number the call sites actually run with, pinned so it cannot drift upward unnoticed: this is a
        // notification about a login that is refused either way, and nothing is lost by giving up early.
        Assert.True(SsoLoginEvents.PublishBudget <= TimeSpan.FromSeconds(5), $"the budget is {SsoLoginEvents.PublishBudget}");
        Assert.True(SsoLoginEvents.PublishBudget > TimeSpan.Zero);
    }

    private static AuthenticationRequestEventArgs SinglePublished(IEventManager bus)
    {
        var call = bus.ReceivedCalls().Single(c => string.Equals(c.GetMethodInfo().Name, "PublishAsync", StringComparison.Ordinal));
        return Assert.IsType<AuthenticationRequestEventArgs>(call.GetArguments()[0]);
    }
}
