// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Net;
using System.Net.Http;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Jellyfin.Plugin.SSO_Auth.Api.Net;
using MediaBrowser.Controller;
using Microsoft.Extensions.DependencyInjection;
using NSubstitute;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// Tests for <see cref="SsoHttp"/> - the single home for the plugin's outbound HTTP policy (#318, #378).
/// <see cref="SsoHttp.CreateClient"/> must resolve the SSRF-hardened <see cref="SsoHttp.OutboundClientName"/>
/// named client from the factory (whose primary handler is the hardened transport in production, #755) with
/// the plugin User-Agent applied, so every server-to-provider call is identifiable and transport-guarded from
/// one definition.
/// </summary>
public class SsoHttpTests
{
    // Opt in to binding a listener off loopback on Windows - see LanListenerAddress for why it is off by
    // default and what answering the dialog it avoids actually costs.
    private const string LanBindOptIn = "SSO_TESTS_ALLOW_LAN_BIND";

    [Fact]
    public void TheLanListenerGate_SkipsInsteadOfBindingOffLoopback_OnAWindowsRunThatDidNotOptIn()
    {
        // #1227. Four tests in this file bind a listener to this machine's own LAN interface address, and
        // that bind is what raises the Windows firewall consent dialog - the administrator prompt that made
        // the suite unrunnable without admin rights. The gate is the whole repair, so it is asserted here
        // rather than assumed from a skip that nobody reads: remove its Windows arm and this goes red on a
        // Windows run that has a LAN address, widen it to every platform and the branch below goes red on
        // the Linux legs. The condition is re-derived from the environment rather than read back from the
        // gate, so a gate that decided the opposite would not agree with it.
        var (address, reason) = LanListenerAddress();
        var optedIn = string.Equals(Environment.GetEnvironmentVariable(LanBindOptIn), "1", StringComparison.Ordinal);

        if (OperatingSystem.IsWindows() && !optedIn)
        {
            Assert.Null(address);
            Assert.Contains(LanBindOptIn, reason, StringComparison.Ordinal); // the way out is named in the skip
        }
        else
        {
            // Everywhere else the gate has to be transparent. A repair that skipped these tests on Linux
            // too would take the #1058 coverage with it and still leave every run green.
            Assert.Equal(FindLocalPrivateAddress(), address);
        }
    }

    [Fact]
    public void CreateClient_ResolvesTheNamedHardenedClient_AndAppliesTheUserAgent()
    {
        using var factoryClient = new HttpClient();
        var factory = Substitute.For<IHttpClientFactory>();
        // CreateClient must ask for the SSRF-hardened OUTBOUND client by name (#755): in production that name
        // is registered with the hardened SocketsHttpHandler, so requesting the default client instead would
        // silently bypass the connect-time guard. A test's stub/loopback factory returns its own client for
        // this name, keeping an in-process IdP reachable.
        factory.CreateClient(SsoHttp.OutboundClientName).Returns(factoryClient);

        var client = SsoHttp.CreateClient(factory);

        Assert.Same(factoryClient, client); // the named client is used, not the default and not a fresh one
        factory.Received(1).CreateClient(SsoHttp.OutboundClientName);
        // The whole User-Agent must round-trip against the single-sourced constant - a wrong version or URL
        // would slip past a substring check.
        Assert.Equal(SsoHttp.UserAgent, client.DefaultRequestHeaders.UserAgent.ToString());
    }

    [Fact]
    public void CreateHardenedHandler_IsConfiguredWithTheSsrfConnectGuardAndNoProxy()
    {
        // The transport guard cannot be exercised at unit level (it fires only on a real socket connect, and
        // the higher-level tests stub the message handler, #385) - so pin its CONFIGURATION here, so a
        // regression that drops the ConnectCallback, re-enables the system proxy (which would make the guard
        // validate the proxy instead of the host), or unbounds redirects fails this test rather than silently
        // reopening the SSRF / DNS-rebinding vector (#755, #370).
        using var handler = SsoHttp.CreateHardenedHandler();

        Assert.NotNull(handler.ConnectCallback);
        Assert.False(handler.UseProxy);
        Assert.True(handler.AllowAutoRedirect);
        Assert.Equal(5, handler.MaxAutomaticRedirections);
    }

    [Theory]
    [InlineData("http://127.0.0.1")] // IPv4 loopback literal
    [InlineData("http://[::1]")] // IPv6 loopback literal
    [InlineData("http://10.0.0.1")] // RFC1918 private literal
    [InlineData("http://169.254.169.254")] // link-local cloud metadata endpoint
    [InlineData("http://localhost")] // a NAME that resolves to loopback
    public async Task HardenedHandler_RefusesAConnectionToABlockedAddress_AtTheSocketLayer(string baseUrl)
    {
        // #928 U7 - the real socket-level integration test the configuration pin above explicitly could not
        // provide. This drives the ACTUAL hardened handler (its ConnectCallback resolves the host and refuses
        // any blocked address before connecting), so a regression that lets the guard connect to a
        // loopback / RFC1918 / link-local address is a red build - not merely a changed handler property.
        // A live listener on the loopback port proves the point: the guard must refuse BEFORE any socket
        // reaches it.
        using var listener = new BlockedListener();
        using var handler = SsoHttp.CreateHardenedHandler();
        using var client = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(10) };

        var target = $"{baseUrl}:{listener.Port}/";
        var ex = await Assert.ThrowsAsync<HttpRequestException>(
            () => client.GetAsync(target, TestContext.Current.CancellationToken));

        // The guard's own diagnostics - proves the refusal came from ConnectToAllowedAddressAsync, not an
        // unrelated transport error.
        Assert.Contains("blocked address", ex.Message, StringComparison.OrdinalIgnoreCase);
        // And nothing reached the socket: the listener never accepted a connection.
        Assert.False(listener.Accepted, "the SSRF guard let a socket reach the blocked loopback listener");
    }

    [Fact]
    public void CreateClient_WithoutTheOptIn_ResolvesTheStrictNamedClient()
    {
        // Strict by default is the whole safety property of #1179: SamlMetadataImporter and any future
        // caller pass no flag, so they must keep landing on the fully-guarded client. A default that
        // leaked the other way would relax the guard for callers that never asked.
        using var factoryClient = new HttpClient();
        var factory = Substitute.For<IHttpClientFactory>();
        factory.CreateClient(SsoHttp.OutboundClientName).Returns(factoryClient);

        Assert.Same(factoryClient, SsoHttp.CreateClient(factory));
        Assert.Same(factoryClient, SsoHttp.CreateClient(factory, allowPrivateNetworkAddresses: false));

        factory.Received(2).CreateClient(SsoHttp.OutboundClientName);
        factory.DidNotReceive().CreateClient(SsoHttp.PrivateOutboundClientName);
    }

    [Fact]
    public void CreateClient_WithTheOptIn_ResolvesThePrivatePermittedNamedClient()
    {
        // The relaxation is baked into WHICH client is resolved, not carried as an ambient per-request
        // mode: the handlers are long-lived and shared across concurrent logins, so a mode that is not part
        // of the client's identity could leak to a provider that never opted in.
        using var factoryClient = new HttpClient();
        var factory = Substitute.For<IHttpClientFactory>();
        factory.CreateClient(SsoHttp.PrivateOutboundClientName).Returns(factoryClient);

        var client = SsoHttp.CreateClient(factory, allowPrivateNetworkAddresses: true);

        Assert.Same(factoryClient, client);
        factory.Received(1).CreateClient(SsoHttp.PrivateOutboundClientName);
        factory.DidNotReceive().CreateClient(SsoHttp.OutboundClientName);
        Assert.Equal(SsoHttp.UserAgent, client.DefaultRequestHeaders.UserAgent.ToString());
    }

    [Fact]
    public void TheTwoOutboundClientNames_AreDistinct()
    {
        // If these ever collide, one registration silently wins and every caller shares whichever tier that
        // was - the leak this whole design exists to prevent.
        Assert.NotEqual(SsoHttp.OutboundClientName, SsoHttp.PrivateOutboundClientName);
    }

    [Theory]
    [InlineData("http://127.0.0.1")] // IPv4 loopback literal
    [InlineData("http://[::1]")] // IPv6 loopback literal
    [InlineData("http://169.254.169.254")] // link-local cloud metadata endpoint
    [InlineData("http://[fe80::1]")] // IPv6 link-local
    [InlineData("http://192.0.0.192")] // IETF protocol assignments (Oracle Cloud metadata)
    [InlineData("http://localhost")] // a NAME that resolves to loopback
    public async Task PrivatePermittedHandler_StillRefusesTheNeverRelaxableAddresses(string baseUrl)
    {
        // The opt-in widens the guard to the admin's own network - it must not open the ranges #1058 said
        // stay closed regardless. The live loopback listener again proves the refusal happens BEFORE any
        // socket reaches it.
        using var listener = new BlockedListener();
        using var handler = SsoHttp.CreateHardenedHandler(AddressPolicy.PrivateNetworkPermitted);
        using var client = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(10) };

        var target = $"{baseUrl}:{listener.Port}/";
        var ex = await Assert.ThrowsAsync<HttpRequestException>(
            () => client.GetAsync(target, TestContext.Current.CancellationToken));

        Assert.Contains("blocked address", ex.Message, StringComparison.OrdinalIgnoreCase);
        Assert.False(listener.Accepted, "the private-permitted guard let a socket reach a never-relaxable listener");
    }

    [Fact]
    public async Task PrivatePermittedHandler_ConnectsToAnRfc1918Address_WhereTheStrictOneRefuses()
    {
        // The reproduction from #1058, at the socket layer: an IdP on the admin's own LAN. Bind a real
        // listener to this machine's own private-range interface address and drive both handlers at it -
        // the strict one must refuse before connecting, the private-permitted one must get through.
        var (privateAddress, skipReason) = LanListenerAddress();
        Assert.SkipWhen(privateAddress is null, skipReason);

        using var listener = new PrivateListener(privateAddress!);
        var target = $"http://{privateAddress}:{listener.Port}/";

        using (var strictHandler = SsoHttp.CreateHardenedHandler())
        using (var strictClient = new HttpClient(strictHandler) { Timeout = TimeSpan.FromSeconds(10) })
        {
            var ex = await Assert.ThrowsAsync<HttpRequestException>(
                () => strictClient.GetAsync(target, TestContext.Current.CancellationToken));

            // The exact failure the reporter saw, from SsoHttp's own diagnostics.
            Assert.Contains("The outbound host resolves only to blocked addresses.", ex.Message, StringComparison.Ordinal);
            Assert.False(listener.Accepted, "the strict guard connected to a private address");
        }

        using var handler = SsoHttp.CreateHardenedHandler(AddressPolicy.PrivateNetworkPermitted);
        using var client = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(10) };

        using var response = await client.GetAsync(target, TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);
        Assert.True(listener.Accepted, "the private-permitted guard did not reach the private-address listener");
    }

    [Fact]
    public async Task CompositionRoot_GivesEachOutboundName_ItsOwnTier()
    {
        // Which tier a name carries is decided in SsoOnlyServiceRegistrator, and until now nothing read that
        // decision back. The conformance rosters allow that file to name the relaxation, and the tests above
        // build handlers directly - so registering the STRICT name with the relaxed policy would have
        // relaxed every caller that names no tier, including the SAML metadata importer, with the whole
        // suite still green. This drives the two registered names at a real socket instead.
        var (privateAddress, skipReason) = LanListenerAddress();
        Assert.SkipWhen(privateAddress is null, skipReason);

        var services = new ServiceCollection();
        services.AddLogging();
        new SsoOnlyServiceRegistrator().RegisterServices(services, Substitute.For<IServerApplicationHost>());
        await using var provider = services.BuildServiceProvider();
        var factory = provider.GetRequiredService<IHttpClientFactory>();

        using var listener = new PrivateListener(privateAddress!);
        var target = $"http://{privateAddress}:{listener.Port}/";

        using (var strict = factory.CreateClient(SsoHttp.OutboundClientName))
        {
            strict.Timeout = TimeSpan.FromSeconds(10);
            var ex = await Assert.ThrowsAsync<HttpRequestException>(
                () => strict.GetAsync(target, TestContext.Current.CancellationToken));

            Assert.Contains("The outbound host resolves only to blocked addresses.", ex.Message, StringComparison.Ordinal);
            Assert.False(listener.Accepted, "the registered strict client connected to a private address");
        }

        using var relaxed = factory.CreateClient(SsoHttp.PrivateOutboundClientName);
        relaxed.Timeout = TimeSpan.FromSeconds(10);
        using var response = await relaxed.GetAsync(target, TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);
        Assert.True(listener.Accepted, "the registered private-permitted client did not reach the private-address listener");
    }

    // The address the four LAN-facing tests bind their listener to, or null with the reason they skip.
    //
    // Two things make it null. The machine may have no RFC 1918 / CGNAT interface address at all - a
    // container on a public address, or loopback-only. Or the run is on Windows without the opt-in: a
    // process that begins listening on a socket bound to something other than loopback is what Windows
    // Defender Firewall raises its consent dialog for, and that dialog is approved by an administrator.
    // Its subject is the executable's full path, so answering it settles nothing beyond that one path -
    // every new build directory is a program Windows holds no decision about, and is asked again. That is
    // #1227: the suite must run unelevated by default. Set SSO_TESTS_ALLOW_LAN_BIND=1 to bind off loopback
    // on Windows anyway; the Linux legs carry this coverage with no opt-in, so it is not lost.
    private static (IPAddress? Address, string SkipReason) LanListenerAddress()
    {
        if (OperatingSystem.IsWindows() && !string.Equals(Environment.GetEnvironmentVariable(LanBindOptIn), "1", StringComparison.Ordinal))
        {
            return (null, $"Binding a listener off loopback raises the Windows firewall consent dialog, which needs an administrator (#1227) - set {LanBindOptIn}=1 to run this test on Windows.");
        }

        return (FindLocalPrivateAddress(), "This machine has no RFC 1918 / CGNAT interface address to bind a listener to.");
    }

    // This machine's own RFC 1918 / CGNAT interface address, or null when it has none (a container on a
    // public address, or loopback-only) - the test skips rather than asserting on an absent network. Read
    // from the interfaces rather than by resolving the host name, which is not resolvable on every machine.
    private static IPAddress? FindLocalPrivateAddress()
    {
        foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
        {
            if (nic.OperationalStatus != OperationalStatus.Up || nic.NetworkInterfaceType == NetworkInterfaceType.Loopback)
            {
                continue;
            }

            foreach (var info in nic.GetIPProperties().UnicastAddresses)
            {
                var address = info.Address;
                if (address.AddressFamily != AddressFamily.InterNetwork || IPAddress.IsLoopback(address))
                {
                    continue;
                }

                var b = address.GetAddressBytes();
                var isPrivate = b[0] == 10
                    || (b[0] == 172 && b[1] >= 16 && b[1] <= 31)
                    || (b[0] == 192 && b[1] == 168)
                    || (b[0] == 100 && b[1] >= 64 && b[1] <= 127);
                if (isPrivate)
                {
                    return address;
                }
            }
        }

        return null;
    }

    // A minimal HTTP listener bound to a private-range address - it answers 204, so a successful response
    // proves the connection actually completed rather than merely not being refused at the guard.
    private sealed class PrivateListener : IDisposable
    {
        private readonly Socket _socket;
        private readonly CancellationTokenSource _cts = new();

        internal PrivateListener(IPAddress address)
        {
            _socket = new Socket(address.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
            _socket.Bind(new IPEndPoint(address, 0));
            _socket.Listen(16);
            Port = ((IPEndPoint)_socket.LocalEndPoint!).Port;
            _ = AcceptLoopAsync(_cts.Token);
        }

        internal int Port { get; }

        internal bool Accepted { get; private set; }

        private async Task AcceptLoopAsync(CancellationToken token)
        {
            try
            {
                while (!token.IsCancellationRequested)
                {
                    using var conn = await _socket.AcceptAsync(token).ConfigureAwait(false);
                    Accepted = true;

                    var buffer = new byte[2048];
                    await conn.ReceiveAsync(buffer, SocketFlags.None, token).ConfigureAwait(false);
                    var response = "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"u8.ToArray();
                    await conn.SendAsync(response, SocketFlags.None, token).ConfigureAwait(false);
                    conn.Shutdown(SocketShutdown.Both);
                }
            }
            catch (Exception ex) when (ex is OperationCanceledException or ObjectDisposedException or SocketException)
            {
                // Listener torn down - expected on dispose.
            }
        }

        public void Dispose()
        {
            _cts.Cancel();
            _socket.Dispose();
            _cts.Dispose();
        }
    }

    [Fact]
    public async Task PrivatePermittedHandler_JudgesEveryRedirectHop_AndRefusesOneAimedAtLoopback()
    {
        // A redirect is a second connection to a host the first response chose, so the guard has to run on
        // it too - otherwise a permitted first hop becomes an open door to whatever it points at, which is
        // the DNS-rebind/SSRF shape the guard exists for. Until now the handler's redirect settings were
        // asserted as properties (AllowAutoRedirect, MaxAutomaticRedirections) but nothing proved a hop was
        // actually judged.
        //
        // The first hop must be an address the tier permits, and the only such address that can be bound
        // locally is this machine's own private one - so this test needs a private interface address and
        // skips without one. It runs where the feature matters; the skip is recorded rather than hidden.
        var (privateAddress, skipReason) = LanListenerAddress();
        Assert.SkipWhen(privateAddress is null, skipReason);

        using var blocked = new BlockedListener();
        using var redirector = new RedirectingListener(privateAddress!, _ => $"http://127.0.0.1:{blocked.Port}/");
        using var handler = SsoHttp.CreateHardenedHandler(AddressPolicy.PrivateNetworkPermitted);
        using var client = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(10) };

        var ex = await Assert.ThrowsAsync<HttpRequestException>(
            () => client.GetAsync($"http://{privateAddress}:{redirector.Port}/", TestContext.Current.CancellationToken));

        // The first hop was allowed and reached, so the refusal below is the redirect hop being judged and
        // not the request failing before it ever started.
        Assert.True(redirector.Requests >= 1, "the private-permitted guard did not reach the permitted first hop");
        Assert.Contains("blocked address", ex.Message, StringComparison.OrdinalIgnoreCase);
        Assert.False(blocked.Accepted, "a redirect hop reached a loopback listener the guard must refuse");
    }

    [Fact]
    public async Task PrivatePermittedHandler_StopsAtTheRedirectBoundTheHandlerSets()
    {
        // The hop-by-hop guard above is only bounded if the redirect chain is: an IdP that redirects
        // forever would otherwise spin the connect guard indefinitely. MaxAutomaticRedirections is 5, so a
        // listener that always redirects to itself must be asked exactly 6 times (the original request plus
        // five hops) and the client must hand back the last redirect rather than following it.
        var (privateAddress, skipReason) = LanListenerAddress();
        Assert.SkipWhen(privateAddress is null, skipReason);

        using var redirector = new RedirectingListener(privateAddress!, port => $"http://{privateAddress}:{port}/next");
        using var handler = SsoHttp.CreateHardenedHandler(AddressPolicy.PrivateNetworkPermitted);
        using var client = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(10) };

        using var response = await client.GetAsync($"http://{privateAddress}:{redirector.Port}/", TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.Found, response.StatusCode);
        Assert.Equal(6, redirector.Requests);
    }

    // A TCP listener bound to a given address that answers every request with a 302 to a caller-chosen
    // location, and counts how many requests it was asked - so a test can prove both that a hop was taken
    // and how many were.
    private sealed class RedirectingListener : IDisposable
    {
        private readonly Socket _socket;
        private readonly CancellationTokenSource _cts = new();
        private readonly Func<int, string> _location;
        private int _requests;

        internal RedirectingListener(IPAddress address, Func<int, string> location)
        {
            _location = location;
            _socket = new Socket(address.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
            _socket.Bind(new IPEndPoint(address, 0));
            _socket.Listen(16);
            Port = ((IPEndPoint)_socket.LocalEndPoint!).Port;
            _ = AcceptLoopAsync(_cts.Token);
        }

        internal int Port { get; }

        internal int Requests => Volatile.Read(ref _requests);

        private async Task AcceptLoopAsync(CancellationToken token)
        {
            try
            {
                while (!token.IsCancellationRequested)
                {
                    using var conn = await _socket.AcceptAsync(token).ConfigureAwait(false);
                    var buffer = new byte[2048];
                    await conn.ReceiveAsync(buffer, SocketFlags.None, token).ConfigureAwait(false);
                    Interlocked.Increment(ref _requests);

                    var response = Encoding.ASCII.GetBytes(
                        $"HTTP/1.1 302 Found\r\nLocation: {_location(Port)}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
                    await conn.SendAsync(response, SocketFlags.None, token).ConfigureAwait(false);
                    conn.Shutdown(SocketShutdown.Both);
                }
            }
            catch (Exception ex) when (ex is OperationCanceledException or ObjectDisposedException or SocketException)
            {
                // Listener torn down - expected on dispose.
            }
        }

        public void Dispose()
        {
            _cts.Cancel();
            _socket.Dispose();
            _cts.Dispose();
        }
    }

    // A loopback TCP listener that would accept any connection reaching it - so a passing test proves the
    // guard refused BEFORE the socket layer, not that the port simply happened to be closed.
    private sealed class BlockedListener : IDisposable
    {
        private readonly Socket _socket;
        private readonly CancellationTokenSource _cts = new();

        internal BlockedListener()
        {
            _socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            _socket.Bind(new IPEndPoint(IPAddress.Loopback, 0));
            _socket.Listen(16);
            Port = ((IPEndPoint)_socket.LocalEndPoint!).Port;
            _ = AcceptLoopAsync(_cts.Token);
        }

        internal int Port { get; }

        internal bool Accepted { get; private set; }

        private async Task AcceptLoopAsync(CancellationToken token)
        {
            try
            {
                while (!token.IsCancellationRequested)
                {
                    using var conn = await _socket.AcceptAsync(token).ConfigureAwait(false);
                    Accepted = true;
                }
            }
            catch (Exception ex) when (ex is OperationCanceledException or ObjectDisposedException or SocketException)
            {
                // Listener torn down - expected on dispose.
            }
        }

        public void Dispose()
        {
            _cts.Cancel();
            _socket.Dispose();
            _cts.Dispose();
        }
    }
}
