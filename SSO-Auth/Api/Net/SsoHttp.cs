// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

namespace Jellyfin.Plugin.SSO_Auth.Api.Net;

/// <summary>
/// The one home for the plugin's outbound HTTP policy: the User-Agent, and the SSRF-hardened transport every
/// server-to-provider call is built on. The OpenID discovery / token / JWKS backchannel (through
/// <see cref="CreateClient"/>, which resolves a named client from the factory) and the avatar fetch (which
/// builds its own long-lived client on <see cref="CreateHardenedHandler"/>) share the same connect-time
/// guard, so a provider or avatar URL resolving to a private/loopback address is rejected at the transport
/// layer in one place (#370, #755). The named clients' hardened handlers are registered in the composition
/// root; a test's stub/loopback factory supplies its own handler for a name, so integration tests reach their
/// in-process IdP while production stays fail-closed.
/// </summary>
/// <remarks>
/// <para>
/// There are two registered outbound tiers, not one (#1179). <see cref="OutboundClientName"/> carries the
/// full guard and is what every caller gets by default. <see cref="PrivateOutboundClientName"/> additionally
/// permits the private, admin-routable ranges, and is resolved <em>only</em> for an OpenID provider whose
/// <c>AllowPrivateNetworkAddresses</c> is set - the opt-in for an identity provider that deliberately lives
/// on the administrator's own network (#1058).
/// </para>
/// <para>
/// The relaxation is baked into which client is resolved rather than carried as an ambient per-request mode.
/// Both handlers are long-lived and shared across concurrent logins, so a mode that was not part of the
/// client's identity could leak the relaxation to a provider that never opted in. Callers that name no tier
/// - the SAML metadata importer, the avatar fetch, and any future one - stay strict by construction.
/// </para>
/// </remarks>
internal static class SsoHttp
{
    /// <summary>
    /// The <see cref="IHttpClientFactory"/> name of the plugin's SSRF-hardened outbound client. The
    /// composition root registers this name with <see cref="CreateHardenedHandler"/>; production
    /// server-to-provider calls resolve it through <see cref="CreateClient"/>.
    /// </summary>
    internal const string OutboundClientName = "sso-outbound";

    /// <summary>
    /// The <see cref="IHttpClientFactory"/> name of the outbound client whose guard additionally permits the
    /// private, admin-routable ranges (RFC 1918, carrier-grade NAT, IPv6 unique-local). The composition root
    /// registers this name with the same hardened handler under
    /// <see cref="AddressPolicy.PrivateNetworkPermitted"/>; loopback, link-local and the cloud-metadata
    /// ranges are refused here too. Resolved only for an OpenID provider that opted in (#1058).
    /// </summary>
    internal const string PrivateOutboundClientName = "sso-outbound-private";

    /// <summary>
    /// The plugin's outbound User-Agent: product token, assembly file version, and project URL.
    /// </summary>
    internal static readonly string UserAgent =
        $"Jellyfin-Plugin-SSO-Auth +{FileVersionInfo.GetVersionInfo(typeof(SsoHttp).Assembly.Location).FileVersion} (https://github.com/Flowfin/jellyfin-plugin-sso)";

    /// <summary>
    /// How long one connection attempt to one resolved address may take before the next address is tried
    /// (#1760).
    /// </summary>
    /// <remarks>
    /// <para>
    /// A connect callback replaces the handler's own connect, and with it the fallback between address families
    /// a default client has. Unbounded, an address that drops the connection silently - an IPv6 address the
    /// container cannot route, a public address that needs NAT loopback - held the attempt until the caller's
    /// whole request timeout cancelled it, so a working address listed after it was never tried and the
    /// administrator read only a timeout (#1759).
    /// </para>
    /// <para>
    /// FIVE SECONDS, AND THE REASON IS THE TWO BUDGETS AROUND IT. A TCP connect that works completes in well
    /// under a second, and one that lost two SYNs to a bad link still completes in about three; the discovery
    /// fetch around it is bounded at ten (<c>OidcDiscoveryReader.FetchTimeout</c>), so one silent address and one
    /// working one fit inside it. The bound applies to every attempt, the last one included, so a host whose only
    /// allowed address is silent fails with this callback's own message, which names what the guard skipped,
    /// rather than with the caller's cancellation, which names nothing.
    /// </para>
    /// </remarks>
    internal static readonly TimeSpan ConnectAttemptTimeout = TimeSpan.FromSeconds(5);

    /// <summary>
    /// Returns an SSRF-hardened outbound client from the factory (whose primary handler is
    /// <see cref="CreateHardenedHandler"/> in production) with <see cref="UserAgent"/> applied. Used for the
    /// OpenID discovery / token / JWKS fetches, so a provider endpoint that resolves to a private/loopback
    /// address cannot be reached (#755).
    /// </summary>
    /// <param name="factory">The shared HTTP client factory.</param>
    /// <param name="allowPrivateNetworkAddresses">
    /// Pass the opted-in provider's <c>AllowPrivateNetworkAddresses</c> to resolve the
    /// <see cref="PrivateOutboundClientName"/> client instead. Defaults to <see langword="false"/>, so a
    /// caller that names no tier gets the fully-guarded <see cref="OutboundClientName"/> client - the
    /// relaxation reaches exactly the provider that asked for it and no other caller (#1179).
    /// </param>
    /// <returns>A client with the plugin User-Agent applied over the hardened transport.</returns>
    internal static HttpClient CreateClient(IHttpClientFactory factory, bool allowPrivateNetworkAddresses = false)
    {
        var client = factory.CreateClient(allowPrivateNetworkAddresses ? PrivateOutboundClientName : OutboundClientName);
        client.DefaultRequestHeaders.UserAgent.ParseAdd(UserAgent);
        return client;
    }

    /// <summary>
    /// The SSRF-hardened transport handler: routes every connection (including redirect targets) through a
    /// callback that resolves the host and connects only to a non-blocked (public) address, closing the SSRF
    /// and DNS-rebinding vectors. Redirects stay enabled but bounded; the system proxy is disabled so the
    /// guard validates the real host, not a proxy; and a pooled connection is recycled periodically so DNS
    /// changes are honoured despite reuse. The one implementation shared by the OpenID backchannel (via the
    /// named outbound clients) and the avatar fetch.
    /// </summary>
    /// <param name="policy">
    /// Which address tier the connect guard classifies under. Defaults to <see cref="AddressPolicy.Strict"/>,
    /// so the avatar fetch and the strict named client keep the full guard unchanged;
    /// <see cref="AddressPolicy.PrivateNetworkPermitted"/> builds the handler behind
    /// <see cref="PrivateOutboundClientName"/>. The policy is captured per handler rather than read
    /// per-request, so a shared handler cannot serve two tiers (#1179).
    /// </param>
    /// <returns>A hardened <see cref="SocketsHttpHandler"/>.</returns>
    internal static SocketsHttpHandler CreateHardenedHandler(AddressPolicy policy = AddressPolicy.Strict) => new()
    {
        AllowAutoRedirect = true,
        MaxAutomaticRedirections = 5,
        ConnectCallback = (context, cancellationToken) => ConnectToAllowedAddressAsync(context, policy, cancellationToken),

        // A system proxy would be the connection target, so the connect callback would validate the proxy's
        // address rather than the real host's - bypassing the guard.
        UseProxy = false,

        // The handler is reused, so bound how long a pooled connection lives - after this the connection is
        // recycled and the host re-resolved, so DNS changes are honored despite reuse.
        PooledConnectionLifetime = TimeSpan.FromMinutes(2),
    };

    // Resolves the target host and connects only to an address the handler's own policy allows, so a hostname
    // that resolves to an internal address - including via DNS rebinding on a redirect hop - cannot be
    // reached. Under the strict policy that means public addresses only; under the private-permitted policy
    // the admin's own network is additionally reachable, while loopback, link-local and the cloud-metadata
    // ranges stay refused. The policy comes from the handler that captured it, never from the request, so a
    // redirect hop is re-checked under the same tier the connection started on.
    private static ValueTask<Stream> ConnectToAllowedAddressAsync(SocketsHttpConnectionContext context, AddressPolicy policy, CancellationToken cancellationToken) =>
        ConnectToAllowedAddressAsync(
            context.DnsEndPoint.Host,
            context.DnsEndPoint.Port,
            policy,
            System.Net.Dns.GetHostAddressesAsync,
            ConnectSocketAsync,
            ConnectAttemptTimeout,
            cancellationToken);

    /// <summary>
    /// The connect guard with its resolver, its socket connect and its per-attempt bound handed in, so a test
    /// can drive a resolver answer this machine's DNS cannot produce (a refused address beside a silent one) and
    /// production passes the real three. The policy test is the same one either way: every address is classified
    /// before anything connects to it.
    /// </summary>
    /// <param name="host">The host the request names.</param>
    /// <param name="port">The port the request names.</param>
    /// <param name="policy">The address tier the handler captured.</param>
    /// <param name="resolve">Resolves the host to its addresses, in the resolver's order.</param>
    /// <param name="connect">Connects to one address and returns the stream, or throws.</param>
    /// <param name="attemptTimeout">How long one attempt may take before the next address is tried.</param>
    /// <param name="cancellationToken">The caller's cancellation, which ends the whole connect.</param>
    /// <returns>A connected stream to the first allowed address that answered.</returns>
    internal static async ValueTask<Stream> ConnectToAllowedAddressAsync(
        string host,
        int port,
        AddressPolicy policy,
        Func<string, CancellationToken, Task<IPAddress[]>> resolve,
        Func<IPAddress, int, CancellationToken, ValueTask<Stream>> connect,
        TimeSpan attemptTimeout,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(resolve);
        ArgumentNullException.ThrowIfNull(connect);

        var addresses = await resolve(host, cancellationToken).ConfigureAwait(false);

        // Try every non-blocked address in turn (a per-address connect fallback for dual-stack / multi-record
        // hosts, since supplying a ConnectCallback replaces the handler's built-in one), connecting to the
        // validated IP rather than the hostname so a DNS rebind cannot redirect the connection internally.
        Exception? lastError = null;
        var attempted = false;

        // WHAT THE GUARD SKIPPED IS COUNTED, NOT NAMED (#1760). A read that fails after the guard refused an
        // address reported only a timeout, and nothing pointed at the setting that would have allowed it. The
        // count goes into the message; the addresses do not, because this message reaches the server log.
        var refusedRelaxable = 0;
        var refusedNeverRelaxable = 0;
        foreach (var address in addresses)
        {
            if (IpAddressClassifier.IsBlockedAddress(address, policy))
            {
                // Relaxable means the private-permitted tier would have allowed it; only then does naming the
                // setting help. Loopback, link-local and cloud-metadata addresses stay refused under both tiers.
                if (policy == AddressPolicy.Strict && !IpAddressClassifier.IsBlockedAddress(address, AddressPolicy.PrivateNetworkPermitted))
                {
                    refusedRelaxable++;
                }
                else
                {
                    refusedNeverRelaxable++;
                }

                continue;
            }

            attempted = true;
            using var attempt = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            attempt.CancelAfter(attemptTimeout);
            try
            {
                return await connect(address, port, attempt.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException ex) when (!cancellationToken.IsCancellationRequested)
            {
                // The attempt's own bound ended it, not the caller: the next address is tried.
                lastError = new TimeoutException(
                    $"A connection attempt did not complete within {attemptTimeout.TotalSeconds:0.#} seconds.",
                    ex);
            }
            catch (Exception ex) when (!cancellationToken.IsCancellationRequested)
            {
                lastError = ex;
            }
        }

        var skipped = DescribeSkipped(refusedRelaxable, refusedNeverRelaxable);
        if (attempted)
        {
            throw new HttpRequestException("Could not connect to any allowed address for the outbound host." + skipped, lastError);
        }

        throw new HttpRequestException("The outbound host resolves only to blocked addresses." + skipped);
    }

    // The sentence that follows a failed connect when the guard skipped anything, or nothing when it did not.
    private static string DescribeSkipped(int refusedRelaxable, int refusedNeverRelaxable)
    {
        var total = refusedRelaxable + refusedNeverRelaxable;
        if (total == 0)
        {
            return string.Empty;
        }

        var skipped = total == 1
            ? " 1 of the host's addresses was skipped because the address guard refuses it."
            : $" {total} of the host's addresses were skipped because the address guard refuses them.";
        if (refusedRelaxable == 0)
        {
            return skipped;
        }

        // THE SETTING IS NAMED WITH ITS REACH (#1764). This transport also serves the avatar fetch and the SAML
        // metadata importer, which stay strict by construction, so a sentence that only said to enable the setting
        // sent a reader whose provider serves pictures from the local network to switch it on for an avatar it
        // never covers.
        return skipped
            + (refusedRelaxable == total
                ? " Each is on a private network."
                : $" {refusedRelaxable} of them are on a private network.")
            + " An OpenID provider's AllowPrivateNetworkAddresses setting allows private addresses for that provider's"
            + " discovery, token and userinfo requests; avatars and SAML metadata are fetched without it.";
    }

    // The production connect: a socket to the validated address, disposed unless its stream is returned.
    private static async ValueTask<Stream> ConnectSocketAsync(IPAddress address, int port, CancellationToken cancellationToken)
    {
        var socket = new Socket(address.AddressFamily, SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
        var connected = false;
        try
        {
            await socket.ConnectAsync(address, port, cancellationToken).ConfigureAwait(false);
            connected = true;
            return new NetworkStream(socket, ownsSocket: true);
        }
        finally
        {
            // Dispose unless ownership passed to the returned NetworkStream, on every failure path including a
            // cancelled attempt.
            if (!connected)
            {
                socket.Dispose();
            }
        }
    }
}
