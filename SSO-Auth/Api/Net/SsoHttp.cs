// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Diagnostics;
using System.IO;
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
    private static async ValueTask<Stream> ConnectToAllowedAddressAsync(SocketsHttpConnectionContext context, AddressPolicy policy, CancellationToken cancellationToken)
    {
        var addresses = await System.Net.Dns.GetHostAddressesAsync(context.DnsEndPoint.Host, cancellationToken).ConfigureAwait(false);

        // Try every non-blocked address in turn (a per-address connect fallback for dual-stack / multi-record
        // hosts, since supplying a ConnectCallback replaces the handler's built-in one), connecting to the
        // validated IP rather than the hostname so a DNS rebind cannot redirect the connection internally.
        Exception? lastError = null;
        var attempted = false;
        foreach (var address in addresses)
        {
            if (IpAddressClassifier.IsBlockedAddress(address, policy))
            {
                continue;
            }

            attempted = true;
            var socket = new Socket(address.AddressFamily, SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
            var connected = false;
            try
            {
                await socket.ConnectAsync(address, context.DnsEndPoint.Port, cancellationToken).ConfigureAwait(false);
                connected = true;
                return new NetworkStream(socket, ownsSocket: true);
            }
            catch (Exception ex) when (!cancellationToken.IsCancellationRequested)
            {
                lastError = ex;
            }
            finally
            {
                // Dispose unless ownership passed to the returned NetworkStream. Runs on the cancellation path
                // too, where the catch filter is skipped and the socket would otherwise leak.
                if (!connected)
                {
                    socket.Dispose();
                }
            }
        }

        if (attempted)
        {
            throw new HttpRequestException("Could not connect to any allowed address for the outbound host.", lastError);
        }

        throw new HttpRequestException("The outbound host resolves only to blocked addresses.");
    }
}
