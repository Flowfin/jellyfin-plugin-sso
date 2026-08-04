// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

namespace Jellyfin.Plugin.SSO_Auth.Api.Net;

/// <summary>
/// Selects which tier of <see cref="IpAddressClassifier"/>'s address policy a caller is asking for. The
/// tiers differ only in the private, admin-routable ranges; the ranges that can never be a deliberate
/// destination - loopback, link-local (where the cloud metadata service lives), the IETF protocol
/// assignments, site-local, unspecified, and multicast/reserved/broadcast - are blocked by both (#1058).
/// </summary>
internal enum AddressPolicy
{
    /// <summary>
    /// Block every address that is not public and externally reachable. This is the only tier any
    /// client-facing or unconfigured path may use, and it is the default so a caller gets it by omission.
    /// </summary>
    Strict,

    /// <summary>
    /// Additionally permit the private ranges an on-premises service legitimately lives on: RFC 1918
    /// (<c>10.0.0.0/8</c>, <c>172.16.0.0/12</c>, <c>192.168.0.0/16</c>), carrier-grade NAT
    /// (<c>100.64.0.0/10</c>), and IPv6 unique-local (<c>fc00::/7</c>). Selected only where an
    /// administrator has explicitly opted a single provider in.
    /// </summary>
    PrivateNetworkPermitted,
}
