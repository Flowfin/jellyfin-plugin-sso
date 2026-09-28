// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Collections.Generic;
using Jellyfin.Plugin.SSO_Auth.Api.Net;

namespace Jellyfin.Plugin.SSO_Auth.Api.Avatar;

/// <summary>An avatar URL bound to the outbound address tier it earned (#1764), so the fetch can never apply a private verdict to a different address than the one it was given for.</summary>
/// <remarks>
/// The verdict is earned in <see cref="Resolve"/> alone: the provider carries <c>AllowPrivateNetworkAddresses</c>
/// and the URL's origin, scheme, host and effective port compared exactly, is the origin of one of that provider's
/// own backchannel endpoints. Anything else keeps <see cref="AddressPolicy.Strict"/>, so the setting adds no host
/// the plugin does not already talk to, and a redirect is followed only to a target the strict tier admits.
/// </remarks>
internal sealed record AvatarTarget
{
    // Private so a private-tier target is minted only by Resolve below, whose one plugin call site the
    // conformance rule counts: holding one is the evidence that both facts held at once there.
    private AvatarTarget(string url, AddressPolicy policy)
    {
        Url = url;
        Policy = policy;
    }

    /// <summary>
    /// Gets the candidate avatar URL, as the login resolved it. Only a candidate: the fetch still gates it
    /// through <see cref="AvatarUrlValidator"/> under <see cref="Policy"/>.
    /// </summary>
    internal string Url { get; }

    /// <summary>Gets the address tier the fetch classifies under.</summary>
    internal AddressPolicy Policy { get; }

    /// <summary>
    /// Binds a resolved avatar URL to the strict tier, which is what every caller that names no provider gets.
    /// </summary>
    /// <param name="url">The candidate avatar URL, or null when the login resolved none.</param>
    /// <returns>The strict-tier target, or null when there is no URL.</returns>
    internal static AvatarTarget? Strict(string? url) => url is null ? null : new AvatarTarget(url, AddressPolicy.Strict);

    /// <summary>Binds a resolved avatar URL to the tier it earns from the provider that supplied it.</summary>
    /// <param name="url">The candidate avatar URL, or null when the login resolved none.</param>
    /// <param name="allowPrivateNetworkAddresses">The provider's <c>AllowPrivateNetworkAddresses</c> opt-in.</param>
    /// <param name="providerEndpoints">The provider's own backchannel endpoints, with a null entry where one is unknown; only an absolute URL contributes an origin.</param>
    /// <returns>The target with the tier it earned, or null when there is no URL.</returns>
    internal static AvatarTarget? Resolve(string? url, bool allowPrivateNetworkAddresses, IEnumerable<string?> providerEndpoints)
    {
        ArgumentNullException.ThrowIfNull(providerEndpoints);
        if (url is null)
        {
            return null;
        }

        // Both facts at once, and the opt-in is read first: a provider that never asked for the private tier
        // costs no origin comparison and cannot earn the tier through any endpoint value.
        if (allowPrivateNetworkAddresses
            && Uri.TryCreate(url, UriKind.Absolute, out var avatar)
            && IsOriginOfAny(avatar, providerEndpoints))
        {
            return new AvatarTarget(url, AddressPolicy.PrivateNetworkPermitted);
        }

        return new AvatarTarget(url, AddressPolicy.Strict);
    }

    /// <summary>
    /// Whether two absolute URLs share an origin: the same scheme, the same host and the same effective port,
    /// each compared exactly. <see cref="Uri"/> has already lowercased the scheme and a DNS host name, so the
    /// ordinal comparison is one of canonical forms rather than of spellings.
    /// </summary>
    /// <param name="a">One absolute URL.</param>
    /// <param name="b">The other absolute URL.</param>
    /// <returns>True when the two name one origin.</returns>
    internal static bool SameOrigin(Uri a, Uri b)
    {
        ArgumentNullException.ThrowIfNull(a);
        ArgumentNullException.ThrowIfNull(b);
        return string.Equals(a.Scheme, b.Scheme, StringComparison.Ordinal)
            && string.Equals(a.Host, b.Host, StringComparison.Ordinal)
            && a.Port == b.Port;
    }

    private static bool IsOriginOfAny(Uri avatar, IEnumerable<string?> endpoints)
    {
        foreach (var endpoint in endpoints)
        {
            if (endpoint is not null && Uri.TryCreate(endpoint, UriKind.Absolute, out var origin) && SameOrigin(avatar, origin))
            {
                return true;
            }
        }

        return false;
    }
}
