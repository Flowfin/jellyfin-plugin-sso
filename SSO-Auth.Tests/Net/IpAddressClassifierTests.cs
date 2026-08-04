// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System.Net;
using Jellyfin.Plugin.SSO_Auth.Api;
using Jellyfin.Plugin.SSO_Auth.Api.Net;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// Coverage for the shared public/blocked address classification (#370) both the avatar-fetch SSRF
/// guard (<see cref="AvatarUrlValidatorTests"/>) and the login rate limiter's client-key derivation
/// rely on.
/// </summary>
public class IpAddressClassifierTests
{
    [Theory]
    [InlineData("127.0.0.1")]
    [InlineData("10.1.2.3")]
    [InlineData("172.16.0.1")]
    [InlineData("172.31.255.255")]
    [InlineData("192.168.0.1")]
    [InlineData("169.254.0.1")]
    [InlineData("100.64.0.1")]
    [InlineData("0.0.0.0")]
    [InlineData("::1")]
    [InlineData("fe80::1")]
    [InlineData("fc00::1")]
    [InlineData("::ffff:127.0.0.1")]
    [InlineData("224.0.0.1")] // multicast
    [InlineData("239.255.255.250")] // multicast (SSDP)
    [InlineData("240.0.0.1")] // reserved
    [InlineData("255.255.255.255")] // broadcast
    [InlineData("64:ff9b::7f00:1")] // NAT64 well-known prefix embedding 127.0.0.1
    [InlineData("64:ff9b::a00:5")] // NAT64 embedding 10.0.0.5
    [InlineData("2002:7f00:1::")] // 6to4 embedding 127.0.0.1
    [InlineData("2002:c0a8:101::")] // 6to4 embedding 192.168.1.1
    [InlineData("::7f00:1")] // deprecated IPv4-compatible ::127.0.0.1
    [InlineData("192.0.0.192")] // Oracle Cloud metadata (192.0.0.0/24 protocol assignments)
    [InlineData("192.0.2.10")] // TEST-NET-1
    [InlineData("198.51.100.10")] // TEST-NET-2
    [InlineData("203.0.113.10")] // TEST-NET-3
    [InlineData("198.18.0.1")] // benchmarking 198.18.0.0/15
    [InlineData("198.19.255.255")] // benchmarking 198.18.0.0/15 (upper half)
    [InlineData("192.88.99.1")] // 6to4 relay anycast
    [InlineData("fec0::1")] // deprecated IPv6 site-local
    public void IsBlockedAddress_PrivateOrLoopback_ReturnsTrue(string ip)
    {
        Assert.True(IpAddressClassifier.IsBlockedAddress(IPAddress.Parse(ip)));
    }

    [Theory]
    [InlineData("8.8.8.8")]
    [InlineData("1.1.1.1")]
    [InlineData("172.32.0.1")]
    [InlineData("100.63.255.255")]
    [InlineData("223.255.255.255")] // last unicast address just below the 224/4 multicast range
    [InlineData("198.17.255.255")] // just below the 198.18.0.0/15 benchmarking range
    [InlineData("198.20.0.1")] // just above the 198.18.0.0/15 benchmarking range
    [InlineData("192.0.1.1")] // adjacent to 192.0.0.0/24 and 192.0.2.0/24, not reserved
    [InlineData("2606:4700:4700::1111")]
    [InlineData("64:ff9b::808:808")] // NAT64 embedding the public 8.8.8.8
    public void IsBlockedAddress_PublicAddresses_ReturnsFalse(string ip)
    {
        Assert.False(IpAddressClassifier.IsBlockedAddress(IPAddress.Parse(ip)));
    }

    /// <summary>
    /// The relaxed tier permits exactly the private, admin-routable ranges an on-premises identity
    /// provider actually lives on (#1177): RFC 1918, carrier-grade NAT, and IPv6 unique-local.
    /// </summary>
    /// <param name="ip">The address to classify.</param>
    [Theory]
    [InlineData("10.1.2.3")]
    [InlineData("10.255.255.255")]
    [InlineData("172.16.0.1")]
    [InlineData("172.31.255.255")]
    [InlineData("192.168.0.1")]
    [InlineData("192.168.255.255")]
    [InlineData("100.64.0.1")] // CGNAT
    [InlineData("100.127.255.255")] // CGNAT (upper half)
    [InlineData("fc00::1")] // IPv6 unique-local
    [InlineData("fd12:3456:789a::1")] // IPv6 unique-local (the fd00::/8 half in practical use)
    [InlineData("::ffff:10.1.2.3")] // IPv4-mapped form of an RFC 1918 address
    [InlineData("64:ff9b::a00:5")] // NAT64 embedding 10.0.0.5
    [InlineData("2002:c0a8:101::")] // 6to4 embedding 192.168.1.1
    public void IsBlockedAddress_PrivateNetworkPermitted_AllowsPrivateRanges(string ip)
    {
        Assert.False(IpAddressClassifier.IsBlockedAddress(IPAddress.Parse(ip), AddressPolicy.PrivateNetworkPermitted));
    }

    /// <summary>
    /// The never-relaxable ranges stay blocked under the relaxed tier too - loopback, link-local
    /// (where the cloud metadata service lives), the IETF protocol assignments, site-local, the
    /// unspecified address and multicast/reserved/broadcast. This is the constraint stated on #1058
    /// that no config setting may negotiate away, including via a transition-address wrapper.
    /// </summary>
    /// <param name="ip">The address to classify.</param>
    [Theory]
    [InlineData("127.0.0.1")]
    [InlineData("127.1.2.3")]
    [InlineData("::1")]
    [InlineData("169.254.0.1")] // link-local
    [InlineData("169.254.169.254")] // cloud metadata service
    [InlineData("fe80::1")] // IPv6 link-local
    [InlineData("192.0.0.192")] // Oracle Cloud metadata (192.0.0.0/24 protocol assignments)
    [InlineData("0.0.0.0")]
    [InlineData("::")]
    [InlineData("fec0::1")] // deprecated IPv6 site-local
    [InlineData("224.0.0.1")] // multicast
    [InlineData("239.255.255.250")] // multicast (SSDP)
    [InlineData("240.0.0.1")] // reserved
    [InlineData("255.255.255.255")] // broadcast
    [InlineData("192.0.2.10")] // TEST-NET-1
    [InlineData("198.51.100.10")] // TEST-NET-2
    [InlineData("203.0.113.10")] // TEST-NET-3
    [InlineData("198.18.0.1")] // benchmarking 198.18.0.0/15
    [InlineData("192.88.99.1")] // 6to4 relay anycast
    [InlineData("::ffff:127.0.0.1")] // IPv4-mapped loopback
    [InlineData("::ffff:169.254.169.254")] // IPv4-mapped metadata service
    [InlineData("64:ff9b::7f00:1")] // NAT64 embedding 127.0.0.1
    [InlineData("64:ff9b::a9fe:a9fe")] // NAT64 embedding 169.254.169.254
    [InlineData("2002:7f00:1::")] // 6to4 embedding 127.0.0.1
    [InlineData("2002:a9fe:a9fe::")] // 6to4 embedding 169.254.169.254
    [InlineData("::7f00:1")] // deprecated IPv4-compatible ::127.0.0.1
    [InlineData("::a9fe:a9fe")] // deprecated IPv4-compatible ::169.254.169.254
    public void IsBlockedAddress_PrivateNetworkPermitted_StillBlocksNeverRelaxableRanges(string ip)
    {
        Assert.True(IpAddressClassifier.IsBlockedAddress(IPAddress.Parse(ip), AddressPolicy.PrivateNetworkPermitted));
    }

    /// <summary>
    /// A public address stays reachable under the relaxed tier - widening the policy must not narrow it.
    /// </summary>
    /// <param name="ip">The address to classify.</param>
    [Theory]
    [InlineData("8.8.8.8")]
    [InlineData("172.32.0.1")]
    [InlineData("100.63.255.255")]
    [InlineData("2606:4700:4700::1111")]
    public void IsBlockedAddress_PrivateNetworkPermitted_StillAllowsPublicAddresses(string ip)
    {
        Assert.False(IpAddressClassifier.IsBlockedAddress(IPAddress.Parse(ip), AddressPolicy.PrivateNetworkPermitted));
    }

    /// <summary>
    /// The first and last address of every range the relaxed tier moves. A range written one octet wide of
    /// its definition is the classic way a partition goes wrong, and it is invisible to a test that only
    /// samples the middle: each of these must be blocked under strict and permitted under relaxed.
    /// </summary>
    /// <param name="ip">The boundary address to classify.</param>
    [Theory]
    [InlineData("10.0.0.0")] // 10.0.0.0/8, first
    [InlineData("10.255.255.255")] // 10.0.0.0/8, last
    [InlineData("172.16.0.0")] // 172.16.0.0/12, first
    [InlineData("172.31.255.255")] // 172.16.0.0/12, last
    [InlineData("192.168.0.0")] // 192.168.0.0/16, first
    [InlineData("192.168.255.255")] // 192.168.0.0/16, last
    [InlineData("100.64.0.0")] // 100.64.0.0/10, first
    [InlineData("100.127.255.255")] // 100.64.0.0/10, last
    [InlineData("fc00::")] // fc00::/7, first
    [InlineData("fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")] // fc00::/7, last
    public void IsBlockedAddress_RangeBoundaries_MoveTierTogetherWithTheirRange(string ip)
    {
        var address = IPAddress.Parse(ip);

        Assert.True(IpAddressClassifier.IsBlockedAddress(address, AddressPolicy.Strict));
        Assert.False(IpAddressClassifier.IsBlockedAddress(address, AddressPolicy.PrivateNetworkPermitted));
    }

    /// <summary>
    /// The address immediately outside each moved range, on both sides. These are ordinary public
    /// addresses and must stay reachable under both tiers - a range that leaked one address wider or
    /// narrower than its definition shows up here rather than in production.
    /// </summary>
    /// <param name="ip">The just-outside address to classify.</param>
    [Theory]
    [InlineData("9.255.255.255")] // just below 10.0.0.0/8
    [InlineData("11.0.0.0")] // just above 10.0.0.0/8
    [InlineData("172.15.255.255")] // just below 172.16.0.0/12
    [InlineData("172.32.0.0")] // just above 172.16.0.0/12
    [InlineData("192.167.255.255")] // just below 192.168.0.0/16
    [InlineData("192.169.0.0")] // just above 192.168.0.0/16
    [InlineData("100.63.255.255")] // just below 100.64.0.0/10
    [InlineData("100.128.0.0")] // just above 100.64.0.0/10
    [InlineData("fbff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")] // just below fc00::/7
    public void IsBlockedAddress_JustOutsideAMovedRange_IsPublicUnderBothTiers(string ip)
    {
        var address = IPAddress.Parse(ip);

        Assert.False(IpAddressClassifier.IsBlockedAddress(address, AddressPolicy.Strict));
        Assert.False(IpAddressClassifier.IsBlockedAddress(address, AddressPolicy.PrivateNetworkPermitted));
    }

    /// <summary>
    /// A wrapped address reaches the same verdict as the same address unwrapped, under the relaxed tier,
    /// for every transition form the classifier unwraps. The two theories above assert the wrapped and the
    /// bare forms separately, which stays green if one of them silently stops being classified at all;
    /// this asserts the equality itself, which is the property that keeps a wrapper from being a way in.
    /// </summary>
    /// <param name="wrapped">The transition-wrapped address.</param>
    /// <param name="bare">The same address written plainly.</param>
    [Theory]
    [InlineData("::ffff:127.0.0.1", "127.0.0.1")] // IPv4-mapped
    [InlineData("::ffff:169.254.169.254", "169.254.169.254")] // IPv4-mapped
    [InlineData("::ffff:192.0.0.192", "192.0.0.192")] // IPv4-mapped
    [InlineData("::ffff:10.1.2.3", "10.1.2.3")] // IPv4-mapped, a relaxable address
    [InlineData("64:ff9b::7f00:1", "127.0.0.1")] // NAT64
    [InlineData("64:ff9b::a9fe:a9fe", "169.254.169.254")] // NAT64
    [InlineData("64:ff9b::a00:5", "10.0.0.5")] // NAT64, a relaxable address
    [InlineData("2002:7f00:1::", "127.0.0.1")] // 6to4
    [InlineData("2002:a9fe:a9fe::", "169.254.169.254")] // 6to4
    [InlineData("2002:c0a8:101::", "192.168.1.1")] // 6to4, a relaxable address
    [InlineData("::7f00:1", "127.0.0.1")] // deprecated IPv4-compatible
    [InlineData("::a9fe:a9fe", "169.254.169.254")] // deprecated IPv4-compatible
    [InlineData("::a01:203", "10.1.2.3")] // deprecated IPv4-compatible, a relaxable address
    public void IsBlockedAddress_PrivateNetworkPermitted_WrappedVerdictEqualsUnwrappedVerdict(string wrapped, string bare)
    {
        Assert.Equal(
            IpAddressClassifier.IsBlockedAddress(IPAddress.Parse(bare), AddressPolicy.PrivateNetworkPermitted),
            IpAddressClassifier.IsBlockedAddress(IPAddress.Parse(wrapped), AddressPolicy.PrivateNetworkPermitted));
    }

    /// <summary>
    /// The tier defaults to strict, so the three existing callers keep byte-identical behaviour without
    /// naming a policy at their call sites (#1177).
    /// </summary>
    [Fact]
    public void IsBlockedAddress_DefaultPolicy_IsStrict()
    {
        var privateAddress = IPAddress.Parse("10.1.2.3");

        Assert.True(IpAddressClassifier.IsBlockedAddress(privateAddress));
        Assert.True(IpAddressClassifier.IsBlockedAddress(privateAddress, AddressPolicy.Strict));
        Assert.False(IpAddressClassifier.IsBlockedAddress(privateAddress, AddressPolicy.PrivateNetworkPermitted));
    }
}
