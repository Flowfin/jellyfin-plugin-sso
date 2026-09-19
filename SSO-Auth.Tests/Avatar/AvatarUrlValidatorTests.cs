// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using Jellyfin.Plugin.SSO_Auth.Api;
using Jellyfin.Plugin.SSO_Auth.Api.Avatar;
using Jellyfin.Plugin.SSO_Auth.Api.Net;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// Coverage for the avatar-fetch SSRF guard: only public http(s) targets may be fetched. The
/// address-range classification itself is covered by <see cref="IpAddressClassifierTests"/> (#370).
/// </summary>
public class AvatarUrlValidatorTests
{
    [Theory]
    [InlineData("https://cdn.example.com/avatar.png")]
    [InlineData("http://example.com/a.jpg")]
    [InlineData("https://8.8.8.8/pic.png")]
    public void IsAllowedUrl_PublicHttpTargets_ReturnsTrue(string url)
    {
        Assert.True(AvatarUrlValidator.IsAllowedUrl(url, out var uri));
        Assert.NotNull(uri);
    }

    [Theory]
    [InlineData("file:///etc/passwd")]
    [InlineData("ftp://example.com/x")]
    [InlineData("gopher://example.com/x")]
    [InlineData("not a url")]
    [InlineData("/relative/path")]
    [InlineData("")]
    [InlineData("http://localhost/x")]
    [InlineData("http://service.localhost/x")]
    [InlineData("http://localhost./x")]
    [InlineData("http://service.localhost./x")]
    [InlineData("http://127.0.0.1/x")]
    [InlineData("http://169.254.169.254/latest/meta-data/")]
    [InlineData("http://192.0.0.192/")]
    [InlineData("http://10.0.0.5/x")]
    [InlineData("http://192.168.1.1/x")]
    [InlineData("http://172.16.0.1/x")]
    [InlineData("http://[::1]/x")]
    public void IsAllowedUrl_DisallowedTargets_ReturnsFalse(string url)
    {
        Assert.False(AvatarUrlValidator.IsAllowedUrl(url, out var uri));
        Assert.Null(uri);
    }

    [Theory]
    [InlineData("http://10.0.0.5/x")]
    [InlineData("http://192.168.1.1/x")]
    [InlineData("http://172.16.0.1/x")]
    [InlineData("http://100.64.0.1/x")]
    [InlineData("http://[fd00::1]/x")]
    public void IsAllowedUrl_PrivateLiteral_MovesWithTheTier(string url)
    {
        // #1764: the address-literal arm is the one thing that moves with the tier. The two-argument form is
        // the strict tier by construction, so an existing caller's verdict is unchanged.
        Assert.True(AvatarUrlValidator.IsAllowedUrl(url, AddressPolicy.PrivateNetworkPermitted, out var uri));
        Assert.NotNull(uri);
        Assert.False(AvatarUrlValidator.IsAllowedUrl(url, AddressPolicy.Strict, out _));
        Assert.False(AvatarUrlValidator.IsAllowedUrl(url, out _));
    }

    [Theory]
    [InlineData("http://127.0.0.1/x")]
    [InlineData("http://[::1]/x")]
    [InlineData("http://169.254.169.254/latest/meta-data/")]
    [InlineData("http://192.0.0.192/")]
    [InlineData("http://[fe80::1]/x")]
    [InlineData("http://localhost/x")]
    [InlineData("http://service.localhost./x")]
    [InlineData("file:///etc/passwd")]
    [InlineData("not a url")]
    public void IsAllowedUrl_NeverRelaxableTargets_StayRefusedUnderThePrivateTier(string url)
    {
        Assert.False(AvatarUrlValidator.IsAllowedUrl(url, AddressPolicy.PrivateNetworkPermitted, out var uri));
        Assert.Null(uri);
    }
}
