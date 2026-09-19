// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using Jellyfin.Plugin.SSO_Auth.Api.Avatar;
using Jellyfin.Plugin.SSO_Auth.Api.Net;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// Tests for <see cref="AvatarTarget"/> (#1764): the one place an avatar URL earns the private address tier,
/// and the origin comparison it earns it on. The rows over a provider's real endpoints are in
/// <see cref="OidcAuthorizeStateBuilderTests"/>; what is here is the value's own contract.
/// </summary>
public class AvatarTargetTests
{
    private static readonly string[] Endpoints = { "https://idp.lan/realms/home", "https://idp.lan/realms/home/protocol/openid-connect/token" };

    [Fact]
    public void Resolve_NoUrl_IsNull()
    {
        Assert.Null(AvatarTarget.Resolve(null, allowPrivateNetworkAddresses: true, Endpoints));
        Assert.Null(AvatarTarget.Strict(null));
    }

    [Fact]
    public void Strict_BindsTheStrictTier()
    {
        var target = AvatarTarget.Strict("https://cdn.example.com/a.png")!;
        Assert.Equal("https://cdn.example.com/a.png", target.Url);
        Assert.Equal(AddressPolicy.Strict, target.Policy);
    }

    [Fact]
    public void Resolve_AnUnparseableUrl_StaysStrict_AndIsLeftForTheValidator()
    {
        // The tier is never earned by a value that names no origin; the validator refuses it later, unchanged.
        var target = AvatarTarget.Resolve("not a url", allowPrivateNetworkAddresses: true, Endpoints)!;
        Assert.Equal("not a url", target.Url);
        Assert.Equal(AddressPolicy.Strict, target.Policy);
    }

    [Fact]
    public void Resolve_IgnoresEndpointEntriesThatNameNoOrigin()
    {
        // Null, empty and relative entries contribute nothing; one absolute entry is enough.
        var only = new string?[] { null, string.Empty, "/relative/path" };
        Assert.Equal(AddressPolicy.Strict, AvatarTarget.Resolve("https://idp.lan/a.png", allowPrivateNetworkAddresses: true, only)!.Policy);

        var withOne = new string?[] { null, string.Empty, "/relative/path", "https://idp.lan/realms/home" };
        Assert.Equal(AddressPolicy.PrivateNetworkPermitted, AvatarTarget.Resolve("https://idp.lan/a.png", allowPrivateNetworkAddresses: true, withOne)!.Policy);
    }

    [Fact]
    public void TwoTargetsWithTheSameUrlAndTier_AreEqual_AndTheTierIsPartOfTheValue()
    {
        // The verdict is part of the value, so a strict and a private target for one URL are two values.
        var strict = AvatarTarget.Strict("https://idp.lan/a.png");
        var earned = AvatarTarget.Resolve("https://idp.lan/a.png", allowPrivateNetworkAddresses: true, Endpoints);
        Assert.Equal(AvatarTarget.Strict("https://idp.lan/a.png"), strict);
        Assert.NotEqual(strict, earned);
    }

    [Fact]
    public void Resolve_WithoutTheOptIn_NeverEarnsTheTier()
    {
        Assert.Equal(AddressPolicy.Strict, AvatarTarget.Resolve("https://idp.lan/a.png", allowPrivateNetworkAddresses: false, Endpoints)!.Policy);
    }

    [Theory]
    [InlineData("https://idp.lan/a", "https://idp.lan:443/b", true)] // the default port spelled out
    [InlineData("https://IDP.lan/a", "https://idp.lan/b", true)] // a host name is case-insensitive and Uri has lowercased it
    [InlineData("http://[fd00::1]/a", "http://[fd00::1]/b", true)] // an address literal
    [InlineData("http://10.0.0.5/a", "http://10.0.0.5/b", true)]
    [InlineData("https://idp.lan/a", "https://idp.lan:8443/b", false)] // another port
    [InlineData("https://idp.lan:443/a", "http://idp.lan:443/b", false)] // another scheme at the same port
    [InlineData("https://idp.lan/a", "https://idp.lan.example/b", false)] // another host
    [InlineData("https://idp.lan/a", "https://cdn.idp.lan/b", false)] // a subdomain is another host
    [InlineData("http://10.0.0.5/a", "http://10.0.0.6/b", false)]
    public void SameOrigin_ComparesSchemeHostAndEffectivePort(string a, string b, bool same)
    {
        Assert.Equal(same, AvatarTarget.SameOrigin(new Uri(a), new Uri(b)));
        Assert.Equal(same, AvatarTarget.SameOrigin(new Uri(b), new Uri(a)));
    }
}
