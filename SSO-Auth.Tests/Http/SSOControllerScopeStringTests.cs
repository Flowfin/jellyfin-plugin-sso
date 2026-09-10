// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using Jellyfin.Plugin.SSO_Auth.Api;
using Jellyfin.Plugin.SSO_Auth.Api.Flows;
using Jellyfin.Plugin.SSO_Auth.Config;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// Pins <see cref="OidcLoginService.BuildScopeString"/> - the shared OpenID scope-string builder used by
/// both the challenge and the callback client. Guards #368: a provider stored without scopes leaves
/// <see cref="OidConfig.OidScopes"/> null, which previously threw an unhandled 500 on the anonymous
/// challenge (<c>OidScopes.Prepend</c> on null) and null-padded the callback scope string
/// (<c>new string[2]</c> → trailing separators). The builder normalizes null to empty so both sides
/// emit the same clean, base-prefixed string.
/// And #1612: the base is a UNION with what is configured, not a prefix in front of it. The cases below
/// that carry <c>openid</c> or <c>profile</c> in the configuration are the ordinary ones - it is what every
/// provider template here and the wiki tell an administrator to enter - and until #1612 they were the only
/// shape this file did not cover, which is how every login on every installation came to ask twice.
/// </summary>
public class SSOControllerScopeStringTests
{
    [Fact]
    public void NullScopes_YieldBaseScopesOnly_NoThrow()
    {
        var config = new OidConfig { OidScopes = null };

        Assert.Equal("openid profile", OidcLoginService.BuildScopeString(config));
    }

    [Fact]
    public void EmptyScopes_YieldBaseScopesOnly()
    {
        var config = new OidConfig { OidScopes = Array.Empty<string>() };

        Assert.Equal("openid profile", OidcLoginService.BuildScopeString(config));
    }

    [Fact]
    public void ConfiguredScopes_ArePrefixedWithBaseScopes()
    {
        var config = new OidConfig { OidScopes = new[] { "email", "groups" } };

        Assert.Equal("openid profile email groups", OidcLoginService.BuildScopeString(config));
    }

    [Fact]
    public void NullElement_IsDropped_NoTrailingSeparator()
    {
        var config = new OidConfig { OidScopes = new[] { "email", null } };

        Assert.Equal("openid profile email", OidcLoginService.BuildScopeString(config));
    }

    [Fact]
    public void EmptyElement_IsDropped_NoDoubledSeparator()
    {
        var config = new OidConfig { OidScopes = new[] { "", "groups" } };

        Assert.Equal("openid profile groups", OidcLoginService.BuildScopeString(config));
    }

    [Fact]
    public void AllBlankElements_YieldBaseScopesOnly()
    {
        var config = new OidConfig { OidScopes = new[] { "", " ", null } };

        Assert.Equal("openid profile", OidcLoginService.BuildScopeString(config));
    }

    [Fact]
    public void TheConfiguredBase_IsNotRepeated()
    {
        // What every wiki page and every provider template in this repository tells an administrator to
        // enter. Before #1612 this went out as "openid profile openid profile email".
        var config = new OidConfig { OidScopes = new[] { "openid", "profile", "email" } };

        Assert.Equal("openid profile email", OidcLoginService.BuildScopeString(config));
    }

    [Fact]
    public void AScopeRepeatedInTheConfiguration_IsCarriedOnce()
    {
        var config = new OidConfig { OidScopes = new[] { "email", "groups", "email" } };

        Assert.Equal("openid profile email groups", OidcLoginService.BuildScopeString(config));
    }

    [Fact]
    public void TheBaseStillLeads_WhenTheConfigurationOrdersItLater()
    {
        // openid missing is not an OpenID request, so its position is the builder's to decide and not the
        // stored order's. A configuration naming it last still gets it first, and only once.
        var config = new OidConfig { OidScopes = new[] { "email", "openid" } };

        Assert.Equal("openid profile email", OidcLoginService.BuildScopeString(config));
    }

    [Fact]
    public void SeveralScopesTypedIntoOneEntry_BecomeSeveralScopes()
    {
        // The field takes a list, and an administrator who pasted a space-delimited scope string into one
        // row of it meant several scopes. Splitting is also what keeps that row from smuggling a repeat of
        // the base past the union.
        var config = new OidConfig { OidScopes = new[] { "openid profile email", "groups" } };

        Assert.Equal("openid profile email groups", OidcLoginService.BuildScopeString(config));
    }

    [Fact]
    public void ScopeComparisonIsCaseSensitive()
    {
        // Scope values are case-sensitive in the specification, so these are two scopes. Collapsing them
        // would be this builder deciding something about a provider it does not know.
        var config = new OidConfig { OidScopes = new[] { "Email", "email" } };

        Assert.Equal("openid profile Email email", OidcLoginService.BuildScopeString(config));
    }
}
