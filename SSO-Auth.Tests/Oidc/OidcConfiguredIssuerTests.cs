// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using Jellyfin.Plugin.SSO_Auth.Api.Oidc;
using Jellyfin.Plugin.SSO_Auth.Config;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// Tests <see cref="OidcConfiguredIssuer"/> directly (#1518) - the rule the account-link import applies to
/// an issuer offered from outside a login. The rows the import itself exercises live beside it in
/// <c>LinkImportTests</c>; these are the ones about the rule rather than about the restore: what it accepts
/// because discovery would accept it, what it refuses because discovery would refuse it, what it does when
/// the provider states no expectation, and the bound on the value it echoes back to whoever posted the file.
/// </summary>
public class OidcConfiguredIssuerTests
{
    [Theory]
    [InlineData("https://idp.example.test", "https://idp.example.test")]
    [InlineData("https://idp.example.test", "https://idp.example.test/")]
    [InlineData("https://idp.example.test/", "https://idp.example.test")]
    [InlineData("https://idp.example.test/.well-known/openid-configuration", "https://idp.example.test")]
    [InlineData("https://idp.example.test/realms/main", "https://idp.example.test/realms/main")]
    [InlineData("https://idp.example.test:8443", "https://idp.example.test:8443")]
    public void AnIssuerDiscoveryWouldAccept_IsAccepted(string endpoint, string issuer)
    {
        // The accept set has to be a superset of what a login can stamp, or the check refuses honest imports.
        // The trailing-slash and well-known rows are the ones that would bite first in the field, because an
        // operator writes the endpoint either way and the discovery document writes the issuer the other.
        Assert.Null(OidcConfiguredIssuer.Refuse(new OidConfig { OidEndpoint = endpoint }, issuer));
    }

    [Theory]
    [InlineData("https://idp.example.com", "http://idp.lan")]
    [InlineData("https://idp.example.test", "https://evil.example.test")]
    [InlineData("https://idp.example.test/realms/main", "https://idp.example.test/realms/other")]
    public void AnIssuerDiscoveryWouldRefuse_IsRefusedAndNamesBoth(string endpoint, string issuer)
    {
        var reason = OidcConfiguredIssuer.Refuse(new OidConfig { OidEndpoint = endpoint }, issuer);

        Assert.NotNull(reason);
        Assert.Contains(issuer, reason, StringComparison.Ordinal);
        Assert.Contains(endpoint, reason, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("not a url")]
    [InlineData("ftp://idp.example.test")]
    public void AnEndpointThatNamesNoUsableAuthority_RefusesEveryIssuer(string? endpoint)
    {
        // Fail closed rather than "cannot tell, so yes". A half-filled provider persists fine - the save gate
        // has no required-field check - so this arm is reachable from an ordinary stored state rather than
        // only from a malformed one, and answering it with acceptance would store a binding against a
        // provider that can complete no login at all.
        var reason = OidcConfiguredIssuer.Refuse(new OidConfig { OidEndpoint = endpoint }, "https://idp.example.test");

        Assert.NotNull(reason);
        Assert.Contains("is not a usable URL", reason, StringComparison.Ordinal);
    }

    [Fact]
    public void AProviderWithIssuerNameValidationOff_AcceptsEveryIssuer()
    {
        // Not a hole this type leaves open, an entailment. DoNotValidateIssuerName sets ValidateIssuer to
        // false in the id_token parameters, so a login on that provider accepts a signed token carrying any
        // iss and can stamp any issuer; a check asking whether a login could stamp this value has one honest
        // answer. What it does NOT make safe is the binding comparison, which never reads the toggle - which
        // is why no page offers the toggle as a way past this refusal.
        var config = new OidConfig { OidEndpoint = "https://idp.example.test", DoNotValidateIssuerName = true };

        Assert.Null(OidcConfiguredIssuer.Refuse(config, "https://tenant-7.idp.example.test"));
    }

    [Fact]
    public void ABlankIssuer_IsNotThisRuleSubject()
    {
        // An absent issuer means "leave the binding alone", which the import decides before it asks here. The
        // rule would otherwise refuse every backup taken before the binding existed.
        var config = new OidConfig { OidEndpoint = "https://idp.example.test" };

        Assert.Null(OidcConfiguredIssuer.Refuse(config, null));
        Assert.Null(OidcConfiguredIssuer.Refuse(config, "   "));
    }

    [Fact]
    public void AnOverlongIssuer_IsEchoedBounded()
    {
        // The refusal is echoed into an HTTP error body and into the log line beside it, and the value is the
        // caller's own text rather than the plugin's. Without a bound, one posted file decides how much a
        // dashboard toast and a log entry have to carry.
        var overlong = "https://idp.example.test/" + new string('a', 4000);

        var reason = OidcConfiguredIssuer.Refuse(new OidConfig { OidEndpoint = "https://idp.example.com" }, overlong);

        Assert.NotNull(reason);
        Assert.DoesNotContain(overlong, reason, StringComparison.Ordinal);
        Assert.Contains("[truncated]", reason, StringComparison.Ordinal);
        Assert.True(reason.Length < 600, "the refusal stays readable: " + reason.Length.ToString(System.Globalization.CultureInfo.InvariantCulture));
    }
}
