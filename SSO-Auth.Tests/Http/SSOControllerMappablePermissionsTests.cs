// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Linq;
using Jellyfin.Database.Implementations.Enums;
using Jellyfin.Plugin.SSO_Auth.Api.Authz;
using Jellyfin.Plugin.SSO_Auth.Config;
using Microsoft.AspNetCore.Mvc;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// In-process tests of <c>GET sso/Config/Permissions</c> (#1484) through <see cref="SsoControllerHarness"/>.
/// What is pinned here is the property the endpoint exists for: the vocabulary it publishes is DERIVED from
/// the same classification the save-time validator refuses by, so a page reading it can never offer a name
/// the save would reject, and can never omit one the save would accept.
/// </summary>
[Collection("SSOController")]
public class SSOControllerMappablePermissionsTests
{
    // The dedicated permissions, stated INDEPENDENTLY of the production set rather than read from it. This
    // is what makes the checks below able to fail: a derivation replaced by a literal keeps agreeing with
    // itself, and only a second statement of the rule can disagree with it. It is a rule, not a snapshot -
    // the first four have their own configuration surface, and IsDisabled is excluded because no SSO role
    // mapping may ever disable an account (#165, Finding H1).
    private static readonly string[] DedicatedPermissionNames =
    {
        nameof(PermissionKind.IsAdministrator),
        nameof(PermissionKind.EnableAllFolders),
        nameof(PermissionKind.EnableLiveTvAccess),
        nameof(PermissionKind.EnableLiveTvManagement),
        nameof(PermissionKind.IsDisabled),
    };

    private static MappablePermissionDocument Published(SsoControllerHarness harness) =>
        Assert.IsType<MappablePermissionDocument>(
            Assert.IsType<OkObjectResult>(harness.Controller.PermissionVocabulary().Result).Value);

    [Fact]
    public void ThePublishedSet_IsJellyfinsEnumMinusTheDedicatedPermissions()
    {
        // Derived on both sides of the assertion, from the enum rather than from names typed out here, so a
        // permission Jellyfin adds is published the day it lands instead of being measured against a
        // vocabulary that drifted. The expectation subtracts the dedicated names by the RULE above; the
        // endpoint subtracts them through PermissionRolePolicy.Classify. The two agreeing is the property.
        var expected = Enum.GetNames<PermissionKind>()
            .Where(name => !DedicatedPermissionNames.Contains(name, StringComparer.Ordinal))
            .OrderBy(name => name, StringComparer.Ordinal);

        Assert.Equal(expected, Published(new SsoControllerHarness()).Permissions);
    }

    [Fact]
    public void NoDedicatedPermission_IsOffered()
    {
        // The half that matters most, asserted on its own so it cannot be lost in a set comparison: a page
        // offering IsDisabled would let an administrator build the mapping that a single SSO login turns into
        // a whole-org lockout, and the save would refuse it only after they had chosen it.
        var published = Published(new SsoControllerHarness()).Permissions;

        foreach (var dedicated in DedicatedPermissionNames)
        {
            Assert.DoesNotContain(dedicated, published, StringComparer.Ordinal);
        }
    }

    [Fact]
    public void EveryPublishedName_IsAcceptedByTheSaveTimeValidator()
    {
        // The round trip in the direction a picker is used: every name offered must survive the refusal the
        // administrator would otherwise meet after choosing it. This is what "one producer" buys, and it is
        // stated against the validator rather than against the derivation it shares.
        foreach (var name in Published(new SsoControllerHarness()).Permissions)
        {
            ProviderConfigValidator.ValidatePermissionRoleMappings(
                "OpenID",
                "kc",
                new[] { new PermissionRoleMap { Permission = name, Roles = new[] { "staff" } } });
        }
    }

    [Fact]
    public void TheAnswer_ReadsNoConfiguration()
    {
        // Two harnesses whose configurations have nothing in common answer identically, because the set is
        // Jellyfin's compiled enum minus this plugin's compiled exclusion set. That is the property the
        // rate-limit exemption rests on, and it is asserted rather than argued.
        var bare = Published(new SsoControllerHarness()).Permissions;
        var loaded = Published(new SsoControllerHarness(c =>
        {
            c.OidConfigs["keycloak"] = new OidConfig { OidClientId = "client-1" };
            c.SamlConfigs["adfs"] = new SamlConfig { SamlEndpoint = "https://adfs.example.invalid/sso" };
        })).Permissions;

        Assert.Equal(bare, loaded);
    }

    [Fact]
    public void TheNamesAreOrdinallySorted_SoAConsumerNeedNotSortThem()
    {
        var published = Published(new SsoControllerHarness()).Permissions;

        Assert.Equal(published.OrderBy(name => name, StringComparer.Ordinal), published);
        Assert.NotEmpty(published);
    }
}
