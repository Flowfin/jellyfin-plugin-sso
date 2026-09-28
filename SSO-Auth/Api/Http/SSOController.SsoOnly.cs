// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net.Mime;
using System.Threading.Tasks;
using Jellyfin.Database.Implementations.Entities;
using Jellyfin.Database.Implementations.Enums;
using Jellyfin.Plugin.SSO_Auth.Api.Audit;
using Jellyfin.Plugin.SSO_Auth.Api.Events;
using Jellyfin.Plugin.SSO_Auth.Api.Flows;
using Jellyfin.Plugin.SSO_Auth.Api.Linking;
using Jellyfin.Plugin.SSO_Auth.Api.Logout;
using Jellyfin.Plugin.SSO_Auth.Api.Metrics;
using Jellyfin.Plugin.SSO_Auth.Api.Net;
using Jellyfin.Plugin.SSO_Auth.Api.Oidc;
using Jellyfin.Plugin.SSO_Auth.Api.Provider;
using Jellyfin.Plugin.SSO_Auth.Api.Session;
using Jellyfin.Plugin.SSO_Auth.Config;
using MediaBrowser.Common.Api;
using MediaBrowser.Controller;
using MediaBrowser.Controller.Configuration;
using MediaBrowser.Controller.Events;
using MediaBrowser.Controller.Library;
using MediaBrowser.Controller.Net;
using MediaBrowser.Controller.Providers;
using MediaBrowser.Controller.Session;
using MediaBrowser.Model.Cryptography;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Jellyfin.Plugin.SSO_Auth.Api.Http;

/// <summary>The SSO-only login mode endpoints and the managed-account status reads.</summary>
public partial class SSOController
{
    /// <summary>
    /// Reports the current SSO-only login state (#165): whether the mode is on, which account is the
    /// designated break-glass admin, and whether that designation still satisfies the fail-closed survivor
    /// guard. Requires administrator privileges. Read-only - it changes nothing.
    /// </summary>
    /// <returns>The SSO-only login status.</returns>
    [Authorize(Policy = Policies.RequiresElevation)]
    [HttpGet("SSO-Only/Status")]
    [Produces(MediaTypeNames.Application.Json)]
    public ActionResult SsoOnlyStatus()
    {
        var (disablePasswordLogin, breakGlassAdmin) = SSOPlugin.Instance.ReadConfiguration(
            configuration => (configuration.DisablePasswordLogin, configuration.BreakGlassAdminUsername));

        // The guard is evaluated live against the current account state so the page can warn if the
        // break-glass admin was deleted, demoted, disabled, or lost its password after activation (T-D2).
        var guardSatisfied = SsoOnlyLoginGuard.Evaluate(breakGlassAdmin, _ssoOnly.DescribeBreakGlass(breakGlassAdmin))
            == SsoOnlyGuardVerdict.Allow;

        return Ok(new
        {
            DisablePasswordLogin = disablePasswordLogin,
            BreakGlassAdminUsername = breakGlassAdmin,
            GuardSatisfied = guardSatisfied,
        });
    }

    /// <summary>Reports whether one Jellyfin account is SSO-managed (#1136), so a provisioning tool can decide in one call whether to offer a password field, a reset link, or neither; elevation-gated and read-only.</summary>
    /// <remarks>The two facts are reported separately because they differ: an account can hold a canonical link while its <c>AuthenticationProviderId</c> still routes password attempts to core, and can carry the SSO stamp with no link left on it; only the first decides whether a password can be used.</remarks>
    /// <param name="jellyfinUserId">The Jellyfin user to report on.</param>
    /// <returns>The account's SSO posture, or 404 when no such user exists.</returns>
    [Authorize(Policy = Policies.RequiresElevation)]
    [HttpGet("SSO-Managed/Status/{jellyfinUserId}")]
    [Produces(MediaTypeNames.Application.Json)]
    public ActionResult SsoManagedStatus(Guid jellyfinUserId)
    {
        // A user id nobody holds is a 404 rather than a report of two falses: "this account uses passwords"
        // and "this account does not exist" are different answers, and a caller that cannot tell them apart
        // would offer a password field for an account it is about to fail to find.
        if (_userManager.GetUserById(jellyfinUserId) is not { } user)
        {
            return NotFound("No such Jellyfin user.");
        }

        return Ok(new
        {
            // The same detector the SSO-only feature and the login-path re-assertion use, so this report and
            // the enforcement can never disagree about what the stamp means.
            PasswordLoginDisabled = SsoAuthenticationProviders.IsSsoProvider(user.AuthenticationProviderId),
            HasCanonicalLink = HoldsAnyCanonicalLink(jellyfinUserId),
        });
    }

    /// <summary>
    /// Whether the user holds at least one canonical link on any provider of either protocol. Reuses the
    /// same per-mode read the link endpoints answer with, so this cannot report a link set the link
    /// endpoints would not list. A provider present with no link for this user yields an empty list, which
    /// is why the test is on the values rather than on the map being non-empty.
    /// </summary>
    /// <param name="jellyfinUserId">The Jellyfin user to look for.</param>
    /// <returns>True when any provider of either protocol holds a link for that user.</returns>
    private bool HoldsAnyCanonicalLink(Guid jellyfinUserId) =>
        _canonicalLinks.LinksByUser(ProviderMode.Oid, jellyfinUserId).Any(entry => entry.Value.Any())
        || _canonicalLinks.LinksByUser(ProviderMode.Saml, jellyfinUserId).Any(entry => entry.Value.Any());

    /// <summary>
    /// Turns SSO-only login on (#165), designating <paramref name="breakGlassAdminUsername"/> as the account
    /// whose native password login is never disabled. Requires administrator privileges. Fail-closed: the
    /// last-admin guard runs first, and unless the designated account is an existing, enabled administrator
    /// that still has a password, the activation is refused with a clear, non-enumerating message and nothing
    /// is changed. On success every non-exempt account is repointed off the password provider and the
    /// transition is audited.
    /// </summary>
    /// <param name="breakGlassAdminUsername">The administrator account to keep password-capable as the break-glass door.</param>
    /// <returns>Ok on activation, or 400 with the refusal reason when the guard rejects it.</returns>
    [Authorize(Policy = Policies.RequiresElevation)]
    [HttpPost("SSO-Only/Enable")]
    [Consumes(MediaTypeNames.Application.Json)]
    public async Task<ActionResult> EnableSsoOnly([FromBody] string breakGlassAdminUsername)
    {
        var actor = await ResolveActorAsync().ConfigureAwait(false);
        var outcome = await _ssoOnly.TryEnableAsync(breakGlassAdminUsername).ConfigureAwait(false);
        if (outcome.Verdict != SsoOnlyGuardVerdict.Allow)
        {
            // Fail closed: a blocked lockout attempt is audited (reason CODE only, no roster) and refused.
            SsoAudit.SsoOnlyLoginActivationRefused(_logger, actor, outcome.Verdict.ToString());
            return BadRequest(SsoOnlyLoginGuard.PublicRefusalMessage);
        }

        SsoAudit.SsoOnlyLoginEnabled(_logger, actor, outcome.BreakGlassAdmin, outcome.RepointedCount);
        return Ok();
    }

    /// <summary>
    /// Turns SSO-only login off (#165), the reversible no-SSO off-switch: it restores native password
    /// routing for every account the mode repointed, WITHOUT resetting or exposing any password. Requires
    /// administrator privileges. Audited on the transition.
    /// </summary>
    /// <returns>Ok once password routing is restored.</returns>
    [Authorize(Policy = Policies.RequiresElevation)]
    [HttpPost("SSO-Only/Disable")]
    public async Task<ActionResult> DisableSsoOnly()
    {
        var actor = await ResolveActorAsync().ConfigureAwait(false);
        var restored = await _ssoOnly.DisableAsync().ConfigureAwait(false);
        SsoAudit.SsoOnlyLoginDisabled(_logger, actor, restored);
        return Ok();
    }

    /// <summary>Sets or changes the designated break-glass administrator (#165), the account SSO-only mode never repoints; elevation-gated and audited.</summary>
    /// <remarks>Fail-closed: the target must be an existing, enabled administrator that still has a password, so the exemption can never point at a non-admin and cannot grant admin; to change the designation while the mode is on, disable it first, because every other admin has already been repointed off the password provider.</remarks>
    /// <param name="username">The administrator account to designate as the break-glass admin.</param>
    /// <returns>Ok on success, or 400 with the refusal reason when the target does not qualify.</returns>
    [Authorize(Policy = Policies.RequiresElevation)]
    [HttpPost("SSO-Only/BreakGlassAdmin")]
    [Consumes(MediaTypeNames.Application.Json)]
    public async Task<ActionResult> DesignateBreakGlassAdmin([FromBody] string username)
    {
        var actor = await ResolveActorAsync().ConfigureAwait(false);
        var outcome = _ssoOnly.TryDesignateBreakGlass(username);
        if (outcome.Verdict != SsoOnlyGuardVerdict.Allow)
        {
            SsoAudit.SsoOnlyLoginActivationRefused(_logger, actor, outcome.Verdict.ToString());
            return BadRequest(SsoOnlyLoginGuard.PublicRefusalMessage);
        }

        SsoAudit.BreakGlassAdminDesignated(_logger, actor, outcome.BreakGlassAdmin);
        return Ok();
    }
}
