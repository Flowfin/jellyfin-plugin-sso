// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Threading.Tasks;
using Jellyfin.Plugin.SSO_Auth.Api.Audit;
using Jellyfin.Plugin.SSO_Auth.Api.Linking;
using Jellyfin.Plugin.SSO_Auth.Api.Provider;
using MediaBrowser.Controller.Session;
using Microsoft.Extensions.Logging;

namespace Jellyfin.Plugin.SSO_Auth.Api.Session;

/// <summary>
/// One pass of the between-logins account-expiry enforcement (#1145): every canonical link whose persisted
/// deadline is at or before now has its Jellyfin account disabled and that account's tokens revoked.
/// <para>
/// Login-time enforcement (#1144) only fires when the expired user comes back, so without this a guest who
/// simply stops logging in keeps an enabled account, any long-lived token, and - with
/// <c>DisablePasswordLogin</c> off - a password door, indefinitely. That is "expired users are refused"
/// rather than "time-limited access", which is the whole claim of the feature.
/// </para>
/// <para>
/// THE GUARD is the same mass-lockout defence the login path carries (T-D1), and it matters MORE here
/// because nobody is watching: an identity provider that started emitting a past instant has, by the time a
/// tick runs, already had every affected deadline written to disk. An administrator is never disabled, and
/// that is enforced inside the shared disable body rather than restated here, so the exemption cannot be
/// present on one path and absent on the other.
/// </para>
/// <para>
/// The pass is separated from the timer that drives it (<see cref="AccountExpirySweepService"/>) so the
/// behaviour is exercised directly by the suite rather than through a clock.
/// </para>
/// </summary>
internal sealed class AccountExpirySweep
{
    private readonly CanonicalLinkService _canonicalLinks;
    private readonly ISessionManager _sessionManager;
    private readonly ILogger _logger;

    /// <summary>
    /// Initializes a new instance of the <see cref="AccountExpirySweep"/> class.
    /// </summary>
    /// <param name="canonicalLinks">The canonical-link store, which owns both the deadline read and the guarded disable.</param>
    /// <param name="sessionManager">Jellyfin session manager, used to revoke the disabled account's live tokens; without it a token minted before the deadline outlives it.</param>
    /// <param name="logger">The logger the audit line is written to.</param>
    internal AccountExpirySweep(CanonicalLinkService canonicalLinks, ISessionManager sessionManager, ILogger logger)
    {
        _canonicalLinks = canonicalLinks ?? throw new ArgumentNullException(nameof(canonicalLinks));
        _sessionManager = sessionManager ?? throw new ArgumentNullException(nameof(sessionManager));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    /// <summary>
    /// Runs one pass and returns how many accounts it disabled.
    /// </summary>
    /// <remarks>
    /// Idempotent by construction. A tick that finds no deadline in the past touches nothing; a tick that
    /// finds an account the previous tick already disabled gets <see langword="null"/> back from the disable
    /// and neither re-audits nor re-revokes, so a permanently expired link costs one audit line in total
    /// rather than one per tick. Cheap by construction too: a bounded walk over the persisted maps and, per
    /// account actually disabled, one user write and one revoke. No identity provider is contacted - polling
    /// the identity provider for a revocation it never announced is a different question (#831's deferred
    /// half) and stays out of this.
    /// </remarks>
    /// <returns>The number of accounts disabled by this pass.</returns>
    internal async Task<int> SweepAsync()
    {
        // One clock read for the whole pass (#676, UTC throughout), so two links with the same deadline
        // cannot land on opposite sides of it because the walk took a moment.
        var now = DateTime.UtcNow;
        var disabled = 0;

        foreach (var link in _canonicalLinks.ExpiredLinks(now))
        {
            // Each entry is re-resolved and re-guarded inside its own transaction, so a link removed, a user
            // deleted, or an account promoted to administrator since the snapshot is a no-op here rather
            // than a disable of something the snapshot no longer describes.
            var disabledUserId = await _canonicalLinks.DisableExpiredAccountBySweepAsync(link.Mode, link.Provider, link.CanonicalKey).ConfigureAwait(false);
            if (disabledUserId is not { } userId)
            {
                continue;
            }

            disabled++;
            SsoAudit.AccountExpiredBySweep(_logger, AuditProtocol(link.Mode), link.Provider);

            // Runs after the disable is persisted, so a revoke that throws leaves the account already
            // disabled rather than the pair half-done. Scoped strictly to the one account whose access just
            // ended, never a provider-wide logout.
            await _sessionManager.RevokeUserTokens(userId, null).ConfigureAwait(false);
        }

        return disabled;
    }

    // The audit spelling of a protocol, matching what the login path writes through VerifiedIdentity so an
    // operator grepping the trail for one provider's expiries finds both routes' lines.
    private static string AuditProtocol(ProviderMode mode) => mode switch
    {
        ProviderMode.Saml => "SAML",
        ProviderMode.Oid => "OpenID",
        _ => throw new ArgumentOutOfRangeException(nameof(mode), mode, "Unknown provider mode."),
    };
}
