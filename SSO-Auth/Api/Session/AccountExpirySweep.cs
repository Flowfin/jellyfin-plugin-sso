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

/// <summary>One pass of the between-logins account-expiry enforcement: every link whose persisted deadline has passed has its account disabled and its tokens revoked (#1145).</summary>
/// <remarks>
/// An administrator is never disabled, enforced inside the shared disable body rather than restated here. See
/// <see href="https://github.com/Flowfin/jellyfin-plugin-sso/wiki/Hardening-and-Options-Reference#time-limited-access-accountexpiryclaim"/>.
/// </remarks>
internal sealed class AccountExpirySweep
{
    private readonly CanonicalLinkService _canonicalLinks;
    private readonly ISessionManager _sessionManager;
    private readonly ILogger _logger;

    /// <summary>Initializes a new instance of the <see cref="AccountExpirySweep"/> class.</summary>
    /// <param name="canonicalLinks">The canonical-link store, which owns both the deadline read and the guarded disable.</param>
    /// <param name="sessionManager">Jellyfin's session manager, which revokes the disabled account's live tokens.</param>
    /// <param name="logger">The logger the audit line is written to.</param>
    internal AccountExpirySweep(CanonicalLinkService canonicalLinks, ISessionManager sessionManager, ILogger logger)
    {
        _canonicalLinks = canonicalLinks ?? throw new ArgumentNullException(nameof(canonicalLinks));
        _sessionManager = sessionManager ?? throw new ArgumentNullException(nameof(sessionManager));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    /// <summary>Runs one pass and returns how many accounts it disabled.</summary>
    /// <remarks>Idempotent: an account the previous tick disabled is neither re-audited nor re-revoked, and no identity provider is contacted.</remarks>
    /// <returns>The number of accounts disabled by this pass.</returns>
    internal async Task<int> SweepAsync()
    {
        // One clock read for the whole pass, in UTC (#676).
        var now = DateTime.UtcNow;
        var disabled = 0;

        foreach (var link in _canonicalLinks.ExpiredLinks(now))
        {
            // Each entry is re-resolved and re-guarded inside its own transaction.
            var disabledUserId = await _canonicalLinks.DisableExpiredAccountBySweepAsync(link.Mode, link.Provider, link.CanonicalKey).ConfigureAwait(false);
            if (disabledUserId is not { } userId)
            {
                continue;
            }

            disabled++;
            SsoAudit.AccountExpiredBySweep(_logger, AuditProtocol(link.Mode), link.Provider);

            // After the disable is persisted, and scoped to the one account whose access ended.
            await _sessionManager.RevokeUserTokens(userId, null).ConfigureAwait(false);
        }

        return disabled;
    }

    // The audit spelling the login path writes, so both routes' lines are found together.
    private static string AuditProtocol(ProviderMode mode) => mode switch
    {
        ProviderMode.Saml => "SAML",
        ProviderMode.Oid => "OpenID",
        _ => throw new ArgumentOutOfRangeException(nameof(mode), mode, "Unknown provider mode."),
    };
}
