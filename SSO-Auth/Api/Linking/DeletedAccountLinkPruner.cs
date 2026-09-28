// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Jellyfin.Data.Events.Users;
using Jellyfin.Plugin.SSO_Auth.Api.Audit;
using MediaBrowser.Controller.Events;
using MediaBrowser.Controller.Library;
using MediaBrowser.Model.Cryptography;
using Microsoft.Extensions.Logging;

namespace Jellyfin.Plugin.SSO_Auth.Api.Linking;

/// <summary>Takes a deleted Jellyfin account's links with it, the moment the host reports the deletion (#1649).</summary>
/// <remarks>
/// A link whose target was deleted counts as absent everywhere, so the next login for the same subject would
/// rebind the key at another account, which was the root under #1637, #1638 and #1647. The host publishes
/// <see cref="UserDeletedEventArgs"/> from its own delete and publishes nothing on enable or disable, so this is
/// the one transition the plugin can observe. The cost is the roster's orphan row (#1119); the fact goes to the
/// audit trail instead, naming protocol, provider and account id and never the subject. A failure to prune is
/// logged and swallowed, because a deletion that already happened must not be reported as failed.
/// </remarks>
internal sealed class DeletedAccountLinkPruner : IEventConsumer<UserDeletedEventArgs>
{
    private readonly Func<CanonicalLinkService?> _links;
    private readonly ILogger _logger;

    /// <summary>
    /// Initializes a new instance of the <see cref="DeletedAccountLinkPruner"/> class for the host's
    /// container: the link service is built per event over the plugin's live configuration store, the way
    /// the expiry sweep builds its own, and is null while the plugin instance is not up.
    /// </summary>
    /// <param name="userManager">Jellyfin user manager.</param>
    /// <param name="cryptoProvider">Jellyfin crypto provider, for the link service's provisioning arm.</param>
    /// <param name="logger">The logger.</param>
    public DeletedAccountLinkPruner(IUserManager userManager, ICryptoProvider cryptoProvider, ILogger<DeletedAccountLinkPruner> logger)
        : this(
            () => SSOPlugin.Instance is { } plugin ? new CanonicalLinkService(userManager, cryptoProvider, plugin.ConfigStore, logger) : null,
            logger)
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="DeletedAccountLinkPruner"/> class over an explicit link
    /// service factory, which is what the tests hand it.
    /// </summary>
    /// <param name="links">Yields the link service to prune through, or null when the plugin is not up.</param>
    /// <param name="logger">The logger.</param>
    internal DeletedAccountLinkPruner(Func<CanonicalLinkService?> links, ILogger logger)
    {
        _links = links ?? throw new ArgumentNullException(nameof(links));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    /// <inheritdoc />
    public Task OnEvent(UserDeletedEventArgs eventArgs)
    {
        if (eventArgs?.Argument is not { } user)
        {
            return Task.CompletedTask;
        }

        try
        {
            if (_links() is not { } links)
            {
                return Task.CompletedTask;
            }

            // The read before the removal is only the no-write guard: most deleted accounts never held a link, and
            // the removal itself is the revoke seam in its own transaction, which reports what it removed whatever
            // moved in between. One read answers both questions (#1733), because the minted-password record is keyed
            // on the account rather than a link and is dropped on both sides of the early return below; an account
            // that also holds a link rides the removal's own transaction rather than paying a second persist.
            var footprint = links.DeletionFootprint(user.Id);

            if (!footprint.HoldsLink)
            {
                if (footprint.HoldsMintedPasswordRecord)
                {
                    links.ForgetProvisionedPassword(user.Id);
                }

                return Task.CompletedTask;
            }

            var providers = new List<string>();
            var removed = links.RemoveUserEverywhere(user.Id, providers, footprint.HoldsMintedPasswordRecord);
            if (removed > 0)
            {
                SsoAudit.DeletedAccountUnlinked(_logger, user.Id, removed, providers);
            }
        }
        catch (Exception ex)
        {
            // The account id only, never a name or a subject: a Guid carries nothing a log line can be
            // forged through, so no sanitizer is needed here. Swallowed on purpose: see the class remarks.
            _logger.LogWarning(ex, "[SSO] Could not remove the SSO links of deleted user {UserId}; its links stay until the next login of the same subject clears them.", user.Id);
        }

        return Task.CompletedTask;
    }
}
