// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Jellyfin.Data.Events.Users;
using Jellyfin.Plugin.SSO_Auth.Api.Audit;
using Jellyfin.Plugin.SSO_Auth.Api.Provider;
using MediaBrowser.Controller.Events;
using MediaBrowser.Controller.Library;
using MediaBrowser.Model.Cryptography;
using Microsoft.Extensions.Logging;

namespace Jellyfin.Plugin.SSO_Auth.Api.Linking;

/// <summary>
/// Takes a deleted Jellyfin account's links with it, the moment the host reports the deletion (#1649).
/// </summary>
/// <remarks>
/// <para>
/// A link whose target account was deleted counts as absent everywhere in this plugin, so the next login
/// for the same subject writes the key again at another account. That dangling link was the root under
/// three things found on one day: a pending-approval record that followed the key (#1637), a deadline that
/// disabled the account that inherited it (#1638), and the first step of a guest's exit from their own
/// limit (#1647). Each map now guards itself on rebind; this removes the state that made a rebind possible.
/// </para>
/// <para>
/// The host publishes <see cref="UserDeletedEventArgs"/> from its own delete, and its event manager hands it
/// to every registered consumer of that closed type - the same mechanism the webhook plugin listens on.
/// Enabling or disabling an account publishes nothing (checked against the host's source), which is why
/// this is the one transition the plugin can observe and the enable is not.
/// </para>
/// <para>
/// WHAT IT COSTS is the roster's orphan row: a link whose account is gone was kept on purpose (#1119) so an
/// administrator could find it. Pruned here, that row does not appear for an account deleted while the
/// plugin was loaded; the fact goes to the audit trail instead, one line per deleted account naming the
/// protocol and provider of every link removed and the account id, never the subject (T-I1). An account
/// deleted while the plugin was not loaded still leaves an orphan, and the roster still shows it.
/// </para>
/// <para>
/// NOTHING HERE MAY REACH THE HOST'S DELETE. The host's event manager catches a consumer's exception, but
/// the rule is kept on this side as well: a failure to prune is logged at Warning and swallowed, because a
/// deletion that already happened must not be reported as failed over bookkeeping the next login would
/// otherwise have to clean up on its own.
/// </para>
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

            // The providers are read before the removal so the audit line can name them, and so an account
            // that held no link costs no write: the revoke seam persists the configuration whenever it runs,
            // and most deleted accounts never had an SSO link - including the one this plugin's own create
            // arm rolls back when a login fails after creating it, where a persist on a full disk would
            // otherwise warn that links stayed which never existed. The removal itself is the existing
            // revoke seam, in its own transaction, which prunes every map that hangs off the links it
            // removes. A link that arrives between the two reads is removed and goes unnamed, which is the
            // harmless direction; one that arrives after an empty read is left to the next login of its
            // subject, which treats a dangling link as absent, exactly as before this consumer existed.
            var providers = HoldingLinksFor(links, user.Id);
            if (providers.Count == 0)
            {
                return Task.CompletedTask;
            }

            var removed = links.RemoveUserEverywhere(user.Id);
            if (removed > 0)
            {
                SsoAudit.DeletedAccountUnlinked(_logger, user.Id, removed, providers);
            }
        }
        catch (Exception ex)
        {
            // The account id only, never a name or a subject, and line endings stripped at the call as
            // the audit trail requires. Swallowed on purpose: see the class remarks.
            _logger.LogWarning(ex, "[SSO] Could not remove the SSO links of deleted user {UserId}; its links stay until the next login of the same subject clears them.", user.Id);
        }

        return Task.CompletedTask;
    }

    // Every provider, labelled by protocol, that holds at least one link for the account.
    private static List<string> HoldingLinksFor(CanonicalLinkService links, Guid userId)
    {
        return links.LinksByUser(ProviderMode.Oid, userId).Where(entry => entry.Value.Any()).Select(entry => "OpenID '" + entry.Key + "'")
            .Concat(links.LinksByUser(ProviderMode.Saml, userId).Where(entry => entry.Value.Any()).Select(entry => "SAML '" + entry.Key + "'"))
            .ToList();
    }
}
