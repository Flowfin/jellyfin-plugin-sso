// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Threading.Tasks;
using MediaBrowser.Controller.Events;
using MediaBrowser.Controller.Events.Authentication;
using MediaBrowser.Controller.Session;
using Microsoft.Extensions.Logging;

namespace Jellyfin.Plugin.SSO_Auth.Api.Events;

/// <summary>
/// Publishes the one SSO login moment Jellyfin's own event bus can carry (#1142): a login the role
/// allow-list refused. The host raises its authentication-failed event only from
/// <c>SessionManager.AuthenticateNewSessionInternal</c>, on the arm where no user resolved, and an SSO
/// login denied by role mapping never reaches that method - it returns before the mint - so nothing
/// delivers that denial today.
/// </summary>
/// <remarks>
/// <para>
/// The event type is the HOST's <see cref="AuthenticationRequestEventArgs"/> rather than one this plugin
/// declares, because a plugin-declared type reaches no consumer: <c>jellyfin-plugin-webhook</c> implements
/// twenty closed <c>IEventConsumer&lt;T&gt;</c> over Jellyfin's own types and no open or non-generic one, so
/// a foreign argument type has no method to be handed to. Publishing the host type is what makes the denial
/// arrive at a configured destination as <c>AuthenticationFailure</c> with no change on that side.
/// </para>
/// <para>
/// The payload carries the provider and a fixed reason and NOTHING about the person: no username, no
/// subject, no claim value. That is the same T-I1 rule the audit trail is written under, applied harder
/// because a webhook payload leaves the machine. The reason is a constant on this class rather than a
/// parameter, so a caller structurally cannot put request- or provider-derived text into the field.
/// </para>
/// <para>
/// A denial's response must not depend on a notification, so every failure here is swallowed and logged.
/// Jellyfin's own <c>EventManager</c> already catches each consumer's exception; the guard below covers the
/// publish itself, and it is what keeps a broken destination from turning a 401 into a 500.
/// </para>
/// </remarks>
internal sealed class SsoLoginEvents
{
    /// <summary>
    /// The client name every SSO-raised event carries, ahead of the provider name. This is what tells an
    /// operator's destination that the denial came from single sign-on rather than from the password form.
    /// </summary>
    internal const string ClientPrefix = "SSO/";

    /// <summary>
    /// The fixed reason the role-mapping denial reports, in the event's device-name field. A constant, never
    /// a parameter: the closed vocabulary the issue asks for, held by construction rather than by discipline.
    /// </summary>
    internal const string RoleDeniedReason = "role-mapping-denied";

    /// <summary>
    /// The device id every SSO-raised event carries. Fixed, because a denial mints no session and so has no
    /// device of its own; a stable value keeps the events grouped rather than inventing one per request.
    /// </summary>
    internal const string EventDeviceId = "sso-auth";

    private readonly IEventManager? _events;
    private readonly ILogger _logger;

    /// <summary>
    /// Initializes a new instance of the <see cref="SsoLoginEvents"/> class.
    /// </summary>
    /// <param name="events">Jellyfin's event bus, or <see langword="null"/> where the host supplied none - in which case nothing is published and no login path changes.</param>
    /// <param name="logger">The logger that records a publish that could not be made.</param>
    internal SsoLoginEvents(IEventManager? events, ILogger logger)
    {
        _events = events;
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    /// <summary>
    /// Publishes the host's authentication-failed event for a login the role allow-list refused.
    /// </summary>
    /// <param name="provider">The configured provider name the login was attempted against; it rides in the client field behind <see cref="ClientPrefix"/>.</param>
    /// <param name="remoteEndPoint">The normalized client address (#177), or <see langword="null"/> where the call site has none.</param>
    /// <returns>A task that completes once every consumer has been offered the event.</returns>
    internal async Task PublishRoleDeniedAsync(string? provider, string? remoteEndPoint)
    {
        if (_events is null)
        {
            return;
        }

        try
        {
            var request = new AuthenticationRequest
            {
                // Deliberately empty: the person is not named. See the T-I1 note above - the OpenID denial
                // resolves a claim-derived username and the SAML one a NameID, and neither may leave the
                // machine, so the field is empty on BOTH protocols rather than on whichever happens to have
                // less to say.
                Username = string.Empty,
                App = ClientPrefix + provider,
                AppVersion = SSOPlugin.Instance?.Version?.ToString() ?? string.Empty,
                DeviceId = EventDeviceId,
                DeviceName = RoleDeniedReason,
                RemoteEndPoint = remoteEndPoint ?? string.Empty,
            };

            await _events.PublishAsync(new AuthenticationRequestEventArgs(request)).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            // Never let a notification decide a login's answer. The denial has already been settled by the
            // policy above this call; this only reports it.
            _logger.LogWarning(ex, "Could not publish the SSO role-denied event for provider {Provider}.", provider?.ReplaceLineEndings(string.Empty));
        }
    }
}
