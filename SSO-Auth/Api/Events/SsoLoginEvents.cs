// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Threading.Tasks;
using MediaBrowser.Controller.Events;
using MediaBrowser.Controller.Events.Authentication;
using MediaBrowser.Controller.Session;
using Microsoft.Extensions.Logging;

namespace Jellyfin.Plugin.SSO_Auth.Api.Events;

/// <summary>Publishes the one SSO login moment Jellyfin's own event bus can carry (#1142): a login the role allow-list refused, which never reaches the host's own authentication-failed arm.</summary>
/// <remarks>
/// The event type is the host's <see cref="AuthenticationRequestEventArgs"/>, because the webhook plugin consumes
/// only closed host types, so the denial arrives at a configured destination as <c>AuthenticationFailure</c>. The
/// payload carries the provider, a fixed reason picked by method rather than passed as text, and the client
/// address, and nothing that names the person. Every failure is swallowed and logged, and the wait is capped at
/// <see cref="PublishBudget"/>, because a consumer that neither returns nor throws, a webhook to a black-holed
/// destination, would otherwise hold a refusal that was already decided; the publish itself is left running.
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
    /// The fixed reason for the other refusal that shares the OpenID denial arm: the login resolved no
    /// username to create or adopt an account under. Reported apart from the role denial because the two
    /// ask an operator for different things - one is a provider policy decision, the other a claim or scope
    /// that is missing - and one label for both would state a cause the code cannot substantiate.
    /// </summary>
    internal const string UnresolvedUsernameReason = "no-username-resolved";

    /// <summary>
    /// The device id every SSO-raised event carries. Fixed, because a denial mints no session and so has no
    /// device of its own; a stable value keeps the events grouped rather than inventing one per request.
    /// </summary>
    internal const string EventDeviceId = "sso-auth";

    /// <summary>
    /// The longest a login refusal may wait for its own notification to be delivered. Chosen rather than
    /// derived: long enough for the ordinary case, where the destination is a relay on the operator's own
    /// network answering in milliseconds, and short enough that a destination which has stopped answering
    /// adds a delay a person reads as a slow page rather than as a hung one.
    /// </summary>
    internal static readonly TimeSpan PublishBudget = TimeSpan.FromSeconds(3);

    private readonly IEventManager? _events;
    private readonly ILogger _logger;
    private readonly TimeSpan _budget;

    /// <summary>
    /// Initializes a new instance of the <see cref="SsoLoginEvents"/> class.
    /// </summary>
    /// <param name="events">Jellyfin's event bus, or <see langword="null"/> where the host supplied none - in which case nothing is published and no login path changes.</param>
    /// <param name="logger">The logger that records a publish that could not be made.</param>
    /// <param name="budget">How long a refusal may wait for its notification; defaults to <see cref="PublishBudget"/>. A parameter only so a test can prove the bound bites without spending the production budget on it.</param>
    internal SsoLoginEvents(IEventManager? events, ILogger logger, TimeSpan? budget = null)
    {
        _events = events;
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _budget = budget ?? PublishBudget;
    }

    /// <summary>
    /// Publishes the host's authentication-failed event for a login the role allow-list refused.
    /// </summary>
    /// <param name="provider">The configured provider name the login was attempted against; it rides in the client field behind <see cref="ClientPrefix"/>.</param>
    /// <param name="remoteEndPoint">The normalized client address (#177), or <see langword="null"/> where the call site has none.</param>
    /// <returns>A task that completes once every consumer has been offered the event.</returns>
    internal Task PublishRoleDeniedAsync(string? provider, string? remoteEndPoint)
        => PublishDeniedAsync(RoleDeniedReason, provider, remoteEndPoint);

    /// <summary>
    /// Publishes the host's authentication-failed event for a login that resolved no username.
    /// </summary>
    /// <param name="provider">The configured provider name the login was attempted against.</param>
    /// <param name="remoteEndPoint">The normalized client address (#177), or <see langword="null"/> where the call site has none.</param>
    /// <returns>A task that completes once every consumer has been offered the event.</returns>
    internal Task PublishUnresolvedUsernameDeniedAsync(string? provider, string? remoteEndPoint)
        => PublishDeniedAsync(UnresolvedUsernameReason, provider, remoteEndPoint);

    private async Task PublishDeniedAsync(string reason, string? provider, string? remoteEndPoint)
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
                DeviceName = reason,
                RemoteEndPoint = remoteEndPoint ?? string.Empty,
            };

            // WaitAsync abandons the WAIT rather than the work: a consumer that is still talking to a
            // stalled destination keeps going on its own, and the refusal answers. Nothing is left unobserved
            // by that - Jellyfin's EventManager catches every consumer exception inside the task it returns,
            // so the abandoned task cannot fault.
            await _events.PublishAsync(new AuthenticationRequestEventArgs(request)).WaitAsync(_budget).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            // Never let a notification decide a login's answer. The denial has already been settled by the
            // policy above this call; this only reports it.
            _logger.LogWarning(ex, "Could not publish the SSO denial event ({Reason}) for provider {Provider} within {Budget}. The login was refused regardless.", reason, provider?.ReplaceLineEndings(string.Empty).Replace('[', '('), _budget);
        }
    }
}
