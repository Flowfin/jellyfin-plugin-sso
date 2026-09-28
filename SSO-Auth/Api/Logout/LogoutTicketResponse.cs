// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System.Text.Json.Serialization;

namespace Jellyfin.Plugin.SSO_Auth.Api.Logout;

/// <summary>What a successful logout-ticket mint answers with (#1768): the ticket token and nothing else.</summary>
/// <remarks>
/// A named type so the wire shape is a thing a reader can find, and one field on purpose: the expiry in particular
/// is absent, because the only honest answer to whether a ticket is still good is to spend it. The wire name is
/// declared rather than inherited from the host's serializer policy, and declared twice because Newtonsoft is a
/// direct dependency that honours only its own attribute, for the reason <see cref="Jellyfin.Plugin.SSO_Auth.Api.Logout.LogoutTicket"/> carries two ignore attributes.
/// </remarks>
/// <param name="Ticket">The one-time token to present as the <c>ticket</c> query parameter of the logout route.</param>
internal sealed record LogoutTicketResponse(
    [property: JsonPropertyName("ticket")]
    [property: Newtonsoft.Json.JsonProperty("ticket")] string Ticket);
