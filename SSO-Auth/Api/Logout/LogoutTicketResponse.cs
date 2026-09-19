// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System.Text.Json.Serialization;

namespace Jellyfin.Plugin.SSO_Auth.Api.Logout;

/// <summary>
/// What a successful logout-ticket mint answers with (#1768): the ticket token and nothing else.
/// </summary>
/// <remarks>
/// A named type rather than an anonymous object, so the wire shape is a thing a reader can find and a test
/// can name. It carries ONE field on purpose. The caller is the page that asked for it, it already knows the
/// provider it asked about and the route it is going to navigate to, and every further field here - the
/// expiry, the user, the built URL - would be either a value the client does not need or a value the client
/// would start trusting instead of the server. The expiry in particular is deliberately absent: a client
/// that reads one would schedule around it, and the only honest answer to "is this ticket still good" is to
/// spend it and see.
/// <para>
/// THE WIRE NAME IS DECLARED AND NOT INHERITED. Without the attribute the JSON key is whatever the host's
/// serializer naming policy happens to be - measured, the same record answers <c>{"Ticket":...}</c> under
/// the default options and <c>{"ticket":...}</c> under the web defaults - so an integrator reading the key
/// would be reading a property of the host rather than of this plugin, and a host that changed its policy
/// would break them silently. Declaring it makes the key this type's own, and
/// <c>TheMintedTicketIsAnswered_UnderOneDeclaredWireName</c> pins it by serializing rather than by
/// inspecting the object.
/// </para>
/// </remarks>
/// <param name="Ticket">The one-time token to present as the <c>ticket</c> query parameter of the logout route.</param>
internal sealed record LogoutTicketResponse([property: JsonPropertyName("ticket")] string Ticket);
