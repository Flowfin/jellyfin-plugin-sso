// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

namespace Jellyfin.Plugin.SSO_Auth.Api.Logout;

/// <summary>What a mint did, in the classes an HTTP answer has to tell apart (#1796), so the mint's policy stays in <see cref="LogoutTicketService"/> and the route decides only what to say about it.</summary>
/// <remarks><see cref="NoCaller"/> is the zero value on purpose, the opposite choice from <see cref="MintRefusal"/>: this enum answers what happened, so an out parameter nobody assigned has to read as a refusal rather than as an issued ticket.</remarks>
internal enum MintOutcome
{
    /// <summary>The caller resolved to no user. Permanent for this request: nothing about a retry supplies one.</summary>
    NoCaller,

    /// <summary>A ticket was minted and handed back.</summary>
    Issued,

    /// <summary>The caller carries no access token, so a ticket would be bound to a session it could not end. Permanent for this request.</summary>
    NoSession,

    /// <summary>The request named no provider, so a ticket would be spendable nowhere. Permanent for this request.</summary>
    NoProvider,

    /// <summary>A capacity bound refused the entry - this account's share or the whole store. The one class that is temporary, and the only one a retry can clear.</summary>
    AtCapacity,
}
