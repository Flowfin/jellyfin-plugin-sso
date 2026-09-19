// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

namespace Jellyfin.Plugin.SSO_Auth.Api.Logout;

/// <summary>
/// Why a mint was refused, so the caller can say which bound it met rather than asserting the wrong one.
/// The <c>Quiet</c> members carry the same fact with the throttle already spent, so a caller logs at most
/// one line per interval per bound without having to own a second flag.
/// </summary>
internal enum MintRefusal
{
    /// <summary>Nothing was refused. Deliberately the zero value, so an unassigned out parameter reads as success only where one was assigned.</summary>
    None,

    /// <summary>This account holds its whole share of the store. One account is affected; the store may be nearly empty.</summary>
    AccountShare,

    /// <summary>As <see cref="AccountShare"/>, with the warning throttle already spent this interval.</summary>
    AccountShareQuiet,

    /// <summary>The store is full, or a token collided. Every account is affected, and this is the one an operator acts on.</summary>
    Store,

    /// <summary>As <see cref="Store"/>, with the warning throttle already spent this interval.</summary>
    StoreQuiet,
}
