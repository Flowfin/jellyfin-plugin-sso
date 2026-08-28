// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Security.Cryptography;
using MediaBrowser.Model.Cryptography;

namespace Jellyfin.Plugin.SSO_Auth.Api.Linking;

/// <summary>
/// The single place a stored password is invented for an account the plugin manages (#1440). Jellyfin
/// creates a user with no password, and an account with no password accepts the EMPTY one on the ordinary
/// login form - so an account this plugin provisions is reachable without the identity provider until
/// something writes one.
/// </summary>
/// <remarks>
/// <para>
/// Two callers write a password and they must write the same KIND of password: the create arm of
/// <see cref="CanonicalLinkService"/>, which shuts the door as an account comes into existence, and the
/// boot-time sweep that shuts it on accounts provisioned by a plugin version that did not (every release up
/// to and including v3.4.0.2). A second spelling of "random enough" is the defect this type exists to make
/// impossible; the value is never displayed, never stored anywhere else and never recoverable, because
/// nothing is meant to log in with it.
/// </para>
/// </remarks>
internal static class ProvisionedPassword
{
    // 64 bytes from the CSPRNG, base64-encoded, which is what the create arm has minted since the upstream
    // fix in 2022 - kept byte-for-byte so the sweep cannot seal an account with a weaker secret than a fresh
    // provisioning would give it.
    // https://jonathancrozier.com/blog/how-to-generate-a-cryptographically-secure-random-string-in-dot-net-with-c-sharp
    private const int EntropyBytes = 64;

    /// <summary>
    /// Mints one unguessable password and returns it already hashed, in the persisted string form
    /// <c>User.Password</c> takes.
    /// </summary>
    /// <param name="cryptoProvider">Jellyfin's crypto provider, so the hash is produced by the same code path a real password change uses.</param>
    /// <returns>The hashed password, ready to assign to <c>User.Password</c>.</returns>
    internal static string Mint(ICryptoProvider cryptoProvider)
    {
        ArgumentNullException.ThrowIfNull(cryptoProvider);

        return cryptoProvider.CreatePasswordHash(Convert.ToBase64String(RandomNumberGenerator.GetBytes(EntropyBytes))).ToString();
    }
}
