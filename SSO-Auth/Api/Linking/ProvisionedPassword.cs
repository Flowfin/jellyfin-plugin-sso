// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Security.Cryptography;
using System.Text;
using Jellyfin.Database.Implementations.Entities;
using Jellyfin.Plugin.SSO_Auth.Config;
using MediaBrowser.Model.Cryptography;

namespace Jellyfin.Plugin.SSO_Auth.Api.Linking;

/// <summary>The single place a stored password is invented for an account the plugin manages (#1440), because an account with no password accepts the empty one on the ordinary login form.</summary>
/// <remarks>The create arm of <see cref="CanonicalLinkService"/> and the boot-time sweep over accounts older versions left open write the same kind of password through here, so a second spelling of random enough cannot arise; the value is never displayed, stored elsewhere or recoverable: <see href="https://github.com/Flowfin/jellyfin-plugin-sso/wiki/Security-Model#password-less-sso-accounts-are-sealed-at-start-up"/>.</remarks>
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

    /// <summary>Records that the password now stored on an account is one this plugin minted (#1733), so a later reader can tell a seal nobody can open from a credential somebody holds.</summary>
    /// <remarks>
    /// What is stored is a digest of the stored hash rather than a flag, so the record corrects itself: the moment
    /// anything else writes <c>User.Password</c> the fingerprint stops matching and the account reads as having a
    /// door again. A digest rather than the hash, because this map lives in the plugin configuration and grants nothing.
    /// </remarks>
    /// <param name="configuration">The live plugin configuration, inside a mutation.</param>
    /// <param name="userId">The account whose stored password was just minted.</param>
    /// <param name="storedHash">The value written to <c>User.Password</c>.</param>
    internal static void Record(PluginConfiguration configuration, Guid userId, string storedHash)
    {
        ArgumentNullException.ThrowIfNull(configuration);

        if (string.IsNullOrEmpty(storedHash))
        {
            // Nothing was sealed, so there is nothing to record, and writing a fingerprint of the empty
            // string would mark an account that still accepts the empty password as one this plugin closed.
            return;
        }

        configuration.ProvisionedPasswords[userId] = Fingerprint(storedHash);
    }

    /// <summary>Drops the record an account holds, because the account is gone (#1733, #1649).</summary>
    /// <remarks>An unlink never reaches this, because removing a link does not change what password the account holds; the callers are the account-deletion consumer and the boot-time sweep, which reclaims records whose account no longer resolves.</remarks>
    /// <param name="configuration">The live plugin configuration, inside a mutation.</param>
    /// <param name="userId">The account to forget.</param>
    /// <returns>True when a record was removed.</returns>
    internal static bool Forget(PluginConfiguration configuration, Guid userId)
    {
        ArgumentNullException.ThrowIfNull(configuration);

        return configuration.ProvisionedPasswords.Remove(userId);
    }

    /// <summary>Whether the only password this account holds is one this plugin minted (#1733), so the account has no password door however its provider id reads.</summary>
    /// <remarks>A true answer makes a guard refuse, so the dangerous mistake is a false true: an account with no record, a stored password that no longer matches the record, or no stored password at all answers false.</remarks>
    /// <param name="configuration">The plugin configuration, inside a read.</param>
    /// <param name="user">The account being asked about.</param>
    /// <returns>True when the stored password is the one this plugin minted and nothing has replaced it.</returns>
    internal static bool IsTheOnlyPassword(PluginConfiguration configuration, User user)
    {
        ArgumentNullException.ThrowIfNull(configuration);
        ArgumentNullException.ThrowIfNull(user);

        if (string.IsNullOrEmpty(user.Password))
        {
            return false;
        }

        return configuration.ProvisionedPasswords.TryGetValue(user.Id, out var recorded)
            && !string.IsNullOrEmpty(recorded)
            && CryptographicOperations.FixedTimeEquals(
                Encoding.UTF8.GetBytes(recorded),
                Encoding.UTF8.GetBytes(Fingerprint(user.Password)));
    }

    // SHA-256 of the stored hash string, hex. Not a password hash and never used as one: both sides of
    // every comparison are values this plugin wrote, so there is no attacker-chosen input to slow down.
    private static string Fingerprint(string storedHash) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(storedHash)));
}
