// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Security.Cryptography;
using System.Text;
using Jellyfin.Database.Implementations.Entities;
using Jellyfin.Plugin.SSO_Auth.Config;
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

    /// <summary>
    /// Records that the password now stored on an account is one this plugin minted (#1733), so a later
    /// reader can tell a seal nobody can open from a credential somebody holds.
    /// </summary>
    /// <remarks>
    /// WHAT IS STORED IS A FINGERPRINT AND NOT THE HASH. A flag saying only "this account was provisioned"
    /// would go on saying it after the owner set a real password of their own, and the guard that reads it
    /// would then refuse a user who does hold a way in - the exact cost #1733 declined to impose on
    /// everybody. Keeping a digest of the stored hash makes the record self-correcting: the moment anything
    /// else writes <c>User.Password</c>, the fingerprint stops matching and the account reads as having a
    /// door again, with no event to subscribe to and nothing to migrate.
    /// <para>
    /// A digest rather than the hash itself, because this map is part of the plugin configuration and a
    /// password hash is credential material that has exactly one home. The digest answers "is this the same
    /// stored value I wrote" and nothing else: it cannot be fed to a verifier and it grants nothing.
    /// </para>
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

    /// <summary>
    /// Drops the record an account holds, because the account is gone (#1733/#1649).
    /// </summary>
    /// <remarks>
    /// AN UNLINK NEVER REACHES THIS, and the omission is the rule rather than a gap: removing a link does
    /// not change what password the account holds, so a record dropped there would stop describing an
    /// account that is still sealed. The two callers are the account-deletion consumer, which acts on the
    /// host's own event, and the boot-time sweep, which reclaims records whose account no longer resolves -
    /// the case the event cannot reach, because an account deleted while the plugin was not loaded raises
    /// that event at nobody.
    /// </remarks>
    /// <param name="configuration">The live plugin configuration, inside a mutation.</param>
    /// <param name="userId">The account to forget.</param>
    /// <returns>True when a record was removed.</returns>
    internal static bool Forget(PluginConfiguration configuration, Guid userId)
    {
        ArgumentNullException.ThrowIfNull(configuration);

        return configuration.ProvisionedPasswords.Remove(userId);
    }

    /// <summary>
    /// Whether the only password this account holds is one this plugin minted (#1733) - a stored value
    /// nobody was ever shown, so the account has no password door however its provider id reads.
    /// </summary>
    /// <remarks>
    /// FAIL-CLOSED IS THE OTHER DIRECTION HERE, and it is worth stating because the word points the wrong
    /// way at first glance. This answers a question whose TRUE arm makes a guard refuse; the dangerous
    /// mistake is a false TRUE, which refuses a user who holds a real password. So an account this plugin
    /// has no record for answers FALSE, an account whose stored password no longer matches what was
    /// recorded answers FALSE, and an account with no stored password at all answers FALSE - the sweep
    /// exists precisely so that state does not persist, and an empty password is an open door rather than
    /// a sealed one.
    /// </remarks>
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
