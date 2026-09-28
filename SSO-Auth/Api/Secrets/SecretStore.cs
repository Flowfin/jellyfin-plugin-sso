// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.IO;
using System.Security.Cryptography;

namespace Jellyfin.Plugin.SSO_Auth.Api.Secrets;

/// <summary>Owns the plugin's data-encryption key and turns config secrets into and back out of at-rest <see cref="SecretEnvelope"/> envelopes.</summary>
/// <remarks>
/// The key lives in its own owner-only file in the plugin data folder, created atomically and never rolled, so a
/// leaked config alone decrypts nothing. Three failures fail closed rather than orphaning every envelope: a
/// wrong-length key file is rejected, revealing with the key file missing throws rather than minting a new key, and
/// encrypting refuses a replacement key while the configuration already holds envelopes:
/// <see href="https://github.com/Flowfin/jellyfin-plugin-sso/wiki/Security-Model#secrets-encrypted-at-rest"/>.
/// </remarks>
internal sealed class SecretStore
{
    private readonly string _keyFilePath;
    private readonly System.Threading.Lock _lock = new();
    private byte[]? _cachedKey;

    /// <summary>
    /// Initializes a new instance of the <see cref="SecretStore"/> class.
    /// </summary>
    /// <param name="keyFilePath">Absolute path of the file that holds (or will hold) the DEK.</param>
    internal SecretStore(string keyFilePath)
    {
        _keyFilePath = keyFilePath;
    }

    /// <summary>
    /// Returns the data-encryption key, generating and persisting a fresh one on first use. Used only when
    /// encrypting a value (there is no key yet on a first run).
    /// </summary>
    /// <returns>The 32-byte data-encryption key.</returns>
    /// <exception cref="CryptographicException">The key file exists but is not the expected length.</exception>
    internal byte[] GetOrCreateKey() => GetOrCreateKeyForEncrypt(configHasEnvelopes: false);

    /// <summary>Encrypts a plaintext secret for storage; an empty or already-encrypted value is returned unchanged, so it is safe to apply to a whole config on every save.</summary>
    /// <param name="storedValue">The secret as currently held.</param>
    /// <param name="configHasEnvelopes">True when the configuration being persisted already holds an encrypted envelope, so a missing key file throws instead of minting a new key; callers protecting a lone value pass false.</param>
    /// <returns>The value in encrypted-at-rest form.</returns>
    /// <exception cref="CryptographicException"><paramref name="configHasEnvelopes"/> is true and the key file is missing, so a key existed and was lost.</exception>
    internal string? Protect(string? storedValue, bool configHasEnvelopes = false)
    {
        // Skip only a genuinely-encrypted value (idempotency); a plaintext that merely starts with the
        // envelope prefix is not a well-formed envelope and is still encrypted here rather than stored raw.
        if (string.IsNullOrEmpty(storedValue) || SecretEnvelope.IsWellFormedEnvelope(storedValue))
        {
            return storedValue;
        }

        return SecretEnvelope.Protect(GetOrCreateKeyForEncrypt(configHasEnvelopes), storedValue);
    }

    /// <summary>
    /// Recovers the plaintext for a stored secret: decrypts an envelope, or passes through a legacy
    /// plaintext (or empty) value unchanged. Revealing an envelope requires the key file to exist; if it is
    /// missing the call fails closed rather than generating a replacement key.
    /// </summary>
    /// <param name="storedValue">The secret as read from configuration.</param>
    /// <returns>The plaintext secret.</returns>
    /// <exception cref="CryptographicException">The key file is missing/corrupt, or the value did not decrypt.</exception>
    internal string? Reveal(string? storedValue)
    {
        if (string.IsNullOrEmpty(storedValue) || !SecretEnvelope.IsProtected(storedValue))
        {
            return storedValue;
        }

        return SecretEnvelope.Unprotect(GetKey(), storedValue);
    }

    // The key to encrypt a plaintext secret under. Mirrors the load-or-create of GetOrCreateKey, but when the
    // key file is missing it only mints a fresh key on a genuine first run (no envelopes exist yet to
    // orphan). If the configuration already carries envelopes the missing key was lost, not absent, so it
    // fails closed exactly as the reveal path does: minting here would re-encrypt this value under a new key
    // while the pre-existing envelopes stay unrecoverable, masking the loss.
    private byte[] GetOrCreateKeyForEncrypt(bool configHasEnvelopes)
    {
        lock (_lock)
        {
            if (_cachedKey != null)
            {
                return _cachedKey;
            }

            if (File.Exists(_keyFilePath))
            {
                return LoadKeyLocked();
            }

            if (configHasEnvelopes)
            {
                throw new CryptographicException(
                    $"The SSO secret key file '{_keyFilePath}' is missing while encrypted secrets are present. Restore it from a backup - do not delete it or let it be regenerated, or every encrypted secret becomes permanently unrecoverable.");
            }

            return CreateKeyLocked();
        }
    }

    // Reads the existing key without ever creating one. Fails closed when the file is missing: reaching here
    // means we were asked to decrypt an already-encrypted value, so a missing key was lost (not absent on a
    // first run), and regenerating it would orphan every secret.
    private byte[] GetKey()
    {
        lock (_lock)
        {
            if (_cachedKey != null)
            {
                return _cachedKey;
            }

            if (!File.Exists(_keyFilePath))
            {
                throw new CryptographicException(
                    $"The SSO secret key file '{_keyFilePath}' is missing while encrypted secrets are present. Restore it from a backup - do not delete it or let it be regenerated, or every encrypted secret becomes permanently unrecoverable.");
            }

            return LoadKeyLocked();
        }
    }

    private byte[] LoadKeyLocked()
    {
        var existing = File.ReadAllBytes(_keyFilePath);
        if (existing.Length != SecretEnvelope.KeySizeBytes)
        {
            throw new CryptographicException(
                $"The SSO secret key file '{_keyFilePath}' is corrupt (unexpected length). Restore it from a backup - do not delete it, or every encrypted secret becomes unrecoverable.");
        }

        _cachedKey = existing;
        return _cachedKey;
    }

    private byte[] CreateKeyLocked()
    {
        var key = RandomNumberGenerator.GetBytes(SecretEnvelope.KeySizeBytes);
        var directory = Path.GetDirectoryName(_keyFilePath);
        if (!string.IsNullOrEmpty(directory))
        {
            Directory.CreateDirectory(directory);
        }

        // Write to a temp file, then move it into place. The two-argument File.Move fails if the target
        // already exists, so a concurrent writer (another process/instance sharing the volume) that won the
        // race cannot be clobbered - we discard our key and adopt theirs instead. This also makes the write
        // atomic: a crash mid-write leaves the temp file, never a truncated key file. The move preserves the
        // temp file's mode, so the key file is owner-only from the instant it exists.
        var tempPath = _keyFilePath + "." + Guid.NewGuid().ToString("N") + ".tmp";
        WriteKeyOwnerOnly(tempPath, key);

        try
        {
            File.Move(tempPath, _keyFilePath);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            TryDelete(tempPath);
            return LoadKeyLocked();
        }

        _cachedKey = key;
        return _cachedKey;
    }

    private static void TryDelete(string path)
    {
        try
        {
            File.Delete(path);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            // Best effort.
        }
    }

    // Writes the key material to a brand-new file that is owner-only from the instant it exists. On Unix the
    // restrictive mode is supplied to open() at creation time (UnixCreateMode), so - unlike a write followed
    // by a chmod - there is no sub-millisecond window where the freshly-created key sits at the umask default
    // (potentially group/world-readable). umask can only clear bits, never add them, so a create mode of
    // UserRead|UserWrite is never widened. On Windows there is no portable owner-only chmod, so the file
    // inherits the (already access-controlled) Jellyfin data directory's NTFS ACLs, as before.
    private static void WriteKeyOwnerOnly(string path, byte[] key)
    {
        var options = new FileStreamOptions
        {
            Mode = FileMode.CreateNew,
            Access = FileAccess.Write,
        };

        if (!OperatingSystem.IsWindows())
        {
            options.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
        }

        using var stream = new FileStream(path, options);
        stream.Write(key, 0, key.Length);
    }
}
