// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Collections.Generic;
using System.Text;
using MediaBrowser.Model.Cryptography;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>An <see cref="ICryptoProvider"/> that keeps every plaintext it was asked to hash, for the tests that assert something about the password the provisioning path invents (#1440).</summary>
/// <remarks>
/// <see cref="FakeCryptoProvider"/> returns one constant hash for every input, so a test built on it cannot tell a random password from a hard-coded one. The hash
/// produced here embeds the plaintext bytes, so <c>User.Password</c> differs whenever the plaintext does. It hashes nothing: never use this shape outside the suite.
/// </remarks>
internal sealed class RecordingCryptoProvider : ICryptoProvider
{
    private readonly List<string> _hashed = new();

    /// <summary>Gets every plaintext handed to <see cref="CreatePasswordHash"/>, in call order.</summary>
    internal IReadOnlyList<string> Hashed => _hashed;

    /// <inheritdoc />
    public string DefaultHashMethod => "PBKDF2-SHA512";

    /// <inheritdoc />
    public PasswordHash CreatePasswordHash(ReadOnlySpan<char> password)
    {
        var plaintext = password.ToString();
        _hashed.Add(plaintext);
        return new PasswordHash(DefaultHashMethod, Encoding.UTF8.GetBytes(plaintext));
    }

    /// <inheritdoc />
    public bool Verify(PasswordHash hash, ReadOnlySpan<char> password) => true;

    /// <inheritdoc />
    public byte[] GenerateSalt() => Array.Empty<byte>();

    /// <inheritdoc />
    public byte[] GenerateSalt(int length) => new byte[length];
}
