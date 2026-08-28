// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Collections.Generic;
using System.Text;
using MediaBrowser.Model.Cryptography;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// An <see cref="ICryptoProvider"/> that keeps every plaintext it was asked to hash, for the tests that
/// have to assert something about the password the provisioning path invents rather than merely that a
/// hash was produced (#1440). <see cref="FakeCryptoProvider"/> returns one constant hash for every input,
/// so a test built on it cannot tell a random password from a hard-coded one - which is the exact
/// distinction the door this class exists to prove is made of.
/// </summary>
/// <remarks>
/// The produced hash embeds the plaintext bytes, so <c>User.Password</c> differs whenever the plaintext
/// does. That makes the assertions readable on the persisted field as well as on the recording. It is a
/// test double and hashes nothing: never use this shape anywhere but in the suite.
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
