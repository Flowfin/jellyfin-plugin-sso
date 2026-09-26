// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

namespace Jellyfin.Plugin.SSO_Auth.Api.Http;

/// <summary>
/// The answer of an OpenID provider save through <c>OID/Add</c> (#1872). A save is allowed to drop the stored
/// client secret - a blank secret field with a changed discovery endpoint or client id does not carry a
/// write-only secret to a re-identified provider - and until this the caller learned that from the next
/// login failing. The save answers with the fact instead, so the secret is asked for at the moment it went.
/// </summary>
public sealed class ProviderSaveResponse
{
    /// <summary>
    /// The sentence an API caller reads when the stored secret was dropped. One fixed English line rather
    /// than a catalogue key: this door has no page to render a key, and the configuration page has its own
    /// localised sentence for the same fact.
    /// </summary>
    internal const string SecretDroppedNotice =
        "The stored client secret was dropped: the discovery endpoint or the client id changed while the secret was blank, and a stored secret is never carried over to a re-identified provider. This provider signs nobody in until a client secret is supplied.";

    /// <summary>
    /// Gets or sets a value indicating whether this save dropped the stored client secret because the
    /// provider identity changed while the posted secret was blank.
    /// </summary>
    public bool SecretDropped { get; set; }

    /// <summary>Gets or sets the notice that goes with <see cref="SecretDropped"/>, or null when nothing was dropped.</summary>
    public string? Notice { get; set; }

    /// <summary>Builds the answer for a save that did or did not drop the stored secret.</summary>
    /// <param name="secretDropped">Whether the stored secret was dropped by this save.</param>
    /// <returns>The response body.</returns>
    internal static ProviderSaveResponse For(bool secretDropped)
        => new() { SecretDropped = secretDropped, Notice = secretDropped ? SecretDroppedNotice : null };
}
