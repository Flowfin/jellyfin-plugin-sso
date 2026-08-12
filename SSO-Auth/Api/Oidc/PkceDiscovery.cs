// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Diagnostics;
using System.Linq;
using System.Text.Json;

namespace Jellyfin.Plugin.SSO_Auth.Api.Oidc;

/// <summary>
/// Decides whether an OpenID provider's discovery document advertises PKCE with SHA-256 (<c>S256</c>).
/// RFC 9700 §2.1.1 requires a client to confirm the authorization server supports PKCE before relying
/// on it. The OidcClient library sends <c>code_challenge</c> (S256) unconditionally but never checks
/// the discovery document's <c>code_challenge_methods_supported</c>, so a server that ignores PKCE would
/// silently downgrade authorization-code-injection protection (#141). Pure: the caller fetches the raw
/// discovery JSON; this only interprets it, and fails closed (<c>false</c>) on anything unexpected.
/// </summary>
internal static class PkceDiscovery
{
    /// <summary>
    /// Returns whether the discovery document lists <c>S256</c> in <c>code_challenge_methods_supported</c>.
    /// </summary>
    /// <param name="discoveryJson">The raw OpenID discovery document JSON.</param>
    /// <returns>
    /// <c>true</c> only when <c>S256</c> is advertised; <c>false</c> on absence, an empty/other-only set,
    /// a non-array value, non-string elements, or malformed/blank JSON.
    /// </returns>
    internal static bool SupportsS256(string? discoveryJson)
    {
        using var document = DiscoveryJson.TryParse(discoveryJson);
        return SupportsS256(document?.RootElement);
    }

    /// <summary>
    /// The same decision taken on an already-parsed document, so the challenge reads both of its discovery
    /// facts out of one parse (#1170).
    /// </summary>
    /// <param name="discovery">The parsed discovery document's root, or <see langword="null"/> when it could not be parsed.</param>
    /// <returns>
    /// <c>true</c> only when <c>S256</c> is advertised; <c>false</c> on absence, an empty/other-only set,
    /// a non-array value, non-string elements, or a null root.
    /// </returns>
    internal static bool SupportsS256(JsonElement? discovery)
    {
        // The ValueKind test is not redundant with the null test: a caller can hold a JsonElement that is
        // non-null and not an object - default(JsonElement) is Undefined - and TryGetProperty THROWS on one
        // rather than answering false, which would turn a malformed document into a 500 on the challenge.
        var advertised = discovery is { ValueKind: JsonValueKind.Object } root
            && root.TryGetProperty("code_challenge_methods_supported", out var methods)
            && methods.ValueKind == JsonValueKind.Array
            && methods.EnumerateArray().Any(method =>
                method.ValueKind == JsonValueKind.String
                && string.Equals(method.GetString(), "S256", StringComparison.Ordinal));

        // Post-condition, compiled out of the shipped build (#1082): a document that did not parse advertises
        // nothing. This is the fail-closed half of RFC 9700 2.1.1 - the answer a caller acts on when the
        // discovery read failed must come from the absence of evidence, never from a default.
        Debug.Assert(discovery is not null || !advertised, "SupportsS256 reported S256 for a document that did not parse.");
        return advertised;
    }
}
