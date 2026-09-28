// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Diagnostics.CodeAnalysis;
using System.Xml;

namespace Jellyfin.Plugin.SSO_Auth.Api.Saml;

/// <summary>The one rule for what a signature Reference URI may be on an inbound SAML document: a same-document shorthand pointer whose fragment is a well-formed XML NCName, shared by the response and logout validators so the two cannot drift (#1003).</summary>
/// <remarks>
/// The constraint is enforced here rather than left to the platform, whose own NCName guard is documented as
/// compatibility-switchable while the resolution below it interpolates the fragment into an XPath predicate
/// unescaped. The divergence from the platform is one-directional: no string that triggers its XPointer
/// rewrite is an NCName and no NCName triggers it, so the two can disagree only by this rule resolving
/// nothing where the platform would resolve something. The accept set on a default host is unchanged, which
/// is the answer to the non-conformant-provider objection, and removing the call does not redden the
/// end-to-end tests: <see href="https://github.com/Flowfin/jellyfin-plugin-sso/wiki/Security-Model#signature-wrapping-the-posture-and-the-families-it-covers"/>.
/// </remarks>
internal static class SamlSignatureReference
{
    /// <summary>
    /// Tries to read a reference URI as a same-document <c>#id</c> shorthand pointer with an NCName fragment.
    /// </summary>
    /// <param name="referenceUri">The raw <c>Reference/@URI</c> value.</param>
    /// <param name="id">The fragment after the <c>#</c> when the URI is a valid shorthand pointer.</param>
    /// <returns><see langword="true"/> when the URI is a same-document ID reference; otherwise <see langword="false"/>.</returns>
    internal static bool TryGetSameDocumentId(string? referenceUri, [NotNullWhen(true)] out string? id)
    {
        id = null;

        // A same-document ID reference only. An empty URI (the whole document, implicitly) and any external
        // or non-fragment URI are rejected: both name content the readers do not bind to. This also rejects
        // every XPointer spelling - "#xpointer(/)" and "#xpointer(id('x'))" are resolved by .NET's reference
        // resolver but are not the shorthand form SAML mandates, and neither survives the NCName test below.
        if (string.IsNullOrEmpty(referenceUri) || referenceUri[0] != '#')
        {
            return false;
        }

        var fragment = referenceUri.Substring(1);
        try
        {
            XmlConvert.VerifyNCName(fragment);
        }
        catch (Exception ex) when (ex is XmlException or ArgumentException)
        {
            // XmlException is the malformed-name case; ArgumentException is the EMPTY one, which a bare "#"
            // reference produces - VerifyNCName rejects it through ThrowIfNullOrEmpty rather than through the
            // name grammar, so catching only XmlException would let a "#"-only URI throw out of a predicate
            // whose whole contract is to answer true or false. (ArgumentNullException derives from it.)
            return false;
        }

        id = fragment;
        return true;
    }
}
