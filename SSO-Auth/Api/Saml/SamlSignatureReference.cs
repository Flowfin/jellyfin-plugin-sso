// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Diagnostics.CodeAnalysis;
using System.Xml;

namespace Jellyfin.Plugin.SSO_Auth.Api.Saml;

/// <summary>
/// The one rule for what a signature's <c>Reference/@URI</c> may be on an inbound SAML document: a
/// same-document shorthand pointer, <c>#id</c>, whose fragment is a well-formed XML <c>NCName</c> - which is
/// exactly what SAML 2.0 requires, since the <c>ID</c> attributes it points at are <c>xsd:ID</c> and therefore
/// NCNames by schema. Shared by the response and the logout validators so the two can never drift on the one
/// question that decides WHAT a signature covers (#1003).
/// </summary>
/// <remarks>
/// The NCName constraint is deliberately enforced HERE rather than left to the platform. .NET's
/// <c>DefaultGetIdElement</c> applies its own NCName guard before resolving, but that guard is documented as
/// compatibility-switchable, and the resolution below it interpolates the fragment into an XPath predicate
/// (<c>//*[@Id="..."]</c>) without escaping it. On a host with that switch flipped, an attacker-chosen
/// fragment carrying a quote would be XPath injection inside reference resolution. Constraining the fragment
/// before it is ever handed over makes the rejection a property of this plugin instead of a property of the
/// host's compatibility configuration - the difference between owning the rule and renting it.
///
/// The divergence from the platform's own resolution is ONE-DIRECTIONAL, which is what makes this safe rather
/// than merely different. .NET's <c>Reference.CalculateHashValue</c> resolves through
/// <c>Utils.ExtractIdFromLocalUri</c>, which rewrites a fragment ONLY when it begins <c>xpointer(id(</c>
/// (matched case-insensitively, taking text to the first <c>)</c> and stripping either quote character). No
/// string that triggers that rewrite is an NCName, and no NCName triggers it - so there is no input for which
/// this rule resolves one element while the platform digests a different one. The two can disagree only by
/// this rule resolving NOTHING where the platform would resolve something, which is the fail-closed direction.
///
/// The accept set on a default host is UNCHANGED by this rule, which is the answer to the obvious objection:
/// non-conformant identity providers do exist - a digit-leading UUID as the <c>ID</c> is the classic case, and
/// is precisely why the leading-underscore convention exists across ADFS, Azure AD, Auth0, Keycloak and
/// Shibboleth. The schema argument alone would not answer that ticket, but the empirical one does:
/// <c>DefaultGetIdElement</c> ALREADY applies an NCName test before resolving (its own comment cites xml:id 1.0
/// §4), so a digit-leading or colon-bearing ID already resolved to null and was already rejected before this
/// rule existed. What changed is WHERE the rejection happens and that it no longer depends on the host's
/// compatibility configuration. Corroborated by measurement: removing the call below does not turn the
/// end-to-end tests red, which is only possible because the platform applies the same test underneath.
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
