// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;

namespace Jellyfin.Plugin.SSO_Auth.Config;

/// <summary>
/// What a link import actually restored (#1520), answered to the caller rather than only written to the
/// audit line.
/// </summary>
/// <remarks>
/// The endpoint used to answer <c>204 No Content</c>, so a restore that rebound every link and a restore
/// that rebound none were the same bytes on the wire and the same sentence on the settings page. That is
/// how #1517 stood from <c>4.3.0-beta.43</c> onward: the payload was being dropped, and the only surface
/// that said so was a log line nobody reads during a migration. A count in the answer is what makes the
/// two outcomes different for the operator who is holding the file.
/// <para>
/// It is a JSON-only transport shape and is never persisted to the config XML, so it carries no
/// XML-serialization attributes, exactly as <see cref="LinkRosterDocument"/> does not. It reports counts
/// and provider names only: a canonical name is the one field identifying a real person at the identity
/// provider, and the refusal path already keeps it out of what leaves this endpoint.
/// </para>
/// </remarks>
public class LinkImportResultDocument
{
    /// <summary>
    /// Gets or sets how many links the document rebound. Zero is a real and reportable answer - an empty
    /// document, or one whose entries this instance could act on none of - and it is the value the fixed
    /// success sentence used to hide.
    /// </summary>
    public int Restored { get; set; }

    /// <summary>
    /// Gets the per-provider breakdown, ordered by protocol and then provider name. Empty when nothing was
    /// restored, which is the same fact as <see cref="Restored"/> being zero and is carried beside it so a
    /// caller that renders the breakdown does not have to special-case the total.
    /// </summary>
    public Collection<LinkImportProviderResult> Providers { get; } = new();

    /// <summary>
    /// Builds the answer from the counts the importer returned.
    /// </summary>
    /// <param name="counts">The per-provider counts <c>LinkImport.Apply</c> produced, already ordered.</param>
    /// <returns>The document to answer with.</returns>
    internal static LinkImportResultDocument Of(IReadOnlyList<LinkImportCount> counts)
    {
        ArgumentNullException.ThrowIfNull(counts);

        var document = new LinkImportResultDocument();
        foreach (var count in counts)
        {
            document.Restored += count.Links;
            document.Providers.Add(new LinkImportProviderResult
            {
                Protocol = count.Protocol,
                Provider = count.Provider,
                Links = count.Links,
            });
        }

        return document;
    }
}

/// <summary>
/// How many links one provider got back from an import.
/// </summary>
public class LinkImportProviderResult
{
    /// <summary>
    /// Gets or sets the protocol the provider speaks (<c>OpenID</c> or <c>SAML</c>). It is part of the
    /// identity because the two protocols keep separate provider namespaces, so a name alone does not say
    /// which map was written.
    /// </summary>
    public string Protocol { get; set; } = string.Empty;

    /// <summary>Gets or sets the provider the links were written on.</summary>
    public string Provider { get; set; } = string.Empty;

    /// <summary>Gets or sets how many links were written on that provider.</summary>
    public int Links { get; set; }
}
