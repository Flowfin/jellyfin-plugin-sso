// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;

namespace Jellyfin.Plugin.SSO_Auth.Config;

/// <summary>What a link import restored, answered to the caller rather than only written to the audit line (#1520).</summary>
/// <remarks>Counts and provider names only, so a canonical name never leaves this endpoint.</remarks>
public class LinkImportResultDocument
{
    /// <summary>Gets or sets how many entries the document rebound; zero is a real answer, and the count is per entry like the audit line's.</summary>
    public int Restored { get; set; }

    /// <summary>Gets the per-provider breakdown, ordered by protocol and then provider name.</summary>
    /// <remarks>Get-only is safe only because this document is written and never bound; System.Text.Json drops a get-only collection on the way in.</remarks>
    public Collection<LinkImportProviderResult> Providers { get; } = new();

    /// <summary>Builds the answer from the counts the importer returned.</summary>
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

/// <summary>How many links one provider got back from an import.</summary>
public class LinkImportProviderResult
{
    /// <summary>Gets or sets the protocol the provider speaks, because the two protocols keep separate provider namespaces.</summary>
    public string Protocol { get; set; } = string.Empty;

    /// <summary>Gets or sets the provider the links were written on.</summary>
    public string Provider { get; set; } = string.Empty;

    /// <summary>Gets or sets how many links were written on that provider.</summary>
    public int Links { get; set; }
}
