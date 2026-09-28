// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System.Collections.ObjectModel;
using System.Diagnostics.CodeAnalysis;

namespace Jellyfin.Plugin.SSO_Auth.Config;

/// <summary>The portable snapshot of the account-link table, keyed by username because a rebuilt user database issues new ids (#1126).</summary>
/// <remarks>
/// A distinct artifact from the configuration export, because it carries identity data an administrator must ask for.
/// See <see href="https://github.com/Flowfin/jellyfin-plugin-sso/wiki/Server-Migration"/>.
/// </remarks>
public class LinkExportDocument
{
    private Collection<LinkExportEntry> _links = new();

    /// <summary>Gets or sets the document format version, a sequence of its own that the importer refuses when unknown.</summary>
    public int FormatVersion { get; set; }

    /// <summary>Gets or sets the exported links, one entry per canonical link whose account still exists.</summary>
    /// <remarks>
    /// The setter is load-bearing: System.Text.Json drops a property it cannot set, and a get-only collection here made the
    /// import restore nothing while reporting success (#1135). Null is coalesced so a posted null means no links.
    /// </remarks>
    [SuppressMessage("Usage", "CA2227:Collection properties should be read only", Justification = "JSON transport shape: the deserializer must be able to assign this property, and a read-only one is silently dropped by System.Text.Json.")]
    public Collection<LinkExportEntry> Links
    {
        get => _links;
        set => _links = value ?? new Collection<LinkExportEntry>();
    }
}

/// <summary>One canonical link as it survives a user-database rebuild: the provider, the canonical name, and the username it resolves to.</summary>
public class LinkExportEntry
{
    /// <summary>Gets or sets the protocol the provider speaks, because the two protocols keep separate provider namespaces.</summary>
    public string? Protocol { get; set; }

    /// <summary>Gets or sets the provider this link belongs to.</summary>
    public string? Provider { get; set; }

    /// <summary>Gets or sets the canonical name the link is keyed by: the provider's stable subject, or the username an older link fell back to.</summary>
    public string? CanonicalName { get; set; }

    /// <summary>Gets or sets the Jellyfin username the link resolves to, resolved at export time.</summary>
    public string? Username { get; set; }

    /// <summary>Gets or sets the issuer an OpenID link is bound to (#186); null for SAML and for links written before the binding existed.</summary>
    public string? Issuer { get; set; }
}
