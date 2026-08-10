// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System.Collections.ObjectModel;

namespace Jellyfin.Plugin.SSO_Auth.Config;

/// <summary>
/// The portable snapshot of the account-link table (#1126), keyed by USERNAME rather than by Jellyfin user
/// id. The links themselves are stored against a <c>Guid</c>, and a rebuilt user database issues new ones,
/// so a snapshot carrying the id would restore into a server where every id it names is gone. The username
/// is the only identifier that survives that rebuild, which is why it is the key here and why this document
/// exists separately from <see cref="ConfigExportDocument"/> rather than as a version bump on it.
/// </summary>
/// <remarks>
/// This is a deliberately distinct artifact, not a widening of the configuration export. The configuration
/// export drops <c>CanonicalLinks</c> under <c>[JsonIgnore]</c> and is documented as carrying no link map;
/// this document carries identity data - usernames paired with identity-provider subject identifiers - so
/// an administrator must ask for it, rather than receiving it as a side effect of exporting provider
/// settings. It is a JSON-only transport shape and is never persisted to the config XML, so it carries no
/// XML-serialization attributes.
/// </remarks>
public class LinkExportDocument
{
    /// <summary>
    /// Gets or sets the document format version. It is its own sequence, independent of
    /// <see cref="ConfigExport.FormatVersion"/>, because the two documents change shape for unrelated
    /// reasons; an importer refuses a version it does not recognise rather than half-applying it.
    /// </summary>
    public int FormatVersion { get; set; }

    /// <summary>
    /// Gets the exported links, one entry per canonical link across every provider of both protocols. A
    /// link whose Jellyfin user id no longer resolves to an account is absent rather than exported with a
    /// blank username, so the document never carries an entry nothing could be restored to.
    /// </summary>
    public Collection<LinkExportEntry> Links { get; } = new();
}

/// <summary>
/// One canonical link, as it survives a user-database rebuild: which provider issued the identity, the
/// canonical name that identity is known by, and the username of the Jellyfin account it resolves to.
/// </summary>
public class LinkExportEntry
{
    /// <summary>
    /// Gets or sets the protocol the provider speaks. The two protocols keep separate provider namespaces
    /// and separate link maps, so an entry that named only the provider would be ambiguous on a server
    /// where an OpenID and a SAML provider share a name.
    /// </summary>
    public string? Protocol { get; set; }

    /// <summary>Gets or sets the provider this link belongs to.</summary>
    public string? Provider { get; set; }

    /// <summary>
    /// Gets or sets the canonical name the link is keyed by: the identity provider's stable subject for
    /// this user, or the username it fell back to for a link made before subjects were required.
    /// </summary>
    public string? CanonicalName { get; set; }

    /// <summary>
    /// Gets or sets the Jellyfin username the link resolves to. This is the field that makes the document
    /// portable, and it is resolved at export time rather than stored.
    /// </summary>
    public string? Username { get; set; }

    /// <summary>
    /// Gets or sets the issuer this link is bound to (#186), for OpenID links that carry one. It is null
    /// for SAML links, which have no issuer binding, and for OpenID links written before the binding
    /// existed. Carrying it means the binding survives the round trip instead of being silently relaxed on
    /// restore.
    /// </summary>
    public string? Issuer { get; set; }
}
