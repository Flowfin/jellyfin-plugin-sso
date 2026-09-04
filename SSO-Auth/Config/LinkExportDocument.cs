// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System.Collections.ObjectModel;
using System.Diagnostics.CodeAnalysis;

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
    private Collection<LinkExportEntry> _links = new();

    /// <summary>
    /// Gets or sets the document format version. It is its own sequence, independent of
    /// <see cref="ConfigExport.FormatVersion"/>, because the two documents change shape for unrelated
    /// reasons; an importer refuses a version it does not recognise rather than half-applying it.
    /// </summary>
    public int FormatVersion { get; set; }

    /// <summary>
    /// Gets or sets the exported links, one entry per canonical link across every provider of both
    /// protocols. A link whose Jellyfin user id no longer resolves to an account is absent rather than
    /// exported with a blank username, so the document never carries an entry nothing could be restored to.
    /// <para>
    /// THE SETTER IS LOAD-BEARING AND REMOVING IT BREAKS THE RESTORE SILENTLY. System.Text.Json - which is
    /// what the host binds a posted body with - ignores a property it cannot set, and this one is posted:
    /// with a get-only collection here the import received an EMPTY link list, restored nothing, answered
    /// 204 and audited <c>0 link(s) rebound</c> at an administrator who had just been told the migration
    /// worked. <c>FormatVersion</c> binds either way, so the document was parsed and version-checked while
    /// only the payload was dropped. Found by walking <c>docs/SERVER-MIGRATION.md</c> against a scratch
    /// server rebuild (#1135), pinned by <c>SSO-Auth.Tests/Config/LinkExportDocumentJsonTests.cs</c>.
    /// </para>
    /// <para>
    /// The setter coalesces null rather than storing it, because a posted <c>"Links": null</c> must not
    /// reach the importer as a null reference. It leaves such a document meaning what a document omitting
    /// the member has always meant - no links to restore - instead of a 500. The creation-handling
    /// attribute that would keep the property read-only was rejected for the same reason: it cannot assign
    /// null and throws out of model binding, past the null check and the rate limiter both, and it makes
    /// repeated <c>Links</c> members APPEND where every JSON reader an operator inspects the file with
    /// takes the last one - a difference between what they read and what the server applies.
    /// </para>
    /// </summary>
    [SuppressMessage("Usage", "CA2227:Collection properties should be read only", Justification = "JSON transport shape: the deserializer must be able to assign this property, and a read-only one is silently dropped by System.Text.Json. See the remarks above.")]
    public Collection<LinkExportEntry> Links
    {
        get => _links;
        set => _links = value ?? new Collection<LinkExportEntry>();
    }
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
