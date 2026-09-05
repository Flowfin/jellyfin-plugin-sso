// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Xml;
using System.Xml.Serialization;

namespace Jellyfin.Plugin.SSO_Auth.Config;

/// <summary>
/// Plugin Configuration.
/// </summary>
public class PluginConfiguration : MediaBrowser.Model.Plugins.BasePluginConfiguration
{
    // Resolved once: reflection over the type is a startup cost, not a per-write one, and a write happens
    // on the login path. See AdoptFrom for why the set is derived rather than listed.
    private static readonly System.Reflection.PropertyInfo[] AdoptableProperties = Array.FindAll(
        typeof(PluginConfiguration).GetProperties(System.Reflection.BindingFlags.Public | System.Reflection.BindingFlags.Instance),
        property => property.CanRead && property.CanWrite && property.GetIndexParameters().Length == 0);

    private List<Guid>? _ssoOnlyRepointedUserIds;
    private SerializableDictionary<string, LogoutSession>? _logoutSessions;

    /// <summary>
    /// Initializes a new instance of the <see cref="PluginConfiguration"/> class.
    /// </summary>
    public PluginConfiguration()
    {
        SamlConfigs = new SerializableDictionary<string, SamlConfig>();
        OidConfigs = new SerializableDictionary<string, OidConfig>();
        ProvisioningProfiles = new SerializableDictionary<string, ProvisioningPolicyTemplate>();
        RateLimitMaxAttempts = 30;
        RateLimitWindowSeconds = 60;
    }

    /// <summary>
    /// Gets or sets the SAML configurations available.
    /// </summary>
    [XmlElement("SamlConfigs")]
    public SerializableDictionary<string, SamlConfig> SamlConfigs { get; set; }

    /// <summary>
    /// Gets or sets the OpenID configurations available.
    /// </summary>
    [XmlElement("OidConfigs")]
    public SerializableDictionary<string, OidConfig> OidConfigs { get; set; }

    /// <summary>
    /// Gets or sets the named provisioning profiles a provider can point at (#1105). Each entry is a
    /// provisioning template (#1099/#1100) under a name, so several providers can share one policy and a
    /// deployment can keep more than one - the <c>guest</c> profile beside the default one. Empty on every
    /// installation that defines none, which is every installation built before this existed.
    /// <para>
    /// A provider gets its profile by naming it in <see cref="ProviderConfigBase.ProvisioningProfile"/>. A
    /// provider that names none keeps using its own inline
    /// <see cref="ProviderConfigBase.ProvisioningPolicyTemplate"/>, so a configuration written before this
    /// existed provisions byte-identically. Naming both is refused on save: one account-creation policy has
    /// one authoritative source, exactly as the dedicated permissions do.
    /// </para>
    /// </summary>
    [XmlElement("ProvisioningProfiles")]
    public SerializableDictionary<string, ProvisioningPolicyTemplate> ProvisioningProfiles { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether the anonymous SSO flow endpoints are rate-limited
    /// per client address (best-effort, in-process). Opt-in (default off). The limiter keys on the
    /// connection's remote address only. CAUTION: behind a reverse proxy, first configure
    /// Jellyfin's own "Known proxies" networking setting so the server resolves the real client
    /// from the forwarded headers - without it every client shares the proxy's address and one
    /// abuser throttles logins for everyone; in that case leave this off. Refs #128.
    /// </summary>
    public bool EnableRateLimit { get; set; }

    /// <summary>
    /// Gets or sets how many hits per window a client may make against the anonymous SSO endpoints
    /// before being throttled with 429. One login is several hits (challenge, callback,
    /// authentication), so keep this generous; the default is 30. A value below 1 disables the
    /// limiter (it never means "block everything").
    /// </summary>
    public int RateLimitMaxAttempts { get; set; }

    /// <summary>
    /// Gets or sets the rate-limit window length in seconds. The default is 60.
    /// </summary>
    public int RateLimitWindowSeconds { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether the plugin manages the "Sign in with …" buttons on the
    /// Jellyfin login page (#722), by splicing a marker-fenced block into the server's branding login
    /// disclaimer. Off by default (fail safe): a deployment that does not opt in never has its branding
    /// mutated. When on, the managed block lists one button per ENABLED provider that does not set
    /// <see cref="ProviderConfigBase.HideLoginButton"/>; turning it off removes only the managed region,
    /// preserving any surrounding admin disclaimer content. The button labels/names are HTML-encoded into the
    /// disclaimer (an anonymous, pre-auth page), so a hostile provider name or label renders inert.
    /// </summary>
    public bool ManageLoginPageButtons { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether Single Logout is on (#727). Off by default (fail safe): a
    /// deployment that does not opt in captures no per-session logout state and exposes no logout surface.
    /// When on, each successful login persists the state a logout needs (<see cref="LogoutSessions"/>) - for
    /// OpenID the <c>id_token</c> used as an <c>id_token_hint</c>, for both protocols the subject/session
    /// index a logout is matched on - so an RP-initiated OpenID logout or an inbound SAML <c>LogoutRequest</c>
    /// can terminate the linked Jellyfin session. It gates only the capture and the (later) logout endpoints;
    /// local Jellyfin logout is unaffected either way.
    /// </summary>
    public bool EnableSingleLogout { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether SSO-only login is on (#165): native password login is
    /// disabled per account by repointing each non-exempt user's <c>AuthenticationProviderId</c> away from
    /// Jellyfin's password provider, EXCEPT a designated break-glass admin whose password door is always
    /// kept. Default <c>false</c> so no upgrade silently loses its password door. This is a server-managed
    /// field: the config-page save re-injects the live value (see
    /// <see cref="ServerManagedFields.Preserve(PluginConfiguration, PluginConfiguration)"/>), so it can only
    /// be changed through the <c>RequiresElevation</c>-gated SSO-Only endpoints, which run the fail-closed
    /// last-admin guard (<see cref="SsoOnlyLoginGuard"/>) and the per-user enforcement sweep. Jellyfin has
    /// no global "disable password login" switch, so this is plugin-driven per-user enforcement, not a core
    /// setting the plugin toggles (SSO-ONLY-LOGIN-DESIGN.md §2/§5).
    /// </summary>
    public bool DisablePasswordLogin { get; set; }

    /// <summary>
    /// Gets or sets the username of the designated break-glass administrator - the one account SSO-only mode
    /// never repoints, so it always retains native password login (SSO-ONLY-LOGIN-DESIGN.md §3 option A).
    /// Its continued existence is what satisfies the activation guard, and unlike an admin's SSO link it
    /// does not depend on the identity provider being reachable, which is the entire point. Server-managed
    /// like <see cref="DisablePasswordLogin"/>: set only through the elevated, audited SSO-Only endpoints,
    /// and only ever pointed at an account that is ALREADY an administrator (it cannot grant admin - T-E1).
    /// Blank means no break-glass admin is designated, so the mode cannot be enabled.
    /// </summary>
    public string? BreakGlassAdminUsername { get; set; }

    /// <summary>
    /// Gets or sets the ids of the accounts SSO-only mode has repointed off the built-in password provider
    /// (#165). This is server-managed bookkeeping, NOT an admin setting: the enable sweep records each
    /// account it moves, the disable/off-switch and the boot-time reconciliation restore <em>only</em> these
    /// accounts, and the set is cleared once they are restored. Tracking is essential for correctness - the
    /// plugin's own created accounts permanently carry the SSO provider id, so an untracked "restore every
    /// SSO-provider account" sweep would wrongly hand them a password door. It persists in the config XML so
    /// the documented recovery (set <see cref="DisablePasswordLogin"/> to <c>false</c> and restart) can
    /// reconcile the user database back to the flag. Withheld from JSON (<c>[JsonIgnore]</c>) and re-injected
    /// on save like the other server-managed fields, so a config PUT can neither read nor set it.
    /// </summary>
    [XmlArray("SsoOnlyRepointedUserIds")]
    [XmlArrayItem("UserId")]
    [System.Text.Json.Serialization.JsonIgnore]
    public List<Guid> SsoOnlyRepointedUserIds
    {
        // Self-healing lazy init (mirrors CanonicalLinks): a config PUT deserializes this to null (it is
        // JSON-ignored), so a later `.Add` under the config lock must land in a stored list, not a discarded
        // throwaway. Every access is under ReadConfiguration/MutateConfiguration, so it cannot race.
        get => _ssoOnlyRepointedUserIds ??= new List<Guid>();
        set => _ssoOnlyRepointedUserIds = value;
    }

    /// <summary>
    /// Gets or sets the per-session Single Logout state captured at login (#727), keyed by an opaque session
    /// key. Server-managed RUNTIME state, NOT an admin setting: the login path writes it (only while
    /// <see cref="EnableSingleLogout"/> is on), the logout path reads and removes it, and it is bounded so it
    /// cannot grow without limit. It persists in the config XML so a session survives a restart with a usable
    /// <c>id_token_hint</c>. Withheld from JSON (<c>[JsonIgnore]</c>) and re-injected on save like the other
    /// server-managed fields, so a config PUT can neither read the stored id_tokens nor forge session state;
    /// each entry's <see cref="LogoutSession.IdToken"/> is additionally encrypted at rest.
    /// </summary>
    [XmlElement("LogoutSessions")]
    [System.Text.Json.Serialization.JsonIgnore]
    public SerializableDictionary<string, LogoutSession> LogoutSessions
    {
        // Self-healing lazy init (mirrors CanonicalLinks/SsoOnlyRepointedUserIds): a config PUT deserializes
        // this to null (it is JSON-ignored), so a later write under the config lock must land in a stored map.
        get => _logoutSessions ??= new SerializableDictionary<string, LogoutSession>();
        set => _logoutSessions = value;
    }

    /// <summary>
    /// Renders this configuration in the exact form the host persists it in, so one configuration can be
    /// compared against another (#1095). Every persisted field counts, secrets and server-managed maps
    /// included, which is what a JSON rendering cannot offer: that boundary withholds the secrets and drops
    /// the link maps by design, so two configurations differing only in a secret compare as equal there.
    /// It lives on this type rather than beside its caller because the XML stack is confined to the
    /// persistence model and the SAML module, and this is the persistence model.
    /// </summary>
    /// <returns>The persisted XML form of this configuration.</returns>
    internal string ToPersistedForm()
    {
        using var writer = new StringWriter(CultureInfo.InvariantCulture);
        new XmlSerializer(typeof(PluginConfiguration)).Serialize(writer, this);
        return writer.ToString();
    }

    /// <summary>
    /// Makes a detached copy of this configuration through the persisted form, so a caller can try a change
    /// on it and decide whether to keep it while the live object never holds a half-applied state (#1095).
    /// </summary>
    /// <returns>An independent configuration carrying the same persisted fields.</returns>
    internal PluginConfiguration DetachedCopy() => FromPersistedForm(ToPersistedForm());

    /// <summary>
    /// Reads back a configuration from what <see cref="ToPersistedForm"/> produced. Split out of
    /// <see cref="DetachedCopy"/> so a caller that needs only to be ABLE to reconstruct - a mutation
    /// holding an undo for a write that might fail (#1521) - pays one serialization and keeps the string,
    /// instead of paying the parse as well for a reconstruction it will almost never use.
    /// </summary>
    /// <param name="persisted">The persisted form to read back.</param>
    /// <returns>An independent configuration carrying the fields that form holds.</returns>
    internal static PluginConfiguration FromPersistedForm(string persisted)
    {
        // These bytes are this plugin's own output rather than anything that arrived from outside, and the
        // reader is still hardened the way every other XML read in this plugin is: no DTD, no resolver. A
        // parse that is safe only because of where its input came from is one refactor away from not being.
        var settings = new XmlReaderSettings
        {
            DtdProcessing = DtdProcessing.Prohibit,
            XmlResolver = null,
        };

        using var text = new StringReader(persisted);
        using var reader = XmlReader.Create(text, settings);
        return (PluginConfiguration)new XmlSerializer(typeof(PluginConfiguration)).Deserialize(reader)!;
    }

    /// <summary>
    /// Takes over every persisted field of <paramref name="source"/> in place, so this object carries that
    /// state without any holder of it seeing a different instance (#1521). This is the swap at the end of a
    /// mutation: the change is prepared on a <see cref="DetachedCopy"/>, written to disk, and adopted here
    /// only once the write returned, so a persist that throws leaves this object exactly as it was.
    /// </summary>
    /// <param name="source">The configuration whose state to take over. Its sub-objects are adopted by
    /// reference, which is safe because a detached copy is reachable from nowhere else.</param>
    internal void AdoptFrom(PluginConfiguration source)
    {
        ArgumentNullException.ThrowIfNull(source);
        if (ReferenceEquals(this, source))
        {
            return;
        }

        // The field set is DERIVED from the type rather than listed here, and it is the same set the XML
        // serializer persists: public instance properties with both a getter and a setter (this model
        // declares no [XmlIgnore], which AdoptFromCarriesEveryPersistedField proves by comparing the two
        // persisted forms). A property added tomorrow is carried without anybody remembering to add it.
        foreach (var property in AdoptableProperties)
        {
            property.SetValue(this, property.GetValue(source));
        }
    }
}

/// <summary>
/// Configuration shared by every SSO provider (OpenID and SAML). Both <see cref="SamlConfig"/> and
/// <see cref="OidConfig"/> inherit these members; the concrete types are what get XML-serialized
/// (SerializableDictionary serializes each value as its concrete type), so inherited members emit the
/// same as declared ones and no <c>[XmlInclude]</c>/polymorphism handling is needed (#204). XML
/// deserialization is by element name, so moving these up - which places them before the
/// provider-specific elements in newly written XML - does not stop existing configs from loading.
/// </summary>
// Model-binding contract for every value-type member here and on the derived SamlConfig/OidConfig
// (the bool flags and the int? PortOverride): the OID/SAML `Add` endpoints (SSOController.OidAdd /
// SamlAdd) and the config-page PUT bind the whole provider object [FromBody] under RequiresElevation
// and REPLACE it wholesale (configuration.OidConfigs[provider] = config), re-injecting only the
// server-managed fields via ServerManagedFields.Preserve. An omitted bool therefore deserializes to
// its default and that default is persisted BY DESIGN - the admin is replacing the object, not
// patching it. This is why the value-type properties stay non-nullable and un-annotated (SonarCloud
// S6964, #196): marking them [JsonRequired] would reject the intended partial post and break the
// write-only-secret / blank-means-keep save flows that deliberately omit fields, while bool? would
// invent an "unset" third state the replace contract does not have. Under-posting here is admin-only
// and crosses no privilege boundary (non-security), so the documented whole-object-replace contract
// is the disposition rather than a per-property annotation.
public abstract class ProviderConfigBase
{
    /// <summary>
    /// The resolution <see cref="CanonicalLinkLastLogins"/> is kept to: a successful login rewrites a stored
    /// instant only once it is this much older than now, so the write cost of the stamp is at most one
    /// configuration persist per link per hour rather than one per login. It lives here, beside the map, so
    /// the promise a reader of the value gets and the rule the writer applies are the same sentence.
    /// </summary>
    internal static readonly TimeSpan LastSsoLoginGranularity = TimeSpan.FromHours(1);

    private SerializableDictionary<string, Guid>? _canonicalLinks;
    private SerializableDictionary<string, DateTime>? _canonicalLinkDeadlines;
    private SerializableDictionary<string, DateTime>? _canonicalLinkLastLogins;

    /// <summary>
    /// Gets or sets the canonical external base URL for this provider, e.g.
    /// <c>https://jellyfin.example.com</c>. When set, the provider's derived external URLs (the OpenID
    /// redirect_uri, or the SAML base and assertion-consumer URL) are built from it instead of the request
    /// <c>Host</c> header (#139), so a spoofed or proxy-forwarded host cannot redirect the login elsewhere.
    /// It overrides the scheme and port overrides. Blank keeps the request-host behavior.
    /// </summary>
    public string BaseUrlOverride { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets a value indicating whether the provider is enabled.
    /// </summary>
    public bool Enabled { get; set; }

    /// <summary>
    /// Gets or sets the URL the identity provider should return the browser to after an RP-initiated logout
    /// (#727, SLO-2), sent as <c>post_logout_redirect_uri</c>. It is honoured only when it sits at or under
    /// this server's canonical base URL (an open-redirect defense enforced by <c>OidcLogout</c>); an off-base
    /// or malformed value is silently ignored (the logout still completes, without a redirect back). Blank
    /// means no post-logout redirect. No effect while <see cref="PluginConfiguration.EnableSingleLogout"/> is
    /// off.
    /// </summary>
    public string? PostLogoutRedirectUri { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether this provider accepts an inbound OpenID Connect back-channel
    /// <c>logout_token</c> (OIDC Back-Channel Logout 1.0, #962), so an IdP-side session termination revokes
    /// the matched Jellyfin sessions. Off by default (fail safe): while off, the anonymous back-channel
    /// endpoint rejects every request for this provider without parsing the token. Requires
    /// <see cref="PluginConfiguration.EnableSingleLogout"/> on (the same master switch that captures the
    /// <c>sid</c> a logout_token is matched on). Note the deployment caveat: back-channel logout needs the
    /// IdP to reach this server directly (server-to-server), which is often unavailable for a self-hosted
    /// server behind NAT - RP-initiated logout (#727) covers the user-clicks-logout case regardless.
    /// </summary>
    public bool EnableBackChannelLogout { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether an SSO login that is DENIED by the role allow-list disables
    /// the existing linked Jellyfin account (login-time deprovisioning, #831), so a user offboarded at the
    /// identity provider loses Jellyfin access immediately rather than keeping their session until a role
    /// change would otherwise apply. Off by default (opt-in). Fail-safe against mass lockout: an
    /// ADMINISTRATOR is NEVER disabled by this path (which also covers the SSO-only break-glass admin, itself
    /// an admin), so a misconfigured allow-list or an identity provider that drops group claims can strand at
    /// most the non-admin accounts - an admin always remains to recover. Acts only on an existing linked
    /// account; a first-time denied login has nothing to disable.
    /// </summary>
    public bool DisableAccountOnRoleDenied { get; set; }

    /// <summary>
    /// Gets or sets the name of the claim (OpenID) or assertion attribute (SAML) that carries an
    /// account-expiry instant (#1143). Blank - the default - reads no expiry at all, so no existing provider
    /// changes behaviour. The value is read as a JWT <c>NumericDate</c> or an ISO-8601 timestamp and
    /// normalised to UTC; a claim that is absent, or whose value is neither shape, resolves to no instant.
    /// For OpenID the name may be a dotted path whose first segment names the claim and whose further
    /// segments walk into that claim's JSON object, the same convention <c>RoleClaim</c> uses. Reading it
    /// makes no access decision on its own; what the instant does is the enforcement step's question
    /// (#1144).
    /// </summary>
    public string? AccountExpiryClaim { get; set; }

    /// <summary>
    /// Gets or sets the role-to-duration mappings that give a brand-new account a fixed access lifetime
    /// (#1146), the second of the two expiry sources: a login provisioning a new account while holding a
    /// mapped role gets a deadline of that moment plus the mapped duration. Null or empty - the default -
    /// maps nothing, so a provider carrying none provisions byte-identically to before.
    /// <para>
    /// It is the RELATIVE source and <see cref="AccountExpiryClaim"/> is the absolute one. Where a login
    /// carries both, the claim wins: the identity provider is the authority on a date it emitted. Where
    /// several mapped roles match, the SHORTEST duration wins, which is the fail-closed direction and
    /// matches the minimum-wins rule <see cref="ParentalRatingRoleMap"/> already states for a ceiling.
    /// </para>
    /// <para>
    /// Stamped ONCE, on the arm that creates the account, and anchored to that moment rather than re-read
    /// per login - so a later login of the same account leaves the recorded deadline exactly where it was.
    /// A sliding deadline would be indistinguishable from unlimited access for anyone who keeps logging in,
    /// which is the whole failure this direction of the feature can have and the absolute claim cannot.
    /// Losing the role later neither extends nor clears the deadline; removing access for a role a user no
    /// longer holds is the allow-list's and #831's job, not this one's.
    /// </para>
    /// </summary>
    [XmlArray("GuestAccessDurationRoleMappings")]
    [XmlArrayItem(typeof(GuestAccessDurationRoleMap), ElementName = "GuestAccessDurationRoleMappings")]
    public List<GuestAccessDurationRoleMap>? GuestAccessDurationRoleMappings { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether this provider is HIDDEN from the managed login-page buttons
    /// (#722), when <see cref="PluginConfiguration.ManageLoginPageButtons"/> is on. Off by default: an enabled
    /// provider gets a button. Set it to keep a provider usable via its direct start URL without advertising a
    /// button on the login page. No effect while managed buttons are off.
    /// </summary>
    public bool HideLoginButton { get; set; }

    /// <summary>
    /// Gets or sets the label for this provider's managed login-page button (#722). Blank uses the provider
    /// name. The value is HTML-encoded into the login disclaimer, so any text is safe. No effect while
    /// <see cref="PluginConfiguration.ManageLoginPageButtons"/> is off or <see cref="HideLoginButton"/> is on.
    /// </summary>
    public string? LoginButtonText { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether RBAC is enabled.
    /// </summary>
    public bool EnableAuthorization { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether an SSO login may adopt a pre-existing, unlinked
    /// Jellyfin account whose username matches the SSO name. Off by default (fail closed): a first
    /// login that matches an existing account is rejected rather than taking it over. Settable in the
    /// admin provider form as well as the config XML (#484, #488).
    /// </summary>
    public bool AllowExistingAccountLink { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether an unknown identity's first successful SSO login provisions
    /// its new Jellyfin account as disabled, pending administrator approval (#737). Off by default (current
    /// behavior): a new account is created enabled and a session is minted. When on, the new account is
    /// created with <c>IsDisabled = true</c> and no permissions, no session is minted, and the login is
    /// refused with an "awaiting administrator approval" message until an administrator enables the account
    /// in the Jellyfin dashboard. This never disables an existing or adopted account - only a brand-new one.
    /// Settable in the admin OpenID provider form as well as the config XML.
    /// </summary>
    public bool ProvisionNewUsersDisabled { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether a login whose identity-provider username differs from the
    /// linked Jellyfin account's name RENAMES that account to follow the provider (#1138). Off by default
    /// (opt-in): a provider-side rename leaves the Jellyfin name as it was, which is the behaviour every
    /// existing deployment has.
    /// <para>
    /// The subject stays the key. Resolution is keyed on the OpenID <c>sub</c> / SAML <c>NameID</c> (#155,
    /// #186) and this adds no name-keyed path: the name FOLLOWS the account the subject already resolved,
    /// and never selects one. Turning it on therefore cannot change which account a login reaches.
    /// </para>
    /// <para>
    /// Fail-safe in both directions. The new name passes the same sanitization a provisioned name does
    /// (<c>ProvisionedUsername</c>, #1137), a name already held by a DIFFERENT account is left alone rather
    /// than fought over, and a rename the host refuses is logged and swallowed - a display-name mismatch is
    /// cosmetic, and turning it into a failed login would be the more expensive failure by far.
    /// </para>
    /// </summary>
    public bool SyncUsernameFromProvider { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether all folders are allowed by default.
    /// </summary>
    public bool EnableAllFolders { get; set; }

    /// <summary>
    /// Gets or sets what folders should users have access to by default.
    /// </summary>
    public string[]? EnabledFolders { get; set; }

    /// <summary>
    /// Gets or sets the roles that are checked to determine whether the user is an administrator.
    /// </summary>
    public string[]? AdminRoles { get; set; }

    /// <summary>
    /// Gets or sets what roles are checked to determine whether the user is allowed to use Jellyfin.
    /// </summary>
    public string[]? Roles { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether RBAC is used to manage folder access.
    /// </summary>
    public bool EnableFolderRoles { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether RBAC is used to manage Live TV access.
    /// </summary>
    public bool EnableLiveTvRoles { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether Live TV is enabled by default.
    /// </summary>
    public bool EnableLiveTv { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether Live TV is allowed to be managed by default.
    /// </summary>
    public bool EnableLiveTvManagement { get; set; }

    /// <summary>
    /// Gets or sets the roles that are checked to determine whether the user is allowed to view Live TV.
    /// </summary>
    public string[]? LiveTvRoles { get; set; }

    /// <summary>
    /// Gets or sets the roles that are checked to determine whether the user is allowed to manage Live TV.
    /// </summary>
    public string[]? LiveTvManagementRoles { get; set; }

    /// <summary>
    /// Gets or sets which folders map to what roles in RBAC.
    /// </summary>
    [XmlArray("FolderRoleMappings")]
    [XmlArrayItem(typeof(FolderRoleMap), ElementName = "FolderRoleMappings")]
    public List<FolderRoleMap>? FolderRoleMapping { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether the generic role-to-permission mapping
    /// (<see cref="PermissionRoleMappings"/>) is applied at login (#164). Off by default (fail closed):
    /// a deployment that does not set it sees no change on upgrade, and the extra permission surface is
    /// only ever managed by SSO when an administrator opts in AND lists explicit mappings. Gated
    /// additionally by <see cref="EnableAuthorization"/> at the mint, exactly like the admin/folder/Live TV
    /// grants, so turning RBAC off leaves every permission untouched.
    /// </summary>
    public bool EnablePermissionRoles { get; set; }

    /// <summary>
    /// Gets or sets the generic role-to-permission mappings applied at login when
    /// <see cref="EnablePermissionRoles"/> is on (#164): each entry names a single Jellyfin
    /// <c>PermissionKind</c> and the roles that grant it. The mapping is authoritative and default-deny -
    /// a listed permission is granted only when the login carries a matching role and is otherwise
    /// explicitly revoked, so a missing or unmapped claim never silently grants a permission. Permissions
    /// with their own dedicated configuration (administrator, all-folders, Live TV access/management) are
    /// rejected here so each permission has exactly one authoritative source. A permission not listed at all
    /// is never touched by SSO - Jellyfin's own default governs it. Validated fail-closed on save (an
    /// unknown or dedicated permission name is rejected before it is persisted).
    /// </summary>
    [XmlArray("PermissionRoleMappings")]
    [XmlArrayItem(typeof(PermissionRoleMap), ElementName = "PermissionRoleMappings")]
    public List<PermissionRoleMap>? PermissionRoleMappings { get; set; }

    /// <summary>
    /// Gets or sets a static policy template written onto a BRAND-NEW SSO account at creation and never
    /// re-applied on any later login (#1099). Null - the default - provisions byte-identically to before,
    /// which is every provider that does not set one.
    /// <para>
    /// "Once, at creation" is the whole contract. Because it never runs again, an administrator's later
    /// per-user edit survives, which is what separates this from the role mappings above: those are
    /// authoritative and re-asserted per login precisely so a revoked role revokes its permission. A
    /// template that re-applied would silently undo hand edits on the next login, and an administrator
    /// would have no way to tell which of the two wrote the value they are looking at.
    /// </para>
    /// </summary>
    public ProvisioningPolicyTemplate? ProvisioningPolicyTemplate { get; set; }

    /// <summary>
    /// Gets or sets the name of the <see cref="PluginConfiguration.ProvisioningProfiles"/> entry written onto
    /// this provider's BRAND-NEW accounts (#1105). Blank - the default - leaves the provider on its own inline
    /// <see cref="ProvisioningPolicyTemplate"/>, so a configuration written before profiles existed provisions
    /// unchanged.
    /// <para>
    /// Setting both this and the inline template is refused on save, and so is naming a profile the
    /// configuration does not define: a provider whose policy cannot be resolved would otherwise be persisted
    /// and then quietly provision nothing. At creation the resolution is deliberately one-way with no
    /// fallback - a name that no longer resolves writes NO policy rather than reaching back to the inline
    /// template, so a profile deleted behind the validator's back can never hand a new account a permission
    /// set the administrator had replaced.
    /// </para>
    /// </summary>
    public string? ProvisioningProfile { get; set; }

    /// <summary>
    /// Gets or sets the ordered role-to-provisioning-profile rows this provider selects a new account's
    /// profile with (#1106). The FIRST row whose roles the login holds decides, so the order the
    /// administrator wrote is the precedence; a login matching no row falls to
    /// <see cref="ProvisioningProfile"/>, and a provider naming neither keeps its own inline
    /// <see cref="ProvisioningPolicyTemplate"/>. No rows is the whole of "off", which is why there is no
    /// separate switch beside it: an empty map already means the feature does nothing, and a second switch
    /// would be a second place for it to be half-enabled from. Null and an empty list are both "no rows" -
    /// a configuration serialized without this element deserializes to an empty list rather than to null, so
    /// the resolver answers the same to either spelling and neither is the privileged one.
    /// <para>
    /// A row naming a profile the configuration does not define is refused on save, exactly as
    /// <see cref="ProvisioningProfile"/> is. At creation the resolution stays one-way with no fallback: a
    /// name that no longer resolves writes NO policy rather than reaching back to the provider default. That
    /// matters more here than it does one level up, because a row exists to send one group somewhere
    /// NARROWER than the default - falling back would hand exactly those accounts the wider policy the
    /// administrator had moved them off, silently.
    /// </para>
    /// </summary>
    [XmlArray("ProvisioningProfileRoleMappings")]
    [XmlArrayItem(typeof(ProvisioningProfileRoleMap), ElementName = "ProvisioningProfileRoleMappings")]
    public List<ProvisioningProfileRoleMap>? ProvisioningProfileRoleMappings { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether the role-to-parental-rating mapping
    /// (<see cref="ParentalRatingRoleMappings"/>) is applied at login (#736). Off by default (fail closed):
    /// a deployment that does not set it sees no change on upgrade. Gated additionally by
    /// <see cref="EnableAuthorization"/> at the mint, exactly like the other role-derived grants, so turning
    /// RBAC off leaves the ceiling untouched.
    /// </summary>
    public bool EnableParentalRatingRoles { get; set; }

    /// <summary>
    /// Gets or sets the role-to-parental-rating-ceiling mappings applied at login when
    /// <see cref="EnableParentalRatingRoles"/> is on (#736): each entry names a maximum parental-rating
    /// score and the roles it applies to (e.g. a <c>kids</c> group → a content-rating ceiling). When a login
    /// matches several entries the MOST RESTRICTIVE (minimum) ceiling wins, never the loosest. A login that
    /// matches no entry leaves the account's existing ceiling untouched - an unmapped or malformed claim
    /// never raises the ceiling. A login that DOES match is authoritative, exactly like the admin/folder/Live
    /// TV grants: the matched (minimum) ceiling is written even if it is looser than a value an administrator
    /// set by hand, so keep the mappings in sync with the intended policy. Validated fail-closed on save (a
    /// negative score, or an entry with no roles, is rejected before it is persisted).
    /// </summary>
    [XmlArray("ParentalRatingRoleMappings")]
    [XmlArrayItem(typeof(ParentalRatingRoleMap), ElementName = "ParentalRatingRoleMappings")]
    public List<ParentalRatingRoleMap>? ParentalRatingRoleMappings { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether the role-to-SyncPlay-access mapping
    /// (<see cref="SyncPlayAccessRoleMappings"/>) is applied at login (#827). Off by default (fail closed):
    /// a deployment that does not set it sees no change on upgrade. Gated additionally by
    /// <see cref="EnableAuthorization"/> at the mint, exactly like the other role-derived grants, so turning
    /// RBAC off leaves the level untouched.
    /// </summary>
    public bool EnableSyncPlayAccessRoles { get; set; }

    /// <summary>
    /// Gets or sets the role-to-SyncPlay-access mappings applied at login when
    /// <see cref="EnableSyncPlayAccessRoles"/> is on (#827): each entry names a SyncPlay access level and the
    /// roles it applies to (e.g. a <c>hosts</c> group → <c>CreateAndJoinGroups</c>). SyncPlay is not a
    /// Jellyfin permission but a three-valued level on the account, so it is not expressible through
    /// <see cref="PermissionRoleMappings"/> however it is spelled. When a login matches several entries the
    /// MOST RESTRICTIVE level wins, never the loosest - and "most restrictive" is declared by the resolver
    /// rather than taken from the enum's numeric order, which runs the other way. A login that matches no
    /// entry leaves the account's existing level untouched. A login that DOES match is authoritative,
    /// exactly like the admin/folder/Live TV grants: the matched level is written even if it is wider than a
    /// value an administrator set by hand, so keep the mappings in sync with the intended policy. Validated
    /// fail-closed on save (an entry with no roles, or a level that is not a declared member of Jellyfin's
    /// SyncPlay access enum, is rejected before it is persisted).
    /// </summary>
    [XmlArray("SyncPlayAccessRoleMappings")]
    [XmlArrayItem(typeof(SyncPlayAccessRoleMap), ElementName = "SyncPlayAccessRoleMappings")]
    public List<SyncPlayAccessRoleMap>? SyncPlayAccessRoleMappings { get; set; }

    /// <summary>
    /// Gets or sets the authentication provider id written to the user's Jellyfin account
    /// (<c>User.AuthenticationProviderId</c>) after a successful SSO login. This is a Jellyfin-native
    /// user attribute; SSO logins themselves always resolve through the per-provider canonical-link maps,
    /// not this field. Blank leaves the account's existing provider id untouched.
    /// </summary>
    public string? DefaultProvider { get; set; }

    /// <summary>
    /// Gets or sets the redirect scheme override.
    /// </summary>
    public string SchemeOverride { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the redirect port override.
    /// </summary>
    public int? PortOverride { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether the last non-linking login used the newer redirect path
    /// spelling (the "/start/" form rather than the legacy short form). This is server-managed runtime
    /// state, not an admin-facing setting: every non-linking challenge overwrites it from the incoming
    /// request path so that a later linking flow - which cannot know which redirect path the identity
    /// provider has registered - reuses the same spelling. It is persisted in the config XML for that
    /// reason, not because it is user-configurable.
    /// </summary>
    public bool NewPath { get; set; }

    /// <summary>
    /// Gets or sets a mapping of canonical names from the provider to jellyfin user ids.
    /// </summary>
    // Server-managed (written by logins), not admin-edited: persisted in the config XML but withheld
    // from every JSON response (#157). This stops the account-link map leaking off the server, closes
    // the tear from serializing it while a login writes it, and blocks setting links via a config PUT.
    // Its preservation on save is handled server-side in ServerManagedFields.Preserve.
    [XmlElement("CanonicalLinks")]
    [System.Text.Json.Serialization.JsonIgnore]
    public SerializableDictionary<string, Guid> CanonicalLinks
    {
        // Self-healing lazy init: the backing map is created and stored on first access, so a direct
        // `CanonicalLinks[key] = id` persists into the stored map instead of a discarded throwaway.
        // Every access runs under the config lock (ReadConfiguration/MutateConfiguration), so the
        // assignment cannot race; an empty map serializes the same as the old throwaway did.
        get => _canonicalLinks ??= new SerializableDictionary<string, Guid>();
        set => _canonicalLinks = value;
    }

    /// <summary>
    /// Gets or sets, per canonical link, the account-expiry instant the last login carried for it (#1145),
    /// in UTC. Keyed by the same stable subject as <see cref="CanonicalLinks"/>. Written only while
    /// <see cref="AccountExpiryClaim"/> is configured and only for a link whose deadline is still in the
    /// future; removed with its link, so the map is bounded by the link map rather than growing on its own.
    /// <para>
    /// It exists because login-time enforcement (#1144) only fires when the expired user comes back. A guest
    /// who simply stops logging in keeps an enabled account, any long-lived token and - with
    /// <see cref="PluginConfiguration.DisablePasswordLogin"/> off - a password door, indefinitely. Persisting
    /// the instant is what lets the background sweep end access ON the deadline rather than at the next
    /// login attempt, and persisting it in the config XML rather than in memory is what makes that survive a
    /// restart.
    /// </para>
    /// </summary>
    // Server-managed exactly like CanonicalLinks: written by logins, never admin-edited, persisted in the
    // config XML but withheld from every JSON response ([JsonIgnore]) so a config PUT can neither read the
    // deadlines back nor forge one - forging a PAST instant would be a remote disable of any account whose
    // subject the poster can guess. Preserved on save by ServerManagedFields.Preserve. Self-healing lazy
    // init, so a direct index assignment persists into the stored map.
    [XmlElement("CanonicalLinkDeadlines")]
    [System.Text.Json.Serialization.JsonIgnore]
    public SerializableDictionary<string, DateTime> CanonicalLinkDeadlines
    {
        get => _canonicalLinkDeadlines ??= new SerializableDictionary<string, DateTime>();
        set => _canonicalLinkDeadlines = value;
    }

    /// <summary>
    /// Gets or sets, per canonical link, the instant of the last successful SSO login that resolved it
    /// (#1120), in UTC. Keyed by the same stable subject as <see cref="CanonicalLinks"/>, so the map's
    /// cardinality IS the link map's: a repeat login overwrites one value and never appends, and the entry is
    /// removed with the link it describes. That is what makes it a bounded per-link field rather than an
    /// event log, which is the property the roster's "last SSO login" column had to be built on.
    /// <para>
    /// It is deliberately coarse. A successful login only rewrites the stored instant once it is older than
    /// <see cref="LastSsoLoginGranularity"/>, because the ordinary repeat login of an established user pays
    /// no configuration persist at all today and a write-through stamp would put one on the login path - on
    /// the file that carries every provider secret envelope and every link map. The trade is stated where a
    /// reader of the value will meet it: the instant is accurate to the granularity, never fresher.
    /// </para>
    /// </summary>
    // Server-managed exactly like CanonicalLinks and CanonicalLinkDeadlines: written by logins, never
    // admin-edited, persisted in the config XML but withheld from every JSON response ([JsonIgnore]) so a
    // config PUT can neither read the login history of a guessed subject back out nor forge an entry.
    // Preserved on save by ServerManagedFields.Preserve. Self-healing lazy init, so a direct index
    // assignment persists into the stored map.
    [XmlElement("CanonicalLinkLastLogins")]
    [System.Text.Json.Serialization.JsonIgnore]
    public SerializableDictionary<string, DateTime> CanonicalLinkLastLogins
    {
        get => _canonicalLinkLastLogins ??= new SerializableDictionary<string, DateTime>();
        set => _canonicalLinkLastLogins = value;
    }
}

/// <summary>
/// The configuration required for a SAML flow.
/// </summary>
// Load-bearing, not copy-paste cruft: this names the element SerializableDictionary.WriteXml persists
// via new XmlSerializer(typeof(TValue)); removing it renames that element and every stored provider
// entry on disk stops deserializing.
[XmlRoot("PluginConfiguration")]
public class SamlConfig : ProviderConfigBase
{
    /// <summary>
    /// Gets or sets the SAML information endpoint.
    /// </summary>
    public string SamlEndpoint { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the identity provider's SAML Single-Logout (SLO) endpoint - a DISTINCT URL from
    /// <see cref="SamlEndpoint"/> (the SSO endpoint), where the browser is redirected with a signed
    /// SP-initiated <c>LogoutRequest</c> (#727, SLO-3c). Blank (the default) means no SP-initiated Single
    /// Logout: the logout route degrades to a fail-safe local-only logout. It must be an absolute https URL
    /// when set (validated at save by <see cref="ProviderConfigValidator.ValidateSamlSloEndpoint"/>), so the
    /// signed LogoutRequest - which names the subject NameID - never traverses plaintext http. No effect while
    /// <see cref="PluginConfiguration.EnableSingleLogout"/> is off.
    /// </summary>
    public string SamlSloEndpoint { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the SAML provider's client ID.
    /// </summary>
    public string SamlClientId { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the SAML public key.
    /// </summary>
    public string? SamlCertificate { get; set; }

    /// <summary>
    /// Gets or sets an OPTIONAL second identity-provider signing certificate accepted alongside
    /// <see cref="SamlCertificate"/> during an INBOUND (IdP-side) signing-key rotation (#491). A response
    /// is accepted when its signature verifies against EITHER this certificate or the primary, under the
    /// SAME algorithm allowlist (no SHA-1), signature-scope, and fail-closed checks; when blank, the trial
    /// narrows to the primary alone. Note the validity-window check added with this field applies to the
    /// primary too, so an already-EXPIRED primary certificate - which the pre-#491 path still accepted, as
    /// XML-DSig verification ignores certificate dates - is now rejected on upgrade unless a current
    /// certificate is configured (here or promoted into <see cref="SamlCertificate"/>). Unlike
    /// <see cref="SamlSigningKeyPfx"/> and
    /// <see cref="SamlRolloverSigningKeyPfx"/> - the SP's own PRIVATE signing keys - this is the identity
    /// provider's PUBLIC signing certificate, exactly like <see cref="SamlCertificate"/>: it is NOT a
    /// secret, so it carries no write-only/encrypted-at-rest handling and is stored and returned in the
    /// clear. An expired certificate is rejected, so an administrator adds the identity provider's new
    /// certificate here before the cutover and promotes it into <see cref="SamlCertificate"/> (clearing
    /// this field) once the provider has fully rotated - with no login downtime across the overlap window.
    /// </summary>
    public string? SamlSecondaryCertificate { get; set; }

    /// <summary>
    /// Gets or sets the audience (SP entity id) that a SAML response must be addressed to. When
    /// unset, the SamlClientId is used. Ignored when <see cref="DoNotValidateAudience"/> is set.
    /// </summary>
    public string? SamlAudience { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether to skip validating the assertion's AudienceRestriction.
    /// Off by default: responses must be addressed to this service provider (fail closed). Only enable
    /// for a provider that cannot emit a matching AudienceRestriction.
    /// </summary>
    public bool DoNotValidateAudience { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether to bind the assertion to this service provider's
    /// assertion-consumer URL by validating the bearer SubjectConfirmationData Recipient (and the
    /// Response Destination when present) against it. Opt-in (default off): enable it once the
    /// identity provider is confirmed to emit a Recipient matching the configured ACS URL. Refs #156.
    /// </summary>
    public bool ValidateRecipient { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether to accept only solicited responses, by correlating the
    /// assertion's InResponseTo against an AuthnRequest this server issued. Opt-in (default off):
    /// enabling it rejects IdP-initiated (unsolicited) SSO, which carries no InResponseTo. Refs #156.
    /// </summary>
    public bool ValidateInResponseTo { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether the outgoing AuthnRequest is signed with this service
    /// provider's signing key, for identity providers that require signed requests (#167). Opt-in
    /// (default off): with it off the request is sent exactly as before (unsigned), so existing
    /// deployments are unaffected. When on, a valid <see cref="SamlSigningKeyPfx"/> must be configured -
    /// the challenge fails closed (rather than silently sending an unsigned request) if the key is
    /// missing or unloadable.
    /// </summary>
    public bool SignAuthnRequests { get; set; }

    /// <summary>
    /// Gets or sets the service-provider signing key used when <see cref="SignAuthnRequests"/> is on,
    /// as a Base64-encoded, unencrypted PKCS#12 (PFX) blob carrying the certificate and its RSA private
    /// key (#167). Supply the keypair whose public certificate the identity provider is configured to
    /// trust. Treated as a secret: write-only across the JSON boundary (deserialized from a save so it
    /// can be set and rotated, but serialized back as null so the private key never reaches the admin
    /// browser or a config export), and preserved on a save that leaves it blank. It is still persisted
    /// to the config XML.
    /// </summary>
    [System.Text.Json.Serialization.JsonConverter(typeof(WriteOnlySecretConverter))]
    public string? SamlSigningKeyPfx { get; set; }

    /// <summary>
    /// Gets or sets an OPTIONAL second service-provider signing key for a zero-downtime rollover of the
    /// SP's own signing certificate (#491, capability 1), as a Base64-encoded, unencrypted PKCS#12 (PFX)
    /// blob in the same shape as <see cref="SamlSigningKeyPfx"/>. It is PUBLISH-ONLY: outgoing
    /// AuthnRequests are always signed with the PRIMARY <see cref="SamlSigningKeyPfx"/>, and this key is
    /// never used to sign. Its purpose is the metadata overlap window - when it is set and
    /// <see cref="SignAuthnRequests"/> is on, the SP metadata advertises BOTH public certificates as two
    /// <c>KeyDescriptor use="signing"</c> entries, so the identity provider accepts the primary's
    /// signature while the administrator stages the swap (publish both, then promote the rollover key
    /// into the primary field, then clear this one). Blank means no overlap: byte-for-byte the pre-#491
    /// single-key, single-KeyDescriptor behavior. It carries the same private key, so it is treated as a
    /// secret exactly like the primary: write-only across the JSON boundary, encrypted at rest (#158),
    /// and preserved on a save that leaves it blank.
    /// </summary>
    [System.Text.Json.Serialization.JsonConverter(typeof(WriteOnlySecretConverter))]
    public string? SamlRolloverSigningKeyPfx { get; set; }
}

/// <summary>
/// The configuration required for a OpenID flow.
/// </summary>
// Load-bearing, not copy-paste cruft: this names the element SerializableDictionary.WriteXml persists
// via new XmlSerializer(typeof(TValue)); removing it renames that element and every stored provider
// entry on disk stops deserializing.
[XmlRoot("PluginConfiguration")]
public class OidConfig : ProviderConfigBase
{
    private SerializableDictionary<string, string>? _canonicalLinkIssuers;

    /// <summary>
    /// Gets or sets the OpenID well-known information endpoint.
    /// </summary>
    public string? OidEndpoint { get; set; }

    /// <summary>
    /// Gets or sets, per canonical link, the discovered issuer the link was minted under (#186). Keyed
    /// by the same stable subject (<c>sub</c>) as <see cref="ProviderConfigBase.CanonicalLinks"/>, the
    /// value is the id_token issuer that asserted that subject when the link was created. At login the
    /// resolved link's stored issuer is compared to the current login's issuer and a mismatch refuses the
    /// login (fail closed), so an admin repointing this provider entry at a DIFFERENT identity provider
    /// (same discovery URL, new issuer) can no longer silently map a new-IdP user whose <c>sub</c>
    /// collides with an old link onto the old user's account. A link that carries no stored issuer (one
    /// minted before this store existed) is stamped with the current issuer on its next successful login
    /// (trust-on-first-use), so existing links keep working while the provider is unchanged and gain the
    /// binding transparently - no userbase lockout on upgrade. OpenID only; SAML is out of scope.
    /// </summary>
    // Server-managed exactly like CanonicalLinks: persisted in the config XML but withheld from every JSON
    // response ([JsonIgnore]) so it cannot be read back or set via a config PUT, self-healing lazy init so
    // a direct index assignment persists, and preserved on save by ServerManagedFields.Preserve (which
    // also CLEARS it, alongside the links, when OidEndpoint changes - the repoint belt, #186).
    [XmlElement("CanonicalLinkIssuers")]
    [System.Text.Json.Serialization.JsonIgnore]
    public SerializableDictionary<string, string> CanonicalLinkIssuers
    {
        get => _canonicalLinkIssuers ??= new SerializableDictionary<string, string>();
        set => _canonicalLinkIssuers = value;
    }

    /// <summary>
    /// Gets or sets OpenID client ID.
    /// </summary>
    public string OidClientId { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets OpenID shared secret.
    /// </summary>
    // Write-only across the JSON boundary (#189): still deserialized from an incoming save (so it
    // can be set and rotated), but serialized back out as null, so the plaintext client secret
    // never reaches the admin browser (HAR, proxy log, shared screen) on a config-page load and
    // cannot be read back via a config GET. It is still persisted to the config XML. On save, a
    // blank incoming value re-injects the live secret (see ServerManagedFields.Preserve),
    // so leaving the field blank keeps the stored secret; a new value replaces it. A plain
    // [JsonIgnore] is wrong here - it is bidirectional and would also drop the value on save.
    [System.Text.Json.Serialization.JsonConverter(typeof(WriteOnlySecretConverter))]
    public string? OidSecret { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether adopting a same-named pre-existing account additionally
    /// requires the login to carry <c>email_verified == true</c> (#218). Only meaningful when
    /// <see cref="ProviderConfigBase.AllowExistingAccountLink"/> is on. Off by default (fail closed for
    /// availability, not for the takeover threat): name-based adoption of an administrator account is
    /// always refused regardless of this flag, so the headline takeover is closed without it; this flag
    /// hardens the residual non-admin, name-based adoption. Enabling it needs the <c>email</c> scope so
    /// the provider actually returns <c>email_verified</c>; an absent or false claim then refuses
    /// adoption. Settable in the admin provider form as well as the config XML (#484, #488).
    /// </summary>
    public bool RequireVerifiedEmailForAdoption { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether every OpenID login for this provider must carry
    /// <c>email_verified == true</c> (#166). Off by default (fail closed for availability, not the threat):
    /// a deployment that does not set it - or an identity provider that omits the claim - is unaffected, so
    /// the whole userbase sees no change on upgrade. When on, a login whose <c>email_verified</c> is not
    /// exactly <c>true</c> (absent, false, or unparseable) is refused, so an identity provider that permits
    /// unverified emails cannot be used to sign in. Distinct from <see cref="RequireVerifiedEmailForAdoption"/>,
    /// which only gates same-name account adoption; this gates the login itself, before any account is
    /// resolved. Enabling it needs the <c>email</c> scope so the provider returns <c>email_verified</c>.
    /// Settable in the admin provider form as well as the config XML (#524, #525).
    /// </summary>
    public bool RequireVerifiedEmailForLogin { get; set; }

    /// <summary>
    /// Gets or sets the space-separated <c>acr_values</c> sent on the authorization request (#757, OIDC
    /// Core §3.1.2.1) - the requested authentication-context class references, most-preferred first (e.g. an
    /// MFA reference such as <c>urn:...:mfa</c>, or a provider's <c>silver</c>/<c>gold</c> level). Empty by
    /// default: the parameter is then omitted and the request is byte-identical to before. Doubles as the
    /// allow-list <see cref="RequireAcr"/> checks the returned <c>acr</c> claim against. Settable in the
    /// admin provider form as well as the config XML.
    /// </summary>
    public string? AcrValues { get; set; }

    /// <summary>
    /// Gets or sets the OIDC <c>prompt</c> parameter sent on the authorization request (#757, OIDC Core
    /// §3.1.2.1) - e.g. <c>login</c> to force re-authentication, or <c>consent</c>. Empty by default: the
    /// parameter is then omitted. Settable in the admin provider form as well as the config XML.
    /// </summary>
    public string? Prompt { get; set; }

    /// <summary>
    /// Gets or sets the OIDC <c>max_age</c> parameter (seconds) sent on the authorization request (#757,
    /// OIDC Core §3.1.2.1) - the maximum allowable time since the user's last active authentication;
    /// <c>0</c> forces re-authentication. Null by default: the parameter is then omitted. A negative value
    /// is treated as unset. Settable in the admin provider form as well as the config XML.
    /// </summary>
    public int? MaxAge { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether every OpenID login for this provider must return an <c>acr</c>
    /// claim within <see cref="AcrValues"/> (#757) - a fail-closed step-up / forced-MFA enforcement. Off by
    /// default (for availability): a deployment that does not set it is unaffected. When on, a login whose
    /// signature-verified id_token carries no <c>acr</c>, or an <c>acr</c> outside the configured list, is
    /// refused. Requires <see cref="AcrValues"/> to be set - the save is rejected otherwise, so a mis-set
    /// cannot silently lock out a userbase or silently no-op. The break-glass password admin is unaffected.
    /// Settable in the admin provider form as well as the config XML.
    /// </summary>
    public bool RequireAcr { get; set; }

    /// <summary>
    /// Gets or sets the claim to check roles against. Separated by "."s.
    /// </summary>
    public string? RoleClaim { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether the node <see cref="RoleClaim"/> resolves to is a JSON
    /// <b>object whose property names are the role names</b>, rather than a JSON array of role strings
    /// (#934). Zitadel emits exactly that shape - <c>{"jellyfin-access": {"&lt;orgId&gt;": "&lt;domain&gt;"}}</c>
    /// under <c>urn:zitadel:iam:org:project:roles</c> - so without this its roles are unreadable and its
    /// role gate can never be turned on. Off by default, so no existing provider changes behaviour.
    /// Only the property NAMES are read, never the values and never nested objects; any other shape
    /// (array, scalar, malformed JSON) still fails closed to no roles. Settable in the admin provider
    /// form as well as the config XML.
    /// </summary>
    public bool RoleClaimIsObjectMap { get; set; }

    /// <summary>
    /// Gets or Sets additional Scopes to request access to in the authorization request.
    /// </summary>
    public string?[]? OidScopes { get; set; }

    /// <summary>
    /// Gets or sets the default username claim when creating new accounts.
    /// </summary>
    public string? DefaultUsernameClaim { get; set; }

    /// <summary>
    /// Gets or sets the URL format of the new user avatar.
    /// </summary>
    public string? AvatarUrlFormat { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether the zero-config fallback to the standard OIDC
    /// <c>picture</c> claim is disabled (#723). Off by default (the fallback is on), so a
    /// standards-compliant IdP yields an avatar with no <see cref="AvatarUrlFormat"/> template. Set it
    /// to opt an admin out of the IdP-driven avatar fetch entirely - with no template and this set, no
    /// avatar candidate is produced and nothing is fetched. A configured template is unaffected either
    /// way. The negative name keeps the safe/parity default at <see langword="false"/>, matching the
    /// other <c>Disable…</c>/<c>DoNot…</c> toggles and surviving deserialization of configs saved before
    /// this field existed.
    /// </summary>
    public bool DisableAvatarFromPictureClaim { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether HTTPS in the discovery endpoint is required.
    /// </summary>
    public bool DisableHttps { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether pushed authorization is required.
    /// </summary>
    public bool DisablePushedAuthorization { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether the OpenID endpoints are validated.
    /// </summary>
    public bool DoNotValidateEndpoints { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether this provider's backchannel (discovery, JWKS, token,
    /// userinfo, back-channel logout) may connect to a private network address. Off by default, so the
    /// outbound SSRF/DNS-rebind guard refuses every non-public address as before; a config saved before
    /// this field existed deserializes to <see langword="false"/> and keeps the full guard. Set it for an
    /// identity provider that deliberately lives on the administrator's own network - the standard
    /// self-hosted shape of an IdP on an RFC 1918 address behind a reverse proxy (#1058). Enabling it
    /// permits only RFC 1918, carrier-grade NAT and IPv6 unique-local, and only for this provider;
    /// loopback, link-local and the cloud-metadata ranges stay blocked regardless, and every other
    /// provider - plus the avatar fetch and the SAML metadata importer - keeps the full guard.
    /// </summary>
    public bool AllowPrivateNetworkAddresses { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether the OpenID issuer name is validated.
    /// </summary>
    public bool DoNotValidateIssuerName { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether the RFC 9207 authorization-response <c>iss</c> parameter
    /// is validated against the id_token issuer (an OpenID Connect mix-up defense). Off by default;
    /// enabling it disables the check for a provider whose response <c>iss</c> legitimately differs.
    /// </summary>
    public bool DoNotValidateResponseIssuer { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether the UserInfo endpoint is used to get profile data.
    /// </summary>
    public bool DoNotLoadProfile { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether the authorization server must advertise PKCE with S256
    /// (in the discovery document's <c>code_challenge_methods_supported</c>) before a login proceeds.
    /// When true, a login is refused if the server does not advertise S256 - fail closed, RFC 9700
    /// §2.1.1. When false (the default), an unsupported server only logs an <c>[SSO Audit]</c> warning
    /// and the login proceeds (PKCE is still sent, but the server may ignore it).
    /// </summary>
    public bool RequirePkce { get; set; }
}

/// <summary>
/// Maps a single provider role to the library folders granted to users who hold that role (RBAC folder access).
/// </summary>
public class FolderRoleMap
{
    /// <summary>
    /// Gets or sets the role of the mapping.
    /// </summary>
    public string? Role { get; set; }

    /// <summary>
    /// Gets or sets the folders that are allowed from the given role.
    /// </summary>
    public List<string>? Folders { get; set; }
}

/// <summary>
/// A static policy written onto a brand-new SSO account at creation and never re-applied (#1099). Every
/// field is opt-in: an unset one leaves Jellyfin's own new-user default alone, so a provider that carries a
/// template still only overrides what it names. Validated fail-closed on save.
/// </summary>
public class ProvisioningPolicyTemplate
{
    /// <summary>
    /// Gets or sets the boolean Jellyfin permissions written onto a brand-new account, each as the exact
    /// <c>PermissionKind</c> enum name with the value to write. A permission that is not listed is never
    /// touched, so Jellyfin's own new-user default governs it - that is what makes every field of this
    /// template opt-in rather than a policy the plugin imposes wholesale.
    /// </summary>
    /// <remarks>
    /// The same vocabulary and the same refusals as <see cref="PermissionRoleMap.Permission"/>: an unknown
    /// name is rejected on save, and so are the permissions with their own dedicated configuration
    /// (administrator, all-folders, Live TV) and <c>IsDisabled</c>. The dedicated four keep one authoritative
    /// source each. <c>IsDisabled</c> is refused for the stronger reason (#165, Finding H1): a template that
    /// could write it would make every account a provider creates arrive disabled, or - read the other way -
    /// hand a second, unaudited route to a permission the plugin deliberately writes from exactly three
    /// places. The pending-approval hold that legitimately creates an inert account is
    /// <see cref="ProviderConfigBase.ProvisionNewUsersDisabled"/>, which is audited.
    /// </remarks>
    [XmlArray("Permissions")]
    [XmlArrayItem(typeof(ProvisionedPermissionEntry), ElementName = "Permissions")]
    public List<ProvisionedPermissionEntry>? Permissions { get; set; }

    /// <summary>
    /// Gets or sets the remote-client bitrate ceiling in bits per second written onto a brand-new account.
    /// Null leaves Jellyfin's own default alone. Zero is a meaningful value (Jellyfin reads it as no limit),
    /// so it is distinct from unset; a negative value is rejected on save.
    /// </summary>
    public int? RemoteClientBitrateLimit { get; set; }

    /// <summary>
    /// Gets or sets the maximum number of simultaneous sessions written onto a brand-new account. Null
    /// leaves Jellyfin's own default alone. Zero is a meaningful value (Jellyfin reads it as unlimited), so
    /// it is distinct from unset; a negative value is rejected on save.
    /// </summary>
    public int? MaxActiveSessions { get; set; }

    /// <summary>
    /// Gets or sets the preferred audio language written onto a brand-new account (#1100), as the language
    /// code Jellyfin itself stores (for example <c>eng</c>). Null leaves Jellyfin's own default alone.
    /// </summary>
    /// <remarks>
    /// This and the five fields below it are playback preferences rather than permissions, so unlike the
    /// permission entries above they grant nothing and can widen no account's access. The two language
    /// fields are not validated against a language list: Jellyfin stores whatever code it is given, and a
    /// plugin-side allow-list would drift against it and begin refusing languages Jellyfin accepts.
    /// </remarks>
    public string? AudioLanguagePreference { get; set; }

    /// <summary>
    /// Gets or sets the preferred subtitle language written onto a brand-new account (#1100), as the
    /// language code Jellyfin itself stores. Null leaves Jellyfin's own default alone.
    /// </summary>
    public string? SubtitleLanguagePreference { get; set; }

    /// <summary>
    /// Gets or sets the subtitle playback mode written onto a brand-new account (#1100), as the exact
    /// <c>SubtitlePlaybackMode</c> enum name (for example <c>Smart</c>). Null leaves Jellyfin's own default
    /// alone, and an unknown name is rejected on save rather than falling back to the enum's zero value,
    /// which would silently be a mode the administrator did not ask for.
    /// </summary>
    public string? SubtitleMode { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether the default audio track is played, written onto a brand-new
    /// account (#1100). Null leaves Jellyfin's own default alone, which is why this is a nullable bool:
    /// with a plain one an unset field is indistinguishable from a deliberate <see langword="false"/>.
    /// </summary>
    public bool? PlayDefaultAudioTrack { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether audio selections are remembered, written onto a brand-new
    /// account (#1100). Null leaves Jellyfin's own default alone.
    /// </summary>
    public bool? RememberAudioSelections { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether subtitle selections are remembered, written onto a brand-new
    /// account (#1100). Null leaves Jellyfin's own default alone.
    /// </summary>
    public bool? RememberSubtitleSelections { get; set; }

    /// <summary>
    /// Gets or sets the web client's home-screen sections written for a brand-new account (#1101), top
    /// slot first, each as the exact <c>HomeSectionType</c> enum name (for example
    /// <c>SmallLibraryTiles</c>, <c>Resume</c>, <c>NextUp</c>, <c>LatestMedia</c>). Null or empty writes
    /// nothing at all, so the account keeps Jellyfin's own layout. Up to ten entries; the remaining slots
    /// are written as <c>None</c>, so the list is the whole layout rather than a prefix the client
    /// completes with its own defaults.
    /// </summary>
    /// <remarks>
    /// Unlike every other field of this template this is not a column on the account: it is written into
    /// the account's display-preferences document for the web client, through the host's
    /// display-preferences store, after the account itself is persisted, and a failure there is logged and
    /// never fails the login. An unknown name, or a list longer than the web client's ten slots, is
    /// rejected on save.
    /// </remarks>
    public List<string>? HomeSections { get; set; }
}

/// <summary>
/// One boolean permission a provisioning template writes onto a brand-new account (#1099).
/// </summary>
public class ProvisionedPermissionEntry
{
    /// <summary>
    /// Gets or sets the Jellyfin permission to write, as the exact <c>PermissionKind</c> enum name (for
    /// example <c>EnableContentDownloading</c>). An unknown name, or one of the permissions managed by
    /// their own dedicated setting or barred from SSO writes, is rejected on save.
    /// </summary>
    public string? Permission { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether the permission is granted. Defaults to <see langword="false"/>,
    /// so an entry added without a value REVOKES rather than grants - the fail-closed direction for a field
    /// an administrator may have added by hand to a config file and left half-filled.
    /// </summary>
    public bool Granted { get; set; }
}

/// <summary>
/// Maps a single Jellyfin permission (by its <c>PermissionKind</c> name) to the roles that grant it,
/// for the generic role-to-permission RBAC mapping (#164). The permission name is validated fail-closed
/// on save; at login the permission is granted only when a matching role is present and otherwise
/// explicitly revoked (default-deny).
/// </summary>
public class PermissionRoleMap
{
    /// <summary>
    /// Gets or sets the Jellyfin permission this mapping grants, as the exact <c>PermissionKind</c>
    /// enum name (e.g. <c>EnableContentDownloading</c>). An unknown name, or one of the dedicated
    /// permissions managed elsewhere (administrator, all-folders, Live TV), is rejected on save.
    /// </summary>
    public string? Permission { get; set; }

    /// <summary>
    /// Gets or sets the roles that grant the permission. A login holding any of these roles is granted
    /// the permission; a login holding none has it explicitly revoked.
    /// </summary>
    public string[]? Roles { get; set; }
}

/// <summary>
/// Maps a set of provider roles to a maximum parental-rating score ceiling (#736): a login holding any of
/// the listed roles has its Jellyfin <c>MaxParentalRatingScore</c> capped at <see cref="Score"/>. When a
/// login matches several entries the minimum (most restrictive) score wins. The score is validated
/// fail-closed on save (non-negative; the role list must be non-empty).
/// </summary>
public class ParentalRatingRoleMap
{
    /// <summary>
    /// Gets or sets the maximum parental-rating score granted to the listed roles. A smaller value is more
    /// restrictive; when several mappings match a login the smallest wins.
    /// </summary>
    public int Score { get; set; }

    /// <summary>
    /// Gets or sets the roles the ceiling applies to. A login holding any of these roles is capped at
    /// <see cref="Score"/>; a login holding none is left untouched.
    /// </summary>
    public string[]? Roles { get; set; }
}

/// <summary>
/// Maps a set of provider roles to a SyncPlay access level (#827): a login holding any of the listed roles
/// has its Jellyfin <c>SyncPlayAccess</c> set to <see cref="Access"/>. When a login matches several entries
/// the MOST RESTRICTIVE level wins - which is NOT the smallest value, because Jellyfin's enum numbers the
/// loosest level zero. The level is validated fail-closed on save (it must be a declared member of the
/// SyncPlay access enum, spelled exactly; the role list must be non-empty).
/// </summary>
public class SyncPlayAccessRoleMap
{
    /// <summary>
    /// Gets or sets the SyncPlay access level granted to the listed roles, as the exact name of a Jellyfin
    /// <c>SyncPlayUserAccessType</c> member - <c>CreateAndJoinGroups</c>, <c>JoinGroups</c> or <c>None</c>.
    /// Held as a string rather than as the enum itself so a mis-set value is reported by save-time
    /// validation instead of failing the whole configuration document at deserialization.
    /// </summary>
    public string? Access { get; set; }

    /// <summary>
    /// Gets or sets the roles the level applies to. A login holding any of these roles is set to
    /// <see cref="Access"/>; a login holding none is left untouched.
    /// </summary>
    public string[]? Roles { get; set; }
}

/// <summary>
/// Maps a set of provider roles to a fixed access duration (#1146): an account provisioned by a login
/// holding any of the listed roles is stamped with a deadline of the provisioning moment plus
/// <see cref="DurationHours"/>. When a login matches several entries the SHORTEST duration wins, which is
/// the fail-closed direction. Validated on save: the role list must be non-empty and the duration must be
/// positive and within <see cref="MaxDurationHours"/>.
/// </summary>
public class GuestAccessDurationRoleMap
{
    /// <summary>
    /// The largest duration a mapping may carry, in hours - a hundred 365-day years. It is a guard rather
    /// than a policy: the duration is added to the provisioning instant on the login path, and
    /// <see cref="DateTime.AddHours"/> THROWS once the result leaves <see cref="DateTime.MaxValue"/>, so an
    /// unbounded value hand-edited into the config XML would turn every provisioning login for that provider
    /// into a 500 rather than into a very distant deadline. Anything needing longer than a century is not a
    /// time limit and should carry no mapping at all.
    /// </summary>
    public const int MaxDurationHours = 876_000;

    /// <summary>
    /// Gets or sets the access duration granted to the listed roles, in hours, counted from the moment the
    /// account is provisioned. Hours rather than days so a short trial (a 12-hour pass) and a long one (a
    /// 30-day guest, 720) are both expressible in one field. A shorter value is more restrictive; when
    /// several mappings match a login the smallest wins.
    /// </summary>
    public int DurationHours { get; set; }

    /// <summary>
    /// Gets or sets the roles the duration applies to. A login holding any of these roles provisions with the
    /// deadline; a login holding none provisions with no deadline at all.
    /// </summary>
    public string[]? Roles { get; set; }
}

/// <summary>
/// One row of a provider's ordered role-to-provisioning-profile map (#1106): the roles that select a named
/// provisioning profile for a brand-new account.
/// </summary>
public class ProvisioningProfileRoleMap
{
    /// <summary>
    /// Gets or sets the name of the <see cref="PluginConfiguration.ProvisioningProfiles"/> entry a matching
    /// login is provisioned from. A blank name selects nothing: it is refused on save, and skipped at
    /// creation so a hand-edited configuration cannot turn one dead row into a failed login.
    /// </summary>
    public string? Profile { get; set; }

    /// <summary>
    /// Gets or sets the roles this row applies to. A login holding any of them matches the row; a login
    /// holding none moves on to the next row.
    /// </summary>
    public string[]? Roles { get; set; }
}
