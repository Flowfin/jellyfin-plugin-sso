// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Xml;
using System.Xml.Serialization;

namespace Jellyfin.Plugin.SSO_Auth.Config;

/// <summary>The persisted plugin configuration: the providers, the global switches and the server-managed maps.</summary>
/// <remarks>
/// What each option does for an administrator is on
/// <see href="https://github.com/Flowfin/jellyfin-plugin-sso/wiki/Hardening-and-Options-Reference"/>; the
/// server-managed maps are withheld from JSON and re-injected on save by <see cref="ServerManagedFields"/>.
/// </remarks>
public class PluginConfiguration : MediaBrowser.Model.Plugins.BasePluginConfiguration
{
    // Resolved once: a write happens on the login path and reflection is a startup cost.
    private static readonly System.Reflection.PropertyInfo[] AdoptableProperties = Array.FindAll(
        typeof(PluginConfiguration).GetProperties(System.Reflection.BindingFlags.Public | System.Reflection.BindingFlags.Instance),
        property => property.CanRead && property.CanWrite && property.GetIndexParameters().Length == 0);

    private List<Guid>? _ssoOnlyRepointedUserIds;
    private SerializableDictionary<Guid, string>? _provisionedPasswords;
    private SerializableDictionary<string, LogoutSession>? _logoutSessions;

    /// <summary>Initializes a new instance of the <see cref="PluginConfiguration"/> class.</summary>
    public PluginConfiguration()
    {
        SamlConfigs = new SerializableDictionary<string, SamlConfig>();
        OidConfigs = new SerializableDictionary<string, OidConfig>();
        ProvisioningProfiles = new SerializableDictionary<string, ProvisioningPolicyTemplate>();
        RateLimitMaxAttempts = 30;
        RateLimitWindowSeconds = 60;
    }

    /// <summary>Gets or sets the SAML providers, keyed by provider name.</summary>
    [XmlElement("SamlConfigs")]
    public SerializableDictionary<string, SamlConfig> SamlConfigs { get; set; }

    /// <summary>Gets or sets the OpenID providers, keyed by provider name.</summary>
    [XmlElement("OidConfigs")]
    public SerializableDictionary<string, OidConfig> OidConfigs { get; set; }

    /// <summary>Gets or sets the named provisioning profiles a provider can point at (#1105).</summary>
    /// <remarks>
    /// A provider names one in <see cref="ProviderConfigBase.ProvisioningProfile"/>; naming a profile and an inline
    /// template together is refused on save, so one account-creation policy has one source. See
    /// <see href="https://github.com/Flowfin/jellyfin-plugin-sso/wiki/Hardening-and-Options-Reference#provisioning-profiles-one-starting-policy-shared-by-several-providers"/>.
    /// </remarks>
    [XmlElement("ProvisioningProfiles")]
    public SerializableDictionary<string, ProvisioningPolicyTemplate> ProvisioningProfiles { get; set; }

    /// <summary>Gets or sets a value indicating whether the anonymous SSO endpoints are rate-limited per client address (#128).</summary>
    /// <remarks>
    /// Off by default. Behind a reverse proxy it needs Jellyfin's known-proxies setting first, or every client shares
    /// one address: <see href="https://github.com/Flowfin/jellyfin-plugin-sso/wiki/Security-Model#rate-limiting-optional"/>.
    /// </remarks>
    public bool EnableRateLimit { get; set; }

    /// <summary>Gets or sets how many hits per window a client may make before a 429; below 1 disables the limiter.</summary>
    public int RateLimitMaxAttempts { get; set; }

    /// <summary>Gets or sets the rate-limit window length in seconds.</summary>
    public int RateLimitWindowSeconds { get; set; }

    /// <summary>Gets or sets a value indicating whether the plugin manages the login-page buttons through the branding disclaimer (#722).</summary>
    /// <remarks>
    /// Off by default, so a deployment that does not opt in never has its branding rewritten. See
    /// <see href="https://github.com/Flowfin/jellyfin-plugin-sso/wiki/Hardening-and-Options-Reference#managed-login-page-buttons"/>.
    /// </remarks>
    public bool ManageLoginPageButtons { get; set; }

    /// <summary>Gets or sets a value indicating whether Single Logout is on (#727).</summary>
    /// <remarks>
    /// Off by default: no per-session logout state is captured and no logout surface is exposed. See
    /// <see href="https://github.com/Flowfin/jellyfin-plugin-sso/wiki/Single-Logout-Design"/>.
    /// </remarks>
    public bool EnableSingleLogout { get; set; }

    /// <summary>Gets or sets a value indicating whether SSO-only login is on (#165).</summary>
    /// <remarks>
    /// Server-managed: settable only through the elevated SSO-Only endpoints, which run the last-admin guard in
    /// <see cref="SsoOnlyLoginGuard"/>. See
    /// <see href="https://github.com/Flowfin/jellyfin-plugin-sso/wiki/SSO-Only-Login-Design"/>.
    /// </remarks>
    public bool DisablePasswordLogin { get; set; }

    /// <summary>Gets or sets the username of the break-glass administrator SSO-only mode never repoints.</summary>
    /// <remarks>
    /// Server-managed like <see cref="DisablePasswordLogin"/>, and only ever pointed at an existing administrator, so
    /// it cannot grant admin. Blank means the mode cannot be enabled.
    /// </remarks>
    public string? BreakGlassAdminUsername { get; set; }

    /// <summary>Gets or sets the ids of the accounts SSO-only mode has repointed off the password provider (#165).</summary>
    /// <remarks>
    /// Server-managed bookkeeping: only these accounts are restored when the mode is turned off, because the plugin's
    /// own accounts carry the SSO provider id permanently and must not be handed a password door.
    /// </remarks>
    [XmlArray("SsoOnlyRepointedUserIds")]
    [XmlArrayItem("UserId")]
    [System.Text.Json.Serialization.JsonIgnore]
    public List<Guid> SsoOnlyRepointedUserIds
    {
        // A config PUT deserializes this to null, so a later write under the config lock needs a stored list.
        get => _ssoOnlyRepointedUserIds ??= new List<Guid>();
        set => _ssoOnlyRepointedUserIds = value;
    }

    /// <summary>Gets or sets a digest, per account, of the password this plugin minted onto it (#1733).</summary>
    /// <remarks>
    /// A digest rather than a flag, so the record stops matching the moment anything else writes the password. See
    /// <see href="https://github.com/Flowfin/jellyfin-plugin-sso/wiki/Security-Model#password-less-sso-accounts-are-sealed-at-start-up"/>.
    /// </remarks>
    [XmlElement("ProvisionedPasswords")]
    [System.Text.Json.Serialization.JsonIgnore]
    public SerializableDictionary<Guid, string> ProvisionedPasswords
    {
        // A config PUT deserializes this to null, so a later write under the config lock needs a stored map.
        get => _provisionedPasswords ??= new SerializableDictionary<Guid, string>();
        set => _provisionedPasswords = value;
    }

    /// <summary>Gets or sets the per-session Single Logout state captured at login (#727), keyed by an opaque session key.</summary>
    /// <remarks>
    /// Server-managed runtime state, bounded, and persisted so a session survives a restart; each entry's
    /// <see cref="LogoutSession.IdToken"/> is encrypted at rest.
    /// </remarks>
    [XmlElement("LogoutSessions")]
    [System.Text.Json.Serialization.JsonIgnore]
    public SerializableDictionary<string, LogoutSession> LogoutSessions
    {
        // A config PUT deserializes this to null, so a later write under the config lock needs a stored map.
        get => _logoutSessions ??= new SerializableDictionary<string, LogoutSession>();
        set => _logoutSessions = value;
    }

    /// <summary>Renders this configuration in the form the host persists, so two configurations compare on every field (#1095).</summary>
    /// <remarks>The JSON boundary withholds secrets and link maps, so two configurations differing only there compare equal through it.</remarks>
    /// <returns>The persisted XML form of this configuration.</returns>
    internal string ToPersistedForm()
    {
        using var writer = new StringWriter(CultureInfo.InvariantCulture);
        new XmlSerializer(typeof(PluginConfiguration)).Serialize(writer, this);
        return writer.ToString();
    }

    /// <summary>Makes a detached copy through the persisted form, so a change can be tried without the live object holding a half-applied state (#1095).</summary>
    /// <returns>An independent configuration carrying the same persisted fields.</returns>
    internal PluginConfiguration DetachedCopy() => FromPersistedForm(ToPersistedForm());

    /// <summary>Reads back a configuration from what <see cref="ToPersistedForm"/> produced.</summary>
    /// <remarks>Split out so a mutation holding an undo pays one serialization and keeps the string (#1521).</remarks>
    /// <param name="persisted">The persisted form to read back.</param>
    /// <returns>An independent configuration carrying the fields that form holds.</returns>
    internal static PluginConfiguration FromPersistedForm(string persisted)
    {
        // The plugin's own output, still read with no DTD and no resolver like every other XML read here.
        var settings = new XmlReaderSettings
        {
            DtdProcessing = DtdProcessing.Prohibit,
            XmlResolver = null,
        };

        using var text = new StringReader(persisted);
        using var reader = XmlReader.Create(text, settings);
        return (PluginConfiguration)new XmlSerializer(typeof(PluginConfiguration)).Deserialize(reader)!;
    }

    /// <summary>Takes over every persisted field of <paramref name="source"/> in place, so no holder of this object sees a different instance (#1521).</summary>
    /// <remarks>The swap at the end of a mutation: prepared on a <see cref="DetachedCopy"/>, written to disk, adopted here only once the write returned.</remarks>
    /// <param name="source">The configuration whose state to take over; its sub-objects are adopted by reference.</param>
    internal void AdoptFrom(PluginConfiguration source)
    {
        ArgumentNullException.ThrowIfNull(source);
        if (ReferenceEquals(this, source))
        {
            return;
        }

        // The set is derived from the type and equals what the XML serializer persists, so a new property is carried without a list to update.
        foreach (var property in AdoptableProperties)
        {
            property.SetValue(this, property.GetValue(source));
        }
    }
}

/// <summary>Configuration shared by every SSO provider; <see cref="SamlConfig"/> and <see cref="OidConfig"/> inherit it.</summary>
/// <remarks>
/// The admin write paths replace a provider object wholesale, so an omitted value type deserializes to its default
/// by design and the properties stay non-nullable (#196, #204). See
/// <see href="https://github.com/Flowfin/jellyfin-plugin-sso/wiki/Hardening-and-Options-Reference"/>.
/// </remarks>
public abstract class ProviderConfigBase
{
    /// <summary>The resolution <see cref="CanonicalLinkLastLogins"/> is kept to, so a repeat login costs at most one persist per link per hour.</summary>
    internal static readonly TimeSpan LastSsoLoginGranularity = TimeSpan.FromHours(1);

    private SerializableDictionary<string, Guid>? _canonicalLinks;
    private SerializableDictionary<string, DateTime>? _canonicalLinkDeadlines;
    private SerializableDictionary<string, DateTime>? _canonicalLinkLastLogins;
    private SerializableDictionary<string, PendingApproval>? _canonicalLinkPendingApprovals;

    /// <summary>Gets or sets the canonical external base URL this provider's redirect and consumer URLs are built from (#139).</summary>
    /// <remarks>
    /// Blank keeps the request host. See
    /// <see href="https://github.com/Flowfin/jellyfin-plugin-sso/wiki/Hardening-and-Options-Reference#canonical-base-url-recommended-hardening"/>.
    /// </remarks>
    public string BaseUrlOverride { get; set; } = string.Empty;

    /// <summary>Gets or sets a value indicating whether the provider is enabled.</summary>
    public bool Enabled { get; set; }

    /// <summary>Gets or sets the <c>post_logout_redirect_uri</c> sent on an RP-initiated logout (#727).</summary>
    /// <remarks>
    /// Honoured only at or under this server's canonical base URL, as an open-redirect defence. See
    /// <see href="https://github.com/Flowfin/jellyfin-plugin-sso/wiki/Hardening-and-Options-Reference#openid-rp-initiated-logout-outbound"/>.
    /// </remarks>
    public string? PostLogoutRedirectUri { get; set; }

    /// <summary>Gets or sets a value indicating whether this provider accepts an inbound OpenID back-channel <c>logout_token</c> (#962).</summary>
    /// <remarks>
    /// Off by default and needs <see cref="PluginConfiguration.EnableSingleLogout"/>. See
    /// <see href="https://github.com/Flowfin/jellyfin-plugin-sso/wiki/Hardening-and-Options-Reference#openid-back-channel-logout-inbound"/>.
    /// </remarks>
    public bool EnableBackChannelLogout { get; set; }

    /// <summary>Gets or sets a value indicating whether a login denied by the role allow-list disables the linked account (#831).</summary>
    /// <remarks>
    /// Off by default, and an administrator is never disabled by this path, so one always remains to recover. See
    /// <see href="https://github.com/Flowfin/jellyfin-plugin-sso/wiki/Hardening-and-Options-Reference#login-time-deprovisioning-disable-account-on-role-denied"/>.
    /// </remarks>
    public bool DisableAccountOnRoleDenied { get; set; }

    /// <summary>Gets or sets the claim or assertion attribute that carries an account-expiry instant (#1143).</summary>
    /// <remarks>
    /// Blank reads no expiry. See
    /// <see href="https://github.com/Flowfin/jellyfin-plugin-sso/wiki/Hardening-and-Options-Reference#time-limited-access-accountexpiryclaim"/>.
    /// </remarks>
    public string? AccountExpiryClaim { get; set; }

    /// <summary>Gets or sets the role-to-duration rows that give a brand-new account a fixed access lifetime (#1146).</summary>
    /// <remarks>
    /// Stamped once at creation; the claim wins over a row, and the shortest matching duration wins. See
    /// <see href="https://github.com/Flowfin/jellyfin-plugin-sso/wiki/Hardening-and-Options-Reference#time-limited-access-accountexpiryclaim"/>.
    /// </remarks>
    [XmlArray("GuestAccessDurationRoleMappings")]
    [XmlArrayItem(typeof(GuestAccessDurationRoleMap), ElementName = "GuestAccessDurationRoleMappings")]
    public List<GuestAccessDurationRoleMap>? GuestAccessDurationRoleMappings { get; set; }

    /// <summary>Gets or sets a value indicating whether this provider gets no managed login-page button (#722).</summary>
    public bool HideLoginButton { get; set; }

    /// <summary>Gets or sets the label of this provider's managed login-page button; blank uses the provider name (#722).</summary>
    public string? LoginButtonText { get; set; }

    /// <summary>Gets or sets a value indicating whether role-based authorization is on.</summary>
    public bool EnableAuthorization { get; set; }

    /// <summary>Gets or sets a value indicating whether a login may adopt an unlinked account of the same name (#484).</summary>
    /// <remarks>
    /// Off by default: a first login matching an existing account is refused rather than taking it over. See
    /// <see href="https://github.com/Flowfin/jellyfin-plugin-sso/wiki/Security-Model#identity-binding-anti-account-takeover"/>.
    /// </remarks>
    public bool AllowExistingAccountLink { get; set; }

    /// <summary>Gets or sets a value indicating whether a first login provisions its account disabled, pending approval (#737).</summary>
    /// <remarks>
    /// Never disables an existing account. See
    /// <see href="https://github.com/Flowfin/jellyfin-plugin-sso/wiki/Hardening-and-Options-Reference#provision-new-users-pending-approval"/>.
    /// </remarks>
    public bool ProvisionNewUsersDisabled { get; set; }

    /// <summary>Gets or sets a value indicating whether a linked account is renamed to follow the provider's username (#1138).</summary>
    /// <remarks>
    /// Off by default. The subject stays the key, so the name follows the account and never selects one; a name held
    /// by another account is left alone.
    /// </remarks>
    public bool SyncUsernameFromProvider { get; set; }

    /// <summary>Gets or sets a value indicating whether every library is granted by default.</summary>
    public bool EnableAllFolders { get; set; }

    /// <summary>Gets or sets the libraries granted by default.</summary>
    public string[]? EnabledFolders { get; set; }

    /// <summary>Gets or sets the roles that make a login an administrator.</summary>
    public string[]? AdminRoles { get; set; }

    /// <summary>Gets or sets the roles a login must hold to use Jellyfin.</summary>
    public string[]? Roles { get; set; }

    /// <summary>Gets or sets a value indicating whether library access is granted by role.</summary>
    public bool EnableFolderRoles { get; set; }

    /// <summary>Gets or sets a value indicating whether a login leaves alone the libraries this provider does not manage (#1846).</summary>
    /// <remarks>
    /// Off by default, which replaces the account's library list on every login. See
    /// <see href="https://github.com/Flowfin/jellyfin-plugin-sso/wiki/Hardening-and-Options-Reference#libraries-a-login-leaves-alone-preserveunmanagedfolders"/>.
    /// </remarks>
    public bool PreserveUnmanagedFolders { get; set; }

    /// <summary>Gets or sets a value indicating whether Live TV access is granted by role.</summary>
    public bool EnableLiveTvRoles { get; set; }

    /// <summary>Gets or sets a value indicating whether Live TV is granted by default.</summary>
    public bool EnableLiveTv { get; set; }

    /// <summary>Gets or sets a value indicating whether Live TV management is granted by default.</summary>
    public bool EnableLiveTvManagement { get; set; }

    /// <summary>Gets or sets the roles that grant Live TV access.</summary>
    public string[]? LiveTvRoles { get; set; }

    /// <summary>Gets or sets the roles that grant Live TV management.</summary>
    public string[]? LiveTvManagementRoles { get; set; }

    /// <summary>Gets or sets the role-to-library rows.</summary>
    [XmlArray("FolderRoleMappings")]
    [XmlArrayItem(typeof(FolderRoleMap), ElementName = "FolderRoleMappings")]
    public List<FolderRoleMap>? FolderRoleMapping { get; set; }

    /// <summary>Gets or sets a value indicating whether <see cref="PermissionRoleMappings"/> is applied at login (#164).</summary>
    /// <remarks>Off by default, and gated by <see cref="EnableAuthorization"/> like every other role-derived grant.</remarks>
    public bool EnablePermissionRoles { get; set; }

    /// <summary>Gets or sets the role-to-permission rows applied at login (#164).</summary>
    /// <remarks>
    /// Default-deny: a listed permission is granted on a matching role and otherwise revoked, and the permissions with
    /// their own setting are refused here. See
    /// <see href="https://github.com/Flowfin/jellyfin-plugin-sso/wiki/Hardening-and-Options-Reference#permission-role-mapping-map-groups-onto-jellyfins-permission-surface"/>.
    /// </remarks>
    [XmlArray("PermissionRoleMappings")]
    [XmlArrayItem(typeof(PermissionRoleMap), ElementName = "PermissionRoleMappings")]
    public List<PermissionRoleMap>? PermissionRoleMappings { get; set; }

    /// <summary>Gets or sets the policy written onto a brand-new account at creation and never re-applied (#1099).</summary>
    /// <remarks>
    /// Once at creation, so a later per-user edit survives. See
    /// <see href="https://github.com/Flowfin/jellyfin-plugin-sso/wiki/Hardening-and-Options-Reference#starting-policy-for-new-accounts-provisioning-template"/>.
    /// </remarks>
    public ProvisioningPolicyTemplate? ProvisioningPolicyTemplate { get; set; }

    /// <summary>Gets or sets the name of the <see cref="PluginConfiguration.ProvisioningProfiles"/> entry written onto this provider's new accounts (#1105).</summary>
    /// <remarks>Naming both this and the inline template is refused on save; a name that no longer resolves writes no policy rather than falling back.</remarks>
    public string? ProvisioningProfile { get; set; }

    /// <summary>Gets or sets the ordered role-to-profile rows that select a new account's provisioning profile (#1106).</summary>
    /// <remarks>The first matching row decides, an unmatched login falls to <see cref="ProvisioningProfile"/>, and a row that no longer resolves writes no policy.</remarks>
    [XmlArray("ProvisioningProfileRoleMappings")]
    [XmlArrayItem(typeof(ProvisioningProfileRoleMap), ElementName = "ProvisioningProfileRoleMappings")]
    public List<ProvisioningProfileRoleMap>? ProvisioningProfileRoleMappings { get; set; }

    /// <summary>Gets or sets a value indicating whether <see cref="ParentalRatingRoleMappings"/> is applied at login (#736).</summary>
    public bool EnableParentalRatingRoles { get; set; }

    /// <summary>Gets or sets the role-to-parental-rating-ceiling rows applied at login (#736).</summary>
    /// <remarks>
    /// The most restrictive matching ceiling wins and an unmatched login is left alone. See
    /// <see href="https://github.com/Flowfin/jellyfin-plugin-sso/wiki/Hardening-and-Options-Reference#parental-rating-by-role-content-ceiling"/>.
    /// </remarks>
    [XmlArray("ParentalRatingRoleMappings")]
    [XmlArrayItem(typeof(ParentalRatingRoleMap), ElementName = "ParentalRatingRoleMappings")]
    public List<ParentalRatingRoleMap>? ParentalRatingRoleMappings { get; set; }

    /// <summary>Gets or sets a value indicating whether <see cref="SyncPlayAccessRoleMappings"/> is applied at login (#827).</summary>
    public bool EnableSyncPlayAccessRoles { get; set; }

    /// <summary>Gets or sets the role-to-SyncPlay-access rows applied at login (#827).</summary>
    /// <remarks>
    /// The most restrictive matching level wins, as declared by the resolver rather than by the enum's order. See
    /// <see href="https://github.com/Flowfin/jellyfin-plugin-sso/wiki/Hardening-and-Options-Reference#syncplay-access-by-role"/>.
    /// </remarks>
    [XmlArray("SyncPlayAccessRoleMappings")]
    [XmlArrayItem(typeof(SyncPlayAccessRoleMap), ElementName = "SyncPlayAccessRoleMappings")]
    public List<SyncPlayAccessRoleMap>? SyncPlayAccessRoleMappings { get; set; }

    /// <summary>Gets or sets the authentication provider id written onto the account after a login; blank leaves it untouched.</summary>
    public string? DefaultProvider { get; set; }

    /// <summary>Gets or sets the redirect scheme override.</summary>
    public string SchemeOverride { get; set; } = string.Empty;

    /// <summary>Gets or sets the redirect port override.</summary>
    public int? PortOverride { get; set; }

    /// <summary>Gets or sets a value indicating whether the last non-linking login used the "/start/" redirect path spelling.</summary>
    /// <remarks>Server-managed runtime state, so a later linking flow reuses the spelling the identity provider has registered.</remarks>
    public bool NewPath { get; set; }

    /// <summary>Gets or sets the map from the provider's stable subject to the linked Jellyfin user id.</summary>
    /// <remarks>
    /// Server-managed and withheld from JSON (#157), so a config PUT can neither read nor set a link. See
    /// <see href="https://github.com/Flowfin/jellyfin-plugin-sso/wiki/Linked-Accounts#design-record-links-keys-and-guards"/>.
    /// </remarks>
    [XmlElement("CanonicalLinks")]
    [System.Text.Json.Serialization.JsonIgnore]
    public SerializableDictionary<string, Guid> CanonicalLinks
    {
        // A config PUT deserializes this to null, so a later write under the config lock needs a stored map.
        get => _canonicalLinks ??= new SerializableDictionary<string, Guid>();
        set => _canonicalLinks = value;
    }

    /// <summary>Gets or sets, per canonical link, the account-expiry instant the last login carried, in UTC (#1145).</summary>
    /// <remarks>
    /// Persisted so the background sweep ends access on the deadline rather than at the next login, and withheld from
    /// JSON so a config PUT cannot forge a past instant.
    /// </remarks>
    [XmlElement("CanonicalLinkDeadlines")]
    [System.Text.Json.Serialization.JsonIgnore]
    public SerializableDictionary<string, DateTime> CanonicalLinkDeadlines
    {
        get => _canonicalLinkDeadlines ??= new SerializableDictionary<string, DateTime>();
        set => _canonicalLinkDeadlines = value;
    }

    /// <summary>Gets or sets, per canonical link, the instant of the last successful SSO login, in UTC (#1120).</summary>
    /// <remarks>
    /// Coarse to <see cref="LastSsoLoginGranularity"/> on purpose, so a repeat login pays no persist. See
    /// <see href="https://github.com/Flowfin/jellyfin-plugin-sso/wiki/Linked-Accounts#the-last-login-stamp-is-coarse-on-purpose"/>.
    /// </remarks>
    [XmlElement("CanonicalLinkLastLogins")]
    [System.Text.Json.Serialization.JsonIgnore]
    public SerializableDictionary<string, DateTime> CanonicalLinkLastLogins
    {
        get => _canonicalLinkLastLogins ??= new SerializableDictionary<string, DateTime>();
        set => _canonicalLinkLastLogins = value;
    }

    /// <summary>Gets or sets, per canonical link, the record that this plugin provisioned the account disabled and awaiting approval (#1529).</summary>
    /// <remarks>
    /// Separates what the plugin did from what it could guess, so the approval surface never offers to enable an
    /// account an administrator disabled on purpose. See
    /// <see href="https://github.com/Flowfin/jellyfin-plugin-sso/wiki/Linked-Accounts#waiting-for-approval"/>.
    /// </remarks>
    [XmlElement("CanonicalLinkPendingApprovals")]
    [System.Text.Json.Serialization.JsonIgnore]
    public SerializableDictionary<string, PendingApproval> CanonicalLinkPendingApprovals
    {
        get => _canonicalLinkPendingApprovals ??= new SerializableDictionary<string, PendingApproval>();
        set => _canonicalLinkPendingApprovals = value;
    }
}

/// <summary>The configuration of one SAML provider.</summary>
// The root name is the element SerializableDictionary.WriteXml persists; renaming it stops every stored entry from loading.
[XmlRoot("PluginConfiguration")]
public class SamlConfig : ProviderConfigBase
{
    /// <summary>Gets or sets the identity provider's single sign-on endpoint.</summary>
    public string SamlEndpoint { get; set; } = string.Empty;

    /// <summary>Gets or sets the identity provider's single logout endpoint, an absolute https URL (#727).</summary>
    /// <remarks>Blank degrades the logout route to a local-only logout; https is required because the signed request names the subject.</remarks>
    public string SamlSloEndpoint { get; set; } = string.Empty;

    /// <summary>Gets or sets this service provider's entity id.</summary>
    public string SamlClientId { get; set; } = string.Empty;

    /// <summary>Gets or sets the identity provider's signing certificate.</summary>
    public string? SamlCertificate { get; set; }

    /// <summary>Gets or sets a second identity-provider signing certificate accepted during an inbound key rotation (#491).</summary>
    /// <remarks>
    /// A public certificate, not a secret; an expired one is refused. See
    /// <see href="https://github.com/Flowfin/jellyfin-plugin-sso/wiki/Hardening-and-Options-Reference#saml-identity-provider-certificate-rotation-inbound"/>.
    /// </remarks>
    public string? SamlSecondaryCertificate { get; set; }

    /// <summary>Gets or sets the audience a response must be addressed to; blank uses <see cref="SamlClientId"/>.</summary>
    public string? SamlAudience { get; set; }

    /// <summary>Gets or sets a value indicating whether the assertion's audience restriction is not checked.</summary>
    /// <remarks>
    /// Off by default, so a response must be addressed to this service provider. See
    /// <see href="https://github.com/Flowfin/jellyfin-plugin-sso/wiki/Hardening-and-Options-Reference#saml-audience-validation"/>.
    /// </remarks>
    public bool DoNotValidateAudience { get; set; }

    /// <summary>Gets or sets a value indicating whether the bearer recipient and the response destination are bound to this server's consumer URL (#156).</summary>
    /// <remarks>
    /// Opt-in. See
    /// <see href="https://github.com/Flowfin/jellyfin-plugin-sso/wiki/Hardening-and-Options-Reference#saml-response-binding-optional-hardening"/>.
    /// </remarks>
    public bool ValidateRecipient { get; set; }

    /// <summary>Gets or sets a value indicating whether only responses to a request this server issued are accepted (#156).</summary>
    /// <remarks>Opt-in, and it refuses identity-provider-initiated sign-on, which carries no <c>InResponseTo</c>.</remarks>
    public bool ValidateInResponseTo { get; set; }

    /// <summary>Gets or sets a value indicating whether the outgoing authentication request is signed with <see cref="SamlSigningKeyPfx"/> (#167).</summary>
    /// <remarks>
    /// Opt-in; with a missing or unloadable key the challenge fails closed rather than sending an unsigned request. See
    /// <see href="https://github.com/Flowfin/jellyfin-plugin-sso/wiki/Hardening-and-Options-Reference#saml-request-signing-optional"/>.
    /// </remarks>
    public bool SignAuthnRequests { get; set; }

    /// <summary>Gets or sets the service-provider signing key as a Base64 unencrypted PKCS#12 blob (#167).</summary>
    /// <remarks>A secret: write-only across the JSON boundary and preserved on a save that leaves it blank.</remarks>
    [System.Text.Json.Serialization.JsonConverter(typeof(WriteOnlySecretConverter))]
    public string? SamlSigningKeyPfx { get; set; }

    /// <summary>Gets or sets a second service-provider signing key that the metadata publishes during a rollover (#491).</summary>
    /// <remarks>
    /// Publish-only: requests are always signed with the primary. See
    /// <see href="https://github.com/Flowfin/jellyfin-plugin-sso/wiki/Hardening-and-Options-Reference#saml-sp-signing-key-rollover"/>.
    /// </remarks>
    [System.Text.Json.Serialization.JsonConverter(typeof(WriteOnlySecretConverter))]
    public string? SamlRolloverSigningKeyPfx { get; set; }
}

/// <summary>The configuration of one OpenID provider.</summary>
// The root name is the element SerializableDictionary.WriteXml persists; renaming it stops every stored entry from loading.
[XmlRoot("PluginConfiguration")]
public class OidConfig : ProviderConfigBase
{
    private SerializableDictionary<string, string>? _canonicalLinkIssuers;

    /// <summary>Gets or sets the OpenID discovery endpoint.</summary>
    public string? OidEndpoint { get; set; }

    /// <summary>Gets or sets, per canonical link, the issuer the link was minted under (#186).</summary>
    /// <remarks>
    /// A mismatch at login refuses the login, so a repointed provider cannot map a colliding subject onto an old
    /// account; a link with no issuer is stamped on its next login. See
    /// <see href="https://github.com/Flowfin/jellyfin-plugin-sso/wiki/Security-Model#account-links-are-bound-to-their-issuer-repointing-protection"/>.
    /// </remarks>
    [XmlElement("CanonicalLinkIssuers")]
    [System.Text.Json.Serialization.JsonIgnore]
    public SerializableDictionary<string, string> CanonicalLinkIssuers
    {
        get => _canonicalLinkIssuers ??= new SerializableDictionary<string, string>();
        set => _canonicalLinkIssuers = value;
    }

    /// <summary>Gets or sets the OpenID client id.</summary>
    public string OidClientId { get; set; } = string.Empty;

    /// <summary>Gets or sets the OpenID client secret.</summary>
    /// <remarks>
    /// Write-only across the JSON boundary, and a blank save keeps the stored value (#189). See
    /// <see href="https://github.com/Flowfin/jellyfin-plugin-sso/wiki/Security-Model#secret-handling"/>.
    /// </remarks>
    [System.Text.Json.Serialization.JsonConverter(typeof(WriteOnlySecretConverter))]
    public string? OidSecret { get; set; }

    /// <summary>Gets a value indicating whether a client secret is stored for this provider (#1872).</summary>
    /// <remarks>
    /// Get-only and derived at every read, so it is neither persisted nor bindable from a request body, which the
    /// <see cref="System.ComponentModel.ReadOnlyAttribute"/> declares for the request-body conformance rule (#1517).
    /// </remarks>
    [System.ComponentModel.ReadOnly(true)]
    public bool OidSecretStored => !string.IsNullOrWhiteSpace(OidSecret);

    /// <summary>Gets or sets a value indicating whether adopting a same-named account also requires <c>email_verified</c> (#218).</summary>
    /// <remarks>Only meaningful with <see cref="ProviderConfigBase.AllowExistingAccountLink"/>; an administrator account is never adopted by name regardless.</remarks>
    public bool RequireVerifiedEmailForAdoption { get; set; }

    /// <summary>Gets or sets a value indicating whether every login must carry <c>email_verified == true</c> (#166).</summary>
    /// <remarks>Off by default for availability; on, it gates the login itself before any account is resolved and needs the <c>email</c> scope.</remarks>
    public bool RequireVerifiedEmailForLogin { get; set; }

    /// <summary>Gets or sets the space-separated <c>acr_values</c> sent on the authorization request (#757).</summary>
    /// <remarks>
    /// Doubles as the allow-list <see cref="RequireAcr"/> checks against. See
    /// <see href="https://github.com/Flowfin/jellyfin-plugin-sso/wiki/Hardening-and-Options-Reference#step-up--mfa"/>.
    /// </remarks>
    public string? AcrValues { get; set; }

    /// <summary>Gets or sets the <c>prompt</c> parameter sent on the authorization request; blank omits it (#757).</summary>
    public string? Prompt { get; set; }

    /// <summary>Gets or sets the <c>max_age</c> parameter in seconds; null or negative omits it (#757).</summary>
    public int? MaxAge { get; set; }

    /// <summary>Gets or sets a value indicating whether every login must return an <c>acr</c> within <see cref="AcrValues"/> (#757).</summary>
    /// <remarks>Refused on save without <see cref="AcrValues"/>, so a mis-set cannot lock out a userbase; the break-glass admin is unaffected.</remarks>
    public bool RequireAcr { get; set; }

    /// <summary>Gets or sets the dotted path of the claim that carries the roles.</summary>
    public string? RoleClaim { get; set; }

    /// <summary>Gets or sets a value indicating whether <see cref="RoleClaim"/> resolves to an object whose property names are the roles (#934).</summary>
    /// <remarks>Zitadel emits that shape; only the names are read and any other shape fails closed to no roles.</remarks>
    public bool RoleClaimIsObjectMap { get; set; }

    /// <summary>Gets or sets the additional scopes requested.</summary>
    public string?[]? OidScopes { get; set; }

    /// <summary>Gets or sets the claim a new account's username is taken from.</summary>
    public string? DefaultUsernameClaim { get; set; }

    /// <summary>Gets or sets the URL format of a new account's avatar.</summary>
    public string? AvatarUrlFormat { get; set; }

    /// <summary>Gets or sets a value indicating whether the fallback to the standard <c>picture</c> claim is off (#723).</summary>
    /// <remarks>The negative name keeps the parity default at <see langword="false"/> for a configuration saved before the field existed.</remarks>
    public bool DisableAvatarFromPictureClaim { get; set; }

    /// <summary>Gets or sets a value indicating whether an http discovery endpoint is accepted.</summary>
    public bool DisableHttps { get; set; }

    /// <summary>Gets or sets a value indicating whether pushed authorization requests are not used.</summary>
    public bool DisablePushedAuthorization { get; set; }

    /// <summary>Gets or sets a value indicating whether the discovered endpoints are not validated.</summary>
    public bool DoNotValidateEndpoints { get; set; }

    /// <summary>Gets or sets a value indicating whether this provider's back channel may reach a private network address (#1058).</summary>
    /// <remarks>
    /// Off by default; on, only RFC 1918, carrier-grade NAT and unique-local ranges open, for this provider alone. See
    /// <see href="https://github.com/Flowfin/jellyfin-plugin-sso/wiki/Hardening-and-Options-Reference#private-network-identity-providers-allowprivatenetworkaddresses"/>.
    /// </remarks>
    public bool AllowPrivateNetworkAddresses { get; set; }

    /// <summary>Gets or sets a value indicating whether the issuer name is not validated.</summary>
    public bool DoNotValidateIssuerName { get; set; }

    /// <summary>Gets or sets a value indicating whether the RFC 9207 response <c>iss</c> parameter is not checked against the id_token issuer.</summary>
    /// <remarks>See <see href="https://github.com/Flowfin/jellyfin-plugin-sso/wiki/Security-Model#openid-authorization-response-issuer-rfc-9207"/>.</remarks>
    public bool DoNotValidateResponseIssuer { get; set; }

    /// <summary>Gets or sets a value indicating whether the UserInfo endpoint is not read.</summary>
    public bool DoNotLoadProfile { get; set; }

    /// <summary>Gets or sets a value indicating whether the server must advertise PKCE with S256 before a login proceeds.</summary>
    /// <remarks>Off by default, where an unsupported server only draws an audit warning. See <see href="https://github.com/Flowfin/jellyfin-plugin-sso/wiki/Security-Model#pkce-downgrade-detection"/>.</remarks>
    public bool RequirePkce { get; set; }
}

/// <summary>Maps one provider role to the libraries it grants.</summary>
public class FolderRoleMap
{
    /// <summary>Gets or sets the role.</summary>
    public string? Role { get; set; }

    /// <summary>Gets or sets the libraries the role grants.</summary>
    public List<string>? Folders { get; set; }
}

/// <summary>A policy written onto a brand-new account at creation and never re-applied; every field is opt-in (#1099).</summary>
public class ProvisioningPolicyTemplate
{
    /// <summary>Gets or sets the boolean permissions written onto a new account, each by its exact <c>PermissionKind</c> name.</summary>
    /// <remarks>
    /// The same vocabulary and refusals as <see cref="PermissionRoleMap.Permission"/>; <c>IsDisabled</c> is refused
    /// because the audited hold is <see cref="ProviderConfigBase.ProvisionNewUsersDisabled"/> (#165).
    /// </remarks>
    [XmlArray("Permissions")]
    [XmlArrayItem(typeof(ProvisionedPermissionEntry), ElementName = "Permissions")]
    public List<ProvisionedPermissionEntry>? Permissions { get; set; }

    /// <summary>Gets or sets the remote-client bitrate ceiling in bits per second; null keeps Jellyfin's default and zero means no limit.</summary>
    public int? RemoteClientBitrateLimit { get; set; }

    /// <summary>Gets or sets the maximum simultaneous sessions; null keeps Jellyfin's default and zero means unlimited.</summary>
    public int? MaxActiveSessions { get; set; }

    /// <summary>Gets or sets the preferred audio language as the code Jellyfin stores (#1100).</summary>
    /// <remarks>The language fields are not checked against a list, because a plugin-side list would drift against what Jellyfin accepts.</remarks>
    public string? AudioLanguagePreference { get; set; }

    /// <summary>Gets or sets the preferred subtitle language as the code Jellyfin stores (#1100).</summary>
    public string? SubtitleLanguagePreference { get; set; }

    /// <summary>Gets or sets the subtitle playback mode by its exact <c>SubtitlePlaybackMode</c> name; an unknown name is refused on save (#1100).</summary>
    public string? SubtitleMode { get; set; }

    /// <summary>Gets or sets a value indicating whether the default audio track is played; null keeps Jellyfin's default (#1100).</summary>
    public bool? PlayDefaultAudioTrack { get; set; }

    /// <summary>Gets or sets a value indicating whether audio selections are remembered; null keeps Jellyfin's default (#1100).</summary>
    public bool? RememberAudioSelections { get; set; }

    /// <summary>Gets or sets a value indicating whether subtitle selections are remembered; null keeps Jellyfin's default (#1100).</summary>
    public bool? RememberSubtitleSelections { get; set; }

    /// <summary>Gets or sets the web client's home-screen sections, top slot first, by exact <c>HomeSectionType</c> name (#1101).</summary>
    /// <remarks>Written into the display-preferences document after the account is persisted, and a failure there never fails the login.</remarks>
    public List<string>? HomeSections { get; set; }
}

/// <summary>One boolean permission a provisioning template writes onto a new account (#1099).</summary>
public class ProvisionedPermissionEntry
{
    /// <summary>Gets or sets the permission by its exact <c>PermissionKind</c> name.</summary>
    public string? Permission { get; set; }

    /// <summary>Gets or sets a value indicating whether the permission is granted; the default revokes, which is the fail-closed direction.</summary>
    public bool Granted { get; set; }
}

/// <summary>Maps one Jellyfin permission to the roles that grant it, default-deny (#164).</summary>
public class PermissionRoleMap
{
    /// <summary>Gets or sets the permission by its exact <c>PermissionKind</c> name; the dedicated permissions are refused on save.</summary>
    public string? Permission { get; set; }

    /// <summary>Gets or sets the roles that grant the permission; a login holding none has it revoked.</summary>
    public string[]? Roles { get; set; }
}

/// <summary>Maps a set of roles to a parental-rating ceiling; the smallest matching score wins (#736).</summary>
public class ParentalRatingRoleMap
{
    /// <summary>Gets or sets the maximum parental-rating score; smaller is more restrictive.</summary>
    public int Score { get; set; }

    /// <summary>Gets or sets the roles the ceiling applies to.</summary>
    public string[]? Roles { get; set; }
}

/// <summary>Maps a set of roles to a SyncPlay access level; the most restrictive matching level wins (#827).</summary>
public class SyncPlayAccessRoleMap
{
    /// <summary>Gets or sets the level as the exact <c>SyncPlayUserAccessType</c> name.</summary>
    /// <remarks>A string rather than the enum, so a mis-set value is reported on save instead of failing the whole document at deserialization.</remarks>
    public string? Access { get; set; }

    /// <summary>Gets or sets the roles the level applies to.</summary>
    public string[]? Roles { get; set; }
}

/// <summary>Maps a set of roles to a fixed access duration for a newly provisioned account; the shortest match wins (#1146).</summary>
public class GuestAccessDurationRoleMap
{
    /// <summary>The largest duration a row may carry, in hours.</summary>
    /// <remarks>A guard rather than a policy: <see cref="DateTime.AddHours"/> throws past <see cref="DateTime.MaxValue"/> on the login path.</remarks>
    public const int MaxDurationHours = 876_000;

    /// <summary>Gets or sets the access duration in hours, counted from the provisioning moment.</summary>
    public int DurationHours { get; set; }

    /// <summary>Gets or sets the roles the duration applies to.</summary>
    public string[]? Roles { get; set; }
}

/// <summary>One row of a provider's ordered role-to-provisioning-profile map (#1106).</summary>
public class ProvisioningProfileRoleMap
{
    /// <summary>Gets or sets the name of the <see cref="PluginConfiguration.ProvisioningProfiles"/> entry a matching login is provisioned from.</summary>
    public string? Profile { get; set; }

    /// <summary>Gets or sets the roles this row applies to.</summary>
    public string[]? Roles { get; set; }
}
