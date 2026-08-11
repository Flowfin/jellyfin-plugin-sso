# Changelog

All notable changes to this plugin are documented here. Versions are three-part
`X.Y.Z` as described in the release policy - **X** a breaking / Jellyfin-ABI
change, **Y** a feature, **Z** a bug-fix or security patch (the two share the
digit and differ by release cadence). The channel and Jellyfin generation are a
suffix on the git tag and GitHub release name only (`-stable`, `-beta.<run>`,
`-JF12-*`), never part of the installed numeric version.

## Unreleased

### Added

- **OpenID providers on a private network (#1058).** A new per-provider option,
  **Allow Private Network Addresses**, lets a provider's backchannel
  (discovery, JWKS, token, userinfo, back-channel logout) reach an identity
  provider that lives on the administrator's own network. Previously the
  outbound SSRF / DNS-rebind guard refused every non-public address with no way
  to say a provider was deliberately internal, so the standard self-hosted shape
  (Authelia or Keycloak on a `10.x`/`192.168.x` address behind a reverse proxy)
  failed discovery with _"The outbound host resolves only to blocked
  addresses"_, and the existing insecure toggles did not help because they relax
  discovery policy rather than the transport. The option is **off by default**
  and scoped to the one provider it is set on: it permits RFC 1918, carrier-grade
  NAT and IPv6 unique-local only, while loopback, link-local and the cloud
  metadata ranges (`169.254.169.254`, `192.0.0.192`) stay blocked regardless.
  Every other provider, the avatar fetch and the SAML metadata importer keep the
  full guard. Enabling it is surfaced as a security downgrade in the config page
  and recorded in the insecure-toggle audit log.
- **OpenID role claims carried as an object map.** A new per-provider option,
  **Role claim is an object map**, reads the roles from the property _names_ of
  a JSON object instead of from a list of strings. Zitadel needs it: it emits
  `{"jellyfin-access": {"<orgId>": "<domain>"}}` under
  `urn:zitadel:iam:org:project:roles`, which no previous configuration could
  read, so its role gate could never be enabled. Only the names are read -
  never the values, never nested objects - and every other claim shape still
  fails closed to no roles. The option is **off by default**, so no existing
  provider changes behaviour.
- **Managed login-page buttons (#722).** An opt-in global option, **Manage
  login-page buttons** (off by default), keeps a "Sign in with …" button block
  on Jellyfin's login page in sync with the configured, enabled providers - so a
  configured provider surfaces a button without hand-crafted branding HTML. The
  managed region is spliced into the login branding disclaimer and removed
  cleanly when the option is turned off, preserving any surrounding admin
  disclaimer text; provider names and labels are HTML-encoded. Per provider,
  **Hide login button** omits one provider's button and **Login button text**
  overrides its label.

### Changed

- **A role claim the plugin could not read now says so in the log (#1149).** A
  mistyped role-claim path and a provider that genuinely sends no roles used to
  look identical from outside: both ended with an empty role set and no entry,
  and under a configured role allow-list both ended with a denied login and
  nothing to explain it. An OpenID login whose role claim could not be read now
  leaves one `[SSO Audit]` warning naming the provider and a fixed reason code -
  the claim value did not parse as JSON, the configured path did not resolve, or
  the node it reached was not the configured shape. A login that carried no role
  claim, or one whose claim resolved to an empty list, leaves nothing, so the
  entry stays a signal rather than appearing on every sign-in. The claim value is
  never part of the entry: a role claim can carry group memberships and other
  personal data, so the provider name and the reason code are all it records.

- **Test connection now says when a provider's document was refused for its
  shape (#1064).** An OpenID document that a provider serves perfectly well can
  still be rejected before it is parsed, because it names the same JSON member
  twice or because its body cannot be inspected as JSON at all. Test connection
  reported both of those under the one message it had, which asks the
  administrator to check that the endpoint is reachable, serves
  `/.well-known/openid-configuration` and is served over HTTPS - all of which
  were already true, so the diagnostic answered confidently and pointed
  somewhere else. The two refusals now have their own messages, worded exactly
  as the matching server-log entry, so an administrator reading the panel and
  the log sees one wording rather than two. Every other read failure keeps the
  message it had. Which member repeated stays in the server log and is not
  echoed into the admin panel.

- **Renamed to "Community SSO for Jellyfin".** The plugin's display name (the
  catalog entry, the dashboard plugin name, and the documentation) is now
  **Community SSO for Jellyfin**. The plugin GUID, the assembly, and the
  configuration are unchanged, so the rename lands as an in-place update that
  keeps every existing setting.

### Security

- **A token minted for one endpoint is no longer read as a token for the other
  (#1317).** Neither JWT the plugin verifies used to have its `typ` header
  looked at, so the only thing separating an id_token from a back-channel
  logout token was the shape of its payload. Measured before the fix: a genuine
  logout token, correctly typed and signed by the provider's own key, validated
  on the login path and produced a user; and a logout token whose header said
  `at+jwt` validated at the logout endpoint. Both entry points now refuse a
  token that declares itself an access token (`at+jwt`), a DPoP proof
  (`dpop+jwt`) or, on the login path, a security event (`secevent+jwt`) or a
  logout token (`logout+jwt`), in every spelling of those media types. Nothing
  a working provider sends is affected: `typ` is optional in an id_token, so a
  token that omits it, sends the generic `JWT`, or sends a vendor value of the
  provider's own is accepted exactly as before. An absent header is not treated
  as a wrong one.

- **A single dropped discovery response no longer cancels a sign-out the
  identity provider ordered (#1183).** On an inbound back-channel logout the
  plugin reads the provider's discovery document to obtain the keys the logout
  token is verified against. That read used to be attempted once, and any
  failure left the sessions the provider had just ended still running, with only
  a log entry to say so. A transient failure is now retried once, within a
  worst case of 21 seconds for the whole request, and only on this path: the
  login redirect and the admin Test-connection button still make exactly one
  attempt, because a failure there creates no session in the first place.
  Nothing is accepted that was not accepted before - when both attempts fail the
  request is still refused, still with the same answer and the same recorded
  reason, and a logout token whose signing keys were never obtained is still
  never acted on. A provider endpoint that is not a usable URL is a
  configuration mistake rather than a transient fault and is not retried.

- **An identity provider can no longer write unbounded log through a failed
  discovery read (#1194).** When a discovery or JWKS fetch failed, the
  fail-closed warning quoted the identity library's error text whole, and that
  text names the URL the fetch was connecting to. On the JWKS leg the provider
  chooses that URL, because its own discovery document named it in `jwks_uri`,
  so a hostile server could put as much text in the log as it liked, once per
  anonymous login challenge, with only the 1 MB response cap in the way.
  Measured before the fix: a document advertising a 200 KB `jwks_uri` produced a
  205,042-character entry from a single read. The quoted text is now cut at 512
  characters with a `[truncated]` marker, so a cut entry cannot be mistaken for
  a whole one, and the endpoint an operator reads the entry to find still
  survives in every ordinary failure.

- **A back-channel logout that did not happen is now its own audit entry.** When
  an identity provider orders a session termination and the plugin cannot reach
  that provider to verify the request, the termination does not happen and the
  signed-out session keeps running. That used to be recorded with the same
  warning as a forged or replayed logout token, which is the opposite situation:
  an attacker blocked, with nothing that was supposed to end. The two are now
  separate entries at separate levels: a refused token stays a warning, while a
  termination that was ordered and not performed is logged as an error naming the
  reason, so it can be alerted on without wading through the rejection noise. The
  same entry covers a validated logout whose token revocation failed. OpenID
  back-channel rejections are also no longer worded as SAML rejections, so a log
  filter for OpenID logout failures finds them. The HTTP response is unchanged:
  every rejection is still the one uniform 400 with nothing that distinguishes
  the branches to the caller.
- **A document that says two things about a user's roles now grants none of
  them.** When a provider's UserInfo response names the role claim twice, the
  two copies reach the plugin as two separate claims, each one clean on its own,
  so the screen that refuses a repeated member inside a claim value never saw
  them. The roles of both copies were merged, which means a second copy naming
  an extra role granted that role. Copies that disagree are now refused
  outright: the login proceeds with no roles rather than with the union.
  Providers that emit the same role claim in both the id_token and the UserInfo
  response are unaffected, because copies that agree still grant, and so is the
  common shape of one claim per group, which is a list written as repeated
  claims rather than two statements about one object.
- **A provider response that names a JSON member twice is refused before it is
  parsed.** A repeated member is accepted silently by every reader these
  documents reach, and none of them raises an error, so which of the two values a
  consumer acts on is decided by parser internals rather than by the document -
  RFC 8259 leaves it unspecified and calls such objects interoperability-unsafe.
  A **successfully served** OpenID discovery document, and the JWKS it names, are
  now screened on the transport, so such a body never reaches the reader that
  would resolve it: the refused document's `jwks_uri` is never requested at all,
  rather than requested and reported afterwards. A document that cannot be
  inspected as JSON - malformed, truncated, nested too deeply, or carrying a
  character set the runtime does not know - is refused the same way. There is no
  size limit here; bounding what the plugin reads from a provider is tracked
  separately. An error response (a 404, a 500) is deliberately not screened and
  keeps its own status, so the log still names what the provider actually
  returned; the plugin uses no value out of such a body.

  Note for operators. A provider whose discovery or JWKS document repeats **any**
  member name inside one object will now fail to sign users in, where previously
  the repeat was resolved silently, and no configuration overrides that. The
  server log records which of the two documents was refused, why, and which
  member name was repeated, so the entry says what to report to the provider.
  That name is the provider's to choose, so at most 128 characters of it are
  recorded, marked `[truncated]` when it is cut, and control characters, Unicode
  format characters and the line and paragraph separators are removed from it
  first. A line-ending strip alone removes none of the first two, and each of
  those classes can split, truncate, reorder or corrupt the entry it lands in.
  Twenty discovery and JWKS documents from ten widely used hosted providers were
  checked and none repeats a member; that sample is hosted providers rather than
  the self-hosted identity servers many installations run, so it bounds the risk
  without eliminating it.

  Two consequences worth knowing. The same refusal on the back-channel logout
  path leaves the session untouched rather than ending it - the behaviour any
  unreadable discovery document already had, unchanged here and tracked
  separately. And the admin **Test connection** button does not yet name this as
  a cause, so a refused document currently shows there under a check that does not
  describe it.

- **A token whose JWS header marks an extension critical is refused (#1038).**
  RFC 7515 §4.1.11 requires a recipient to reject a token whose `crit` header
  names an extension it does not understand and process. The plugin implements
  no JWS extension, and the token library ignores `crit` entirely, so a
  genuinely signed `id_token` or back-channel `logout_token` carrying one was
  accepted with the constraint it declared silently dropped - an extension is
  marked critical precisely because ignoring it changes what the token asserts,
  such as a narrowed audience or a proof-of-possession binding. Both token paths
  now refuse such a token from one shared rule, so they cannot drift apart.

  This was not exploitable on its own: the token still had to carry a signature
  from a key the provider's own JWKS advertises, so nobody could mint one. What
  changes is that a provider using a JWS extension the plugin cannot honour now
  gets a refusal rather than a login granted on terms the plugin never applied.
  The back-channel refusal carries its own reason code
  (`unprocessed_critical_header`) rather than the generic signature failure, so
  an operator can tell a provider that needs a feature apart from an attempted
  forgery.

## 4.3.0

A feature release. This line advances the plugin's maturity to **Beta** on the
back of a large login-hardening and code-quality pass: SSO-only login
enforcement, full role-based access control, a redesigned configuration UI, and
a broad security + perfection audit.

### Added

- **SSO-only login enforcement (#165).** An optional mode that closes the
  built-in username/password door so accounts authenticate only through the
  configured SSO provider. It is fail-closed by construction: activation is
  refused unless a designated, enabled break-glass administrator keeps a working
  password login, so no reachable configuration can strand the last admin. The
  per-login enforcement and the enable sweep agree on which accounts are moved,
  and the mode is fully reversible on disable.
- **Full role-based access control (#164).** Providers can map identity-provider
  roles to Jellyfin permissions through a generic permission-role mapping,
  validated fail-closed at save so a malformed mapping is rejected at the door
  rather than silently granting nothing at login.
- **Redesigned configuration UI (#697).** The admin settings page was reworked
  into clearer, native accordion sections.

### Changed

- **The self-service linking and auth-completion pages were polished
  (#666, #667, #669).** The linking page renders a proper help label and an
  empty-state placeholder instead of bare headings; the auth-completion status
  line is an `aria-live` region that announces failures to assistive tech and
  now offers a "Return to login" link instead of dead-ending.
- **Browser-navigated login errors are now styled (#668).** A rejection reached
  by direct navigation (the OpenID/SAML challenge and callback routes) is
  rendered as a themed HTML page with a return link and a strict
  Content-Security-Policy, instead of raw plain text on what looked like a broken
  page. The uniform denial message was reworded to be actionable without
  enumerating.
- **Internal consolidation (#670, #671, #695).** The duplicated challenge
  redirect-path resolver and a single-caller OpenID wrapper were unified, and the
  provider-config validation doc was corrected to describe the single source of
  truth - no behavioural change, locked in by conformance tests.

### Security

- **SAML parsing hardened (#698).**
- **SAML `DoNotValidateAudience` is now audited (#672).** Enabling this default-on
  protection's escape hatch leaves an `[SSO Audit]` trail on save and import, at
  parity with the OpenID insecure toggles.
- **Rate-limit endpoint-class bucket keys are typed (#694).** The per-client
  limiter keys are named constants rather than bare string literals, so a typo
  can no longer silently split a security budget; a conformance test forbids
  regressions.
- **SSO-only no longer strips a third-party provider account's login path (#690).**
- **The OpenID authorize-state store is keyed on UTC (#696), and role-privilege
  mapping guards null folder sets (#693).**

## 4.2.1

A bug-fix release.

### Fixed

- **Admin-or-self authorization now denies explicitly on a null auth context
  (#626).** `RequestHelpers.AssertCanUpdateUser` previously failed closed by
  throwing a `NullReferenceException` (which could surface as a 500) on a null
  or ambiguous authorization context. It now returns an explicit `false` - a
  clean, total deny. Normal authenticated requests are unaffected; the fix
  removes a fragile reliance on an exception for a security-critical denial and
  eliminates the internal-error surface. A masked test that had tolerated the
  old exception was corrected to assert the explicit deny.

## 4.2.0

A breaking release.

### Removed

- **`SAML/Auth` no longer accepts a raw SAML assertion (BREAKING, #528).** #251
  replaced the assertion browser round-trip with a one-time, server-side login
  outcome token: the assertion-consumer callback (`SAML/post`) validates the
  signed assertion once and hands the intermediate page only an opaque token,
  and `SAML/Auth` redeems that token to mint the session without re-parsing the
  assertion. For one release `SAML/Auth` also still accepted and fully
  re-validated the pre-#251 shape - a full base64 assertion POSTed straight to
  it - so a login already in flight during an upgrade would not break. That
  deprecation window has now closed: `SAML/Auth` accepts **only** the opaque
  outcome token. A scripted client that POSTs a raw assertion straight to
  `SAML/Auth`, bypassing the rendered page, is now rejected fail-closed (a clean
  400 in the uniform SAML body, nothing minted). The normal browser login and
  linking flows are unaffected - the plugin has rendered only tokens for login
  since #251. Callers that scripted the legacy direct-assertion POST must switch
  to the callback-plus-token round-trip.

## 4.1.1

A bug-fix release that restores plugin loading on Jellyfin 10.11. No
configuration changes.

### Fixed

- **The plugin no longer fails to load on Jellyfin 10.11 (#590).** 4.1.0.0
  shipped with `Duende.IdentityModel.OidcClient` 7.x, whose assemblies are built
  against the .NET 10 framework and reference
  `Microsoft.Extensions.Logging.Abstractions` 10.0.0.0 in their manifest - an
  assembly the host provides (Jellyfin 10.11 runs on .NET 9 and ships 9.0.0.0)
  and the plugin therefore does not bundle. Because .NET rolls a host assembly
  reference forward to a newer host but never down a major version, the packaged
  plugin threw `FileNotFoundException` the moment the host constructed it, and
  the server disabled it at startup - taking down every OpenID and SAML login.
  `dotnet build` and `dotnet test` stayed green because they run against the full
  publish output, which contains the 10.x assembly; the failure only surfaced on
  a real host, the same blind spot the SAML/OIDC crypto DLLs hit in 4.1.0.0.

  The OIDC client is pinned back to the 6.x line, which references
  `Logging.Abstractions` 8.0.0.0 and rolls forward onto the host's 9.0.0.0
  cleanly; the whole dependency graph stays on the .NET 9 ABI. No behaviour
  changes - the OpenID and SAML flows are identical to 4.1.0.0.

### Added

- **A conformance test locks the ABI floor in.**
  `ArchitectureConformanceTests.HostProvidedFrameworkAssemblies_StayOnTheHostNet9Abi`
  fails the build if any host-provided `Microsoft.Extensions.*` assembly is
  referenced above the .NET 9 host ABI, so a future dependency bump that
  re-crosses the floor is caught before release instead of in the field.

## 4.1.0

The first feature release of the revived plugin. It folds in a full
security-parity pass over the SAML and OpenID login path, encrypts provider
secrets at rest, adds outgoing SAML request signing, exposes the previously
config-only provider flags in the admin UI, and lands a large internal rework
that decomposes the login controller into small, testable services.

### Breaking

- **Provider secrets are now encrypted at rest (#158).** Client secrets and
  signing keys are stored as an AES-256-GCM envelope (`ssoenc:` values) instead
  of plaintext. **Upgrading is transparent** - an existing plaintext config is
  read as-is and re-encrypted on the next save, no action required.
  **Downgrading is breaking:** an older plugin build cannot read `ssoenc:`
  values. Before rolling back, open each provider on the settings page and
  re-enter its secret in plaintext (or restore the pre-upgrade config backup),
  then install the older build. See
  [Secrets encrypted at rest and downgrade](https://github.com/iderex/jellyfin-plugin-sso/wiki/Provider-Setup#secrets-encrypted-at-rest-and-downgrade).
- **OpenID logins that relied on legacy username matching are refused until you
  migrate (#358).** Links created by 4.0.0.4 and earlier are keyed on the
  username, which the IdP controls. After upgrade, a login carrying such a
  legacy link is not followed automatically - the account is adopted only when
  the provider has `AllowExistingAccountLink` enabled (treat this as a short,
  supervised maintenance window, not a standing setting), or when an admin links
  the account explicitly via `AddCanonicalLink`. A returning administrator with
  a pre-existing legacy link must be linked by an admin; self-migration is
  refused for admins even with the flag on. Plan this before upgrading - see the
  migration runbook under
  [OpenID Connect id_token requirements](https://github.com/iderex/jellyfin-plugin-sso/wiki/Provider-Setup#openid-connect-id_token-requirements)
  and the
  [Security Model](https://github.com/iderex/jellyfin-plugin-sso/wiki/Security-Model)
  wiki page.

### Security

The login path was hardened end to end and now fails closed by default.

- **SAML:** XXE-safe XML loading, strict single-assertion conformance, a signed
  algorithm allowlist (SHA-1 and other weak algorithms rejected), replay
  protection with a bounded cache, and enforced time-bound, audience, and
  recipient checks.
- **OpenID Connect:** PKCE S256, `state`, and `iss` / RFC 9207 response
  validation, all sourced from the login's own discovery document rather than
  trusting request-supplied facts; full `id_token` validation; and a verified-
  email gate for account login and adoption.
- **Account linking:** OpenID links are bound to the IdP issuer (#186) and to
  the stable `sub` / `NameID`, so a renamed or re-pointed account cannot be
  silently taken over.
- **Abuse resistance:** rate limiting across the login, link/unlink, and
  unregister endpoints; active session/token revocation when a user is
  unregistered or their last link is removed; and provider-name validation that
  rejects control characters.
- **Transport and supply chain:** security response headers / CSP on the plugin
  pages, SSRF-guarded avatar fetches, and a Trojan-Source (unicode) guard in CI.

### Features

- **Outgoing SAML AuthnRequest signing (#167),** including ECDSA signing keys
  (#493) alongside RSA, for IdPs that require signed requests.
- **Admin-UI toggles for provider flags** that were previously config-file only
  (for example `AllowExistingAccountLink` and the verified-email requirement),
  plus a real device name on linked sessions.
- **Provider-name hardening** so invalid names are rejected at configuration
  time.

### Architecture / internal

- The monolithic `SSOController` was decomposed into a thin controller over pure,
  single-responsibility helpers and `Api/Flows/*Service` login services (#318),
  with a fail-closed `VerifiedIdentity` keystone. Structural rules are locked in
  as architecture-conformance tests that run in CI. This is an internal change
  with no user-facing configuration impact.

### Fixes

- Login rejections consistently return their intended status codes and never
  surface as HTTP 500.
- Corrected avatar handling (missing-file self-heal, file-extension and path
  handling) and disabled-provider handling across the login and linking flows.
- Numerous smaller robustness fixes in state handling, session minting, and the
  admin/linking pages.
