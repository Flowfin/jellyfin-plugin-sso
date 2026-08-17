# Changelog

All notable changes to this plugin are documented here. Versions are three-part
`X.Y.Z` as described in the release policy - **X** a breaking / Jellyfin-ABI
change, **Y** a feature, **Z** a bug-fix or security patch (the two share the
digit and differ by release cadence). The channel and Jellyfin generation are a
suffix on the git tag and GitHub release name only (`-stable`, `-beta.<run>`,
`-JF12-*`), never part of the installed numeric version.

## Unreleased

### Added

- **The account-link roster now reports the last SSO login (#1120).** Each link
  in the roster carries the moment a login last signed in through it, so an
  administrator can tell a live link from one nobody has used. Nothing is added
  to the log: the plugin keeps one timestamp per link that already exists,
  overwritten by the next login rather than appended to, and it is removed the
  moment the link is - by unlinking, by removing an account's links from the
  dashboard, and by deleting or repointing the provider. The stored value is
  deliberately coarse. It is rewritten only once it is more than an hour old, so
  signing in repeatedly costs no write to the plugin configuration, and the
  roster reports "not later than" rather than a precise instant. A link nobody
  has used since this version, or one made before it, reports nothing at all
  instead of a made-up date. The value is withheld from the configuration page
  in both directions: it cannot be read back through it, and a settings save can
  neither clear it nor invent one. It is not part of the portable link export
  either, because a login instant belongs to the server that observed it and
  cannot be restored onto another.
- **A per-provider starting policy for accounts SSO creates (#1099).** A
  provider can carry a template whose set fields are written onto a brand-new
  SSO account at creation: any of the boolean Jellyfin permissions, a
  remote-client bitrate ceiling, and a maximum session count. It is written
  once, at creation, and never re-applied, so a change you make on the user
  afterwards survives every later login. That is the difference from the
  role-to-permission mappings, which are re-asserted on every login on purpose.
  Opt-in field by field: anything the template does not name is left at
  Jellyfin's own default, and a provider with no template creates accounts
  exactly as before. A template cannot grant administrator, all-folders or Live
  TV access, which keep their own dedicated settings, and it cannot disable an
  account; those names are refused when you save, and refused again when the
  template is written, so a configuration file edited by hand cannot use one
  either. A negative bitrate or session count is refused at save rather than
  quietly changed. Zero means no limit and unlimited, as it does elsewhere in
  Jellyfin. The template is set in the plugin configuration; the provider forms
  in the dashboard do not carry it yet.
- **The starting policy can also seed playback preferences (#1100).** The same
  per-provider template now carries the language and playback block: preferred
  audio language, preferred subtitle language, subtitle mode, whether the
  default audio track plays, and whether audio and subtitle selections are
  remembered. It behaves exactly like the rest of the template. Each field is
  opt-in, anything left unset stays at Jellyfin's own default, and the values are
  written once when the account is created and never re-applied, so a preference
  you or the user change afterwards survives every later login. Clearing one of
  the three switches is a real setting rather than an absent one, so a template
  can turn it off and have it stick. The subtitle mode is the one field with a
  fixed vocabulary: an unrecognised name is refused when you save, naming the
  modes Jellyfin accepts, and refused again when the template is written, so a
  configuration file edited by hand cannot slip one through and leave an account
  on a mode nobody chose. The two language fields are passed to Jellyfin as given
  rather than checked against a list, so any code Jellyfin accepts works. As with
  the rest of the template, these are set in the plugin configuration and the
  provider forms in the dashboard do not carry them yet.
- **A guest or trial group can carry a fixed access duration (#1146).** A
  provider can map identity-provider roles to a length of access in hours, and
  an account created by a login holding one of those roles is given a deadline
  of that moment plus the mapped duration. It is the second way into the expiry
  machinery: the claim below is the provider naming a date, this one is you
  naming a length, which is what a guest or trial group usually needs. The
  deadline is stamped once, when the account is created, and a later login by
  the same account leaves it exactly where it is, so a trial does not quietly
  become unlimited access for anyone who keeps signing in. A login holding two
  mapped roles takes the shorter of the two. Where a login carries both a mapped
  role and an expiry claim, the claim wins, because the provider is the
  authority on a date it emitted. Only a newly created account is given a
  deadline: an SSO login that takes over an existing Jellyfin account is not,
  and losing the role later neither extends nor clears a deadline already
  recorded. Nothing changes for a provider that maps no role, which is every
  provider by default. A duration of zero or less is refused when you save, as
  is one longer than a century, and so is a mapping that lists no roles. The
  mappings are set in the plugin configuration; the provider forms in the
  dashboard do not carry them yet.
- **Account expiry now ends access on the deadline rather than at the next
  login (#1145).** The instant a login carries is persisted against that
  account's SSO link, and an hourly background pass disables any linked account
  whose deadline has gone by and revokes that account's tokens. Until now the
  deadline was only checked when the expired user came back, so a guest who
  simply stopped logging in kept an enabled account, any long-lived token and,
  with password login still on, a password door, for as long as those happened
  to last. The deadline is stored in the plugin configuration, so it survives a
  restart, and a settings save can neither clear it nor set one. Nothing changes
  for a provider that names no expiry claim, which is every provider by default.
  An administrator is never disabled by this pass, exactly as on the login path:
  a provider that starts emitting a past instant reaches every account at once,
  and someone has to be left who can open the settings page. A provider you
  switch off is skipped rather than swept, and an account already disabled is
  left alone rather than logged again on every pass.
- **An account-expiry instant read from a provider claim (#1143).** A provider
  can name a claim (OpenID) or assertion attribute (SAML) that carries the
  instant its account access ends, and both protocols now read it onto the
  verified identity as a UTC timestamp. It is read and carried, nothing more:
  no login is refused, no account is disabled, and a provider that names no
  claim behaves exactly as before, which is every provider by default. The
  value is accepted as a JWT `NumericDate` or an ISO-8601 timestamp with or
  without an offset, and an offset-less value is read as UTC rather than as the
  server's local time. A claim that is absent, or whose value is neither shape,
  carries no instant instead of failing the login. For OpenID the name may be a
  dotted path into the claim's JSON, the same convention the role claim uses.
  The field is settable in the plugin configuration; the provider forms in the
  dashboard do not carry it yet.
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
- **Every release now carries an OpenVEX document (#1093).** `openvex.json` and
  its `openvex.sha256` ship as release assets beside `sbom.cyclonedx.json` on
  all four release legs, so a scanner that flags an advisory in a transitive
  dependency can read the recorded disposition for it instead of guessing. Only
  the plugin zip still carries an `.md5`, which is what keeps the manifest
  checksum paired with the build it belongs to.
- **An export of one account's SSO linkages (#1091).** A new administrator-only
  endpoint, `GET /SSO/Links/Export/{jellyfinUserId}`, returns every OpenID and
  SAML linkage held for one Jellyfin account in a single document, in the same
  shape the whole-table export already produces. Answering an access request
  previously meant either two calls per protocol against the per-user listings
  or exporting the whole link table and redacting every other account by hand.
  The document names the account by username rather than by its internal id and
  carries no provider secret, signing key or token; an account that exists but
  holds no linkage exports an empty document, which is a different answer from
  the 404 an unknown id returns. The endpoint is rate-limited under a budget of
  its own, so an administrator session cannot be used to walk the user table one
  id at a time, and the throttle is applied before the account lookup so the
  404 cannot be used to test for an account either.
- **A linked-account roster for administrators (#1119).** A new
  administrator-only endpoint, `GET /SSO/Links/Roster`, lists every Jellyfin
  account that holds an SSO link, with the provider and canonical name behind
  each one, in a single read. Finding out _which_ accounts were linked
  previously meant walking the whole Jellyfin user list and asking the per-user
  listings one request at a time. An account linked to several providers is one
  row carrying several links, and a link whose account has since been deleted is
  reported as an orphan rather than dropped, which is the one place that state is
  visible at all. The roster is assembled from the link maps alone, so no
  provider secret, signing key or certificate can appear in it.

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

### Fixed

- **A second, unremovable set of sign-in buttons on the login page (#1344).**
  The plugin fences the buttons it manages inside the login disclaimer with a
  marker comment, and finds that region again by an exact search on the next
  sync. The opening marker's wording changed in an earlier release, so on any
  server whose disclaimer already held the previous wording the plugin stopped
  recognising its own region: it added a second set of buttons beside the first,
  and nothing it could do afterwards removed the first. Turning the buttons off
  removed only the newer set and left the older one behind, so the duplicate
  outlived the feature that created it and only a hand edit of the disclaimer
  cleared it. The region is now recognised by the stable
  `<!-- SSO-LOGIN-BUTTONS:BEGIN` token alone, and the wording that follows it is
  no longer read, so a server holding either wording converges to exactly one
  managed set on its next sync and to none when the buttons are turned off -
  including a server already left holding two. An admin's own disclaimer text,
  before, between and after the managed regions, is preserved as it always was.
  A future edit to that wording can no longer orphan anything.

### Security

- **A back-channel logout token can no longer break the check that decides
  whether it is one (#1349).** The plugin looks for a fixed member in a logout
  token's `events` claim, and found it with the same call #1340 took out of the
  discovery readers: one that decodes every candidate member name long enough to
  still match, where a name written with an unpaired surrogate escape has no
  decoding. A token whose `events` object named only such a member raised an
  error out of the validator instead of being refused, so the uniform response
  the endpoint answers every unusable token with was not sent and the rejection
  never reached the audit trail. The member is now looked up through the same
  walk that skips a name it cannot decode and keeps going: such a token is
  refused as not a logout token, with that reason recorded, and a token carrying
  the real member beside an undecodable one is still recognised and still ends
  the session it names. Reaching this needed a token that had already passed
  signature, issuer, audience and lifetime validation, so it was never a way in
  for a caller without the provider's signing key.

- **A discovery document can no longer break both of the plugin's discovery
  checks with a member name it never had to look at (#1340).** The two readers
  that decide whether a provider advertises PKCE `S256` and the RFC 9207
  response `iss` parameter both looked their member up with a call that decodes
  every candidate name long enough to still match. A name written with an
  unpaired surrogate escape has no decoding, so the lookup raised an error
  instead of answering, and which of the two readers it hit depended only on how
  long that unrelated name was. Both facts are now read through one lookup that
  skips a name it cannot decode and keeps going, so a provider that does
  advertise `S256` beside such a name still reads as advertising it, rather than
  having every login under **Require PKCE** refused. Both answers are otherwise
  unchanged, each still failing in the direction it is documented to: PKCE
  support closed, the response `iss` flag tolerant. No login on the shipped
  configuration reached this - the repeated-member screen already reports such a
  body unreadable before either reader sees it - and the two documents that
  reach it join the fuzz corpus so the smoke gate replays them.

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
