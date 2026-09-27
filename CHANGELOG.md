# Changelog

Versions are three-part `X.Y.Z` per the release policy - **X** a breaking or
Jellyfin-ABI change, **Y** a feature, **Z** a bug-fix or security patch. The
channel and Jellyfin generation are a suffix on the tag and release name only.

An entry is two or three sentences: what changed, the setting or route and its
default, and the issue that holds the rest. The depth lives in the issue, the
pull request and the wiki.

## Unreleased

### Changed

- **The PR-hygiene gate caps the commit subject at 72 characters, the commit
  body at 25 lines and the pull-request body at 200 words outside one fenced
  block (#1900).** Each cap is refused by name; bots and merge commits are exempt.
- **Every CHANGELOG entry is two or three sentences, and CONTRIBUTING carries
  the rule (#1897).** The long form is unchanged in git and in the pull requests.

### Fixed

- **Removing the last SSO link says the sign-out happened instead of reporting a
  failure (#1882).** The removal revokes every token, so the reloaded page had no
  session and drew the generic banner for a removal that had worked; the page now
  reads that 401 and says the link is gone and this sign-in has ended.

### Security

- **A refused OpenID login no longer writes the person's profile into the server
  log (#1881).** The role gate's warning printed every claim with its value, so
  each refused attempt logged a display name, username and e-mail address. Every
  type is still listed; only the role claim and `sub` keep their values.

## 5.1.1

A feature release, and the first stable release of the 5.1 line. It is numbered
5.1.1 because a release is offered to a server on a beta only where it outranks
every beta of its line (#1841). The Jellyfin 10.11 / .NET 9 leg is retired,
ending support for the 4.x line (#1770).

**Not verified for this release, by decision** (decided on #1879 on
2026-09-27): the SAML login against a real identity provider, the Quick Connect
round trips on Android and Android TV, reverse-proxy forwarded-header
attribution, and an upgrade over an existing install. The OpenID login and the
browser items were walked during the soak, recorded on #1879.

### Added

- **A provider can leave alone the folders its configuration does not manage
  (#1846).** Every login rewrote the folder list from the role mapping; the new
  `PreserveUnmanagedFolders`, off by default, writes the current folders minus
  the managed set plus the grants instead.
- **The RP-initiated OpenID logout accepts a one-time ticket, so a client never
  has to put an access token in a URL (#1768).** `POST OID/logout-ticket/{provider}`
  mints one bound to that caller, valid for a minute and redeemable once. **Read
  before upgrading:** `GET OID/logout/{provider}` refuses in the method, not under
  `[Authorize]`, so it is anonymously reachable.

### Changed

- **The OpenID endpoint's help names the issuer (#1836).** The field is the
  issuer rather than a base address, because the plugin appends the well-known
  path to it, and both catalogues carry the new text.
- **The credential-less refusals of the RP-initiated OpenID logout write a
  bounded number of audit lines, on any configuration (#1792).** The first ten in
  a minute are recorded one by one and the rest counted into one line, on a
  `logout-refusal` rate-limit class of their own.
- **The logout-ticket mint answers 503 only where a retry can clear it (#1796).**
  A caller a ticket cannot be bound to gets `401` and a request naming no
  provider `400`, and only the capacity ceiling keeps its `503`.
- **An avatar served by an OpenID provider on the administrator's own network is
  fetched when that provider has Allow Private Network Addresses set (#1764).**
  The avatar earns the private tier where the opt-in is set and the URL's origin
  is exactly that provider's discovery, token or userinfo origin.
- **The Jellyfin 10.11 / .NET 9 leg is retired; this line builds one target,
  net10.0, for Jellyfin 12 (#1770).** This ends support for the 4.x line, with no
  advance notice and no six months of security fixes, which `SECURITY.md` now
  says. A 10.11 server keeps 4.3.0, since the manifests cover every release.

### Fixed

- **A server on a beta build is offered the release of its own line (#1841).**
  The stable channel carried 5.0.0.0 while the beta channel carried 5.0.0.88, so
  every release is now carried into the beta channel too and one that does not
  outrank its line's betas is refused before it is created.
- **A discovery document whose issuer the endpoint refuses is logged with both
  values (#1835).** The warning quoted the library's text, which names one value
  and not which it is; it now names the configured endpoint and the published
  issuer on lines of their own.
- **Test Connection reports an issuer mismatch as its own result, with both
  values (#1837).** It came back under the reachability message, which was true
  and not the cause; the probe now says the document was read, that its issuer is
  not the configured endpoint, and lists both.
- **An administrator refusal names the two ways to link that account (#1765).**
  The log said "link it explicitly via the admin endpoints", which names a
  category rather than a route; both refusals now name the self-service page and
  the account-management API.
- **The refused-login line follows the code the provider returned (#1763).** The
  line always ended by naming the redirect URI, which is wrong advice for a
  client the provider refused with 401, so the closing sentence now follows what
  came back and interprets nothing where it cannot.
- **A provider address that does not answer no longer uses up the whole request,
  and a failed connect says what the address guard skipped (#1760).** Each
  attempt is bounded at five seconds, and a failed connect counts the refused
  addresses and names **Allow Private Network Addresses** with its reach.

## 5.0.0

A feature release, and the first stable release of the Jellyfin 12 line. It
advances the plugin's maturity to **Full Release** on the back of the rebuilt
settings pages, provisioning profiles, the account-link roster, sign-in
counters, declarative providers and the self-lockout guards.

**Not verified for this release, by decision** (decided on #1729 on 2026-09-16):
reverse-proxy forwarded-header attribution, and an upgrade over an existing
install. The native-client round trips were walked on iPhone and Apple TV and
not on the Android pair, and the pairwise phase checked no pair, so its green
conclusion is not co-existence evidence (#1773). Verified: the seven-provider
matrix on Jellyfin 12.0, the canonical provider on 12.1, and five and a half
days of soak, closed early by decision on 2026-09-21.

### Added

- **A login refused by the provider's role allow-list now reaches a notification
  destination (#1142).** Both protocols publish Jellyfin's own
  authentication-failed event at that refusal, carrying the provider and a fixed
  reason and nothing that names the person.
- **A way back from a link import that restored the wrong document (#1519).**
  `DELETE /sso/{mode}/Links/{provider}/{expectedLinkCount}` removes every
  canonical link one provider holds, which makes a re-import possible. It refuses
  a call written against a stale page, or one leaving an administrator no way in.
- **An unreadable `SSO-Auth.xml` is kept, announced, and refused rather than
  quietly replaced (#1543).** Jellyfin writes a default configuration over a file
  it cannot deserialize, costing every provider, link and secret. The plugin now
  copies it aside once per incident and answers every sign-in with 503.
- **A starting policy can seed the home screen (#1101).** The provisioning
  template gains a **Home screen sections** list, written whole and once at
  account creation, for the web client only.
- **Named provisioning profiles are editable from the dashboard (#1105).** The
  configuration page carries a **Provisioning Profiles** section and each
  provider form a selector. Deleting a profile something still names is refused,
  and renaming repoints every reference in the same save.
- **The starting policy is on the provider forms (#1367).** Both forms carry what
  a provider writes onto a brand-new account, with three states per control so
  one you leave alone sends nothing and Jellyfin's default governs.
- **The dashboard shows who is linked, and can cut one account off (#1121).** A
  Linked Accounts panel lists every account holding a link with its provider,
  subject and last sign-in, and each row offers a revoke that ends every session.
  An orphaned link is shown without a revoke button.
- **A group can decide who may start a SyncPlay session (#827).** A provider can
  map its roles onto the account's SyncPlay access, re-asserted at every sign-in
  and under the same `EnableAuthorization` switch as every other grant. Where a
  login holds several mapped groups the strictest wins.
- **One action checks every configured provider at once (#1084).** A
  "Configuration check" section answers, for every provider, whether a login
  would get past the configuration, using the same judgement a save is refused
  by. It contacts no identity provider, which is what Test Connection is for.
- **A provisioning policy can be named once and shared by several providers
  (#1105).** A provider says which named profile its new accounts get, and one
  naming none keeps its inline template exactly as before. A name that stops
  resolving writes no policy rather than falling back.
- **A provider can pick which provisioning profile a new account gets from the
  login's own roles (#1106).** An ordered list of role-to-profile rows resolves
  first-row-wins, then the named profile, then the inline template, then nothing.
  A row whose profile stops resolving writes no policy rather than the wider one.
- **Counters for the sign-in path, on a metrics endpoint an operator can scrape
  (#1139).** `GET /SSO/Metrics` publishes sign-ins, refusals by reason, account
  creations, rate-limiter rejections and failed fetches in the Prometheus format,
  every counter present even at zero. It needs administrator rights and names no
  person.
- **Providers can be declared entirely in environment variables (#1097).** A
  variable names a path into the configuration with `__` between the steps, so
  every field of a provider is settable under its own name. One the plugin cannot
  place refuses the whole environment and changes nothing.
- **The account-link roster now reports the last SSO login (#1120).** One
  timestamp per link, rewritten only once it is more than an hour old and removed
  with the link, so the roster reports "not later than" rather than an instant.
  It is withheld from the configuration page in both directions.
- **Jellyfin accounts can follow a rename at the identity provider (#1138).**
  **Follow Username Renames From The Provider**, off by default, renames a linked
  account at the next login when the provider's username changed. It is the
  display name only, and each rename is audited with both names.
- **A per-provider starting policy for accounts SSO creates (#1099).** A template
  whose set fields are written onto a brand-new account at creation and never
  re-applied. It is opt-in field by field and cannot grant administrator,
  all-folders or Live TV access or disable an account.
- **The starting policy can also seed playback preferences (#1100).** The same
  template carries the two language fields, the subtitle mode and the three
  playback switches, each opt-in and written once. The subtitle mode has a fixed
  vocabulary refused at save and again at write.
- **A guest or trial group can carry a fixed access duration (#1146).** A
  provider can map roles to a length of access in hours, stamped once when the
  account is created, so a trial does not become unlimited access. Two mapped
  roles take the shorter, and an expiry claim wins over a mapped role.
- **Account expiry now ends access on the deadline rather than at the next login
  (#1145).** An hourly pass disables any linked account whose deadline has gone
  by and revokes its tokens. An administrator is never disabled by this pass and
  a switched-off provider is skipped.
- **An account-expiry instant read from a provider claim (#1143).** A provider can
  name a claim or attribute carrying the instant its access ends, and both
  protocols read it as a UTC timestamp. It is read and carried and nothing more:
  no login is refused and no account disabled.
- **OpenID providers on a private network (#1058).** **Allow Private Network
  Addresses**, off by default and per provider, lets that provider's backchannel
  reach a provider on the administrator's own network. Loopback, link-local and
  the metadata ranges stay blocked, and the opt-in is audited as a downgrade.
- **OpenID role claims carried as an object map.** **Role claim is an object
  map**, off by default, reads roles from the property names of a JSON object
  instead of a list of strings, which is what Zitadel emits. Every other claim
  shape still fails closed to no roles.
- **Managed login-page buttons (#722).** **Manage login-page buttons**, off by
  default, keeps a "Sign in with …" block on the login page in sync with the
  enabled providers and removes it cleanly when turned off. Per provider, **Hide
  login button** omits one and **Login button text** overrides its label.
- **Every release now carries an OpenVEX document (#1093).** `openvex.json` and
  its `openvex.sha256` ship beside `sbom.cyclonedx.json` on all four release
  legs. Only the plugin zip still carries an `.md5`, which keeps the manifest
  checksum paired with its build.
- **An export of one account's SSO linkages (#1091).**
  `GET /SSO/Links/Export/{jellyfinUserId}` returns every linkage held for one
  account, which an access request used to need several calls for. It carries no
  secret and is rate-limited before the account lookup.
- **A linked-account roster for administrators (#1119).** `GET /SSO/Links/Roster`
  lists every account holding a link with the provider and canonical name behind
  each, in one read. A link whose account was deleted is reported as an orphan
  rather than dropped.
- **An account can be linked to an identity before its first login (#1133).** An
  administrator-only endpoint writes the link from a subject to an existing
  account, so an account created by an invite tool signs in through SSO the first
  time. A subject already linked elsewhere is refused, and every link is audited.

### Changed

- **A failed release call no longer throws away the build behind it (#1736).**
  Building and publishing are two jobs, so re-running a failed publish releases
  the package already built, under the same version. A failure after the release
  is published still meets a sealed release on the second attempt.
- **This line is 5.0, because the Jellyfin generation under it changed (#1579).**
  Jellyfin 12.0 went GA on 2026-09-07 and plugins built for 10.11 do not load on
  it, which is what **X** is reserved for, so what was numbered 4.4 is 5.0. 4.3
  stays the last release for Jellyfin 10.11.
- **The settings page is five pages (#1527).** One 222 KB page carrying all 123
  controls became **Overview**, **Providers**, **Accounts**, **Policies** and
  **Server**, every control keeping its id and save path. Overview is new and
  holds no setting, and the bookmarked address still opens the plugin.
- **One Save on the Server page, an unsaved-changes indicator, and the outcome
  where the button is (#1572).** One Save reads and posts the document once and
  writes only the switches you moved, so a refusal leaves both as stored. The
  thirteen modal alerts are gone, each outcome written beside the button.
- **The login audit line now names the Jellyfin account, and the
  provider-presented name beside it where the two differ (#1551).** The line
  carried the presented name, which is not always the resolved account. **A parser
  reading that field now gets the account's name.**
- **Restoring an account-link backup now says how many links it restored
  (#1520).** The route answered the same empty `204` whether it rebound every link
  or none, which is how #1517 went unnoticed. It now answers `200` with a total
  and a breakdown, so **an integration asserting on `204` has to accept `200`**.
- **A misspelled protocol segment on a link route now answers 400 (#1399).** A
  value that was neither `oid` nor `saml` used to throw, so the caller saw
  whatever the server made of it; all three routes now answer `400` with a fixed
  sentence and never repeat what was sent.
- **The redirect URI on the settings page now comes from the server (#1303).**
  The page composed the value in the browser, so a disagreement failed at the
  provider rather than here; the field now shows what the server answers, which
  costs the preview for an unsaved provider.
- **A role claim the plugin could not read now says so in the log (#1149).** A
  mistyped path and a provider that sends no roles used to look identical, so an
  unreadable claim now leaves one `[SSO Audit]` warning naming the provider and a
  reason code, never the claim value.
- **Test connection now says when a provider's document was refused for its shape
  (#1064).** A document that repeats a JSON member, or that cannot be inspected
  as JSON, was reported under the reachability message; the two refusals now have
  their own messages, worded as the matching log entry.
- **Renamed to "Community SSO for Jellyfin".** The display name in the catalog,
  the dashboard and the documentation changed while the GUID, the assembly and
  the configuration did not, so the rename lands as an in-place update.

### Fixed

- **The Test Connection verdict is translated (#1728).** The verdict was built as
  English sentences on the server, which the untranslated-sentence gate could not
  see either. The server now answers with catalogue keys, which changes both Test
  endpoints: `Message` and `Details` become `Key` and `Facts`.
- **The self-service page asks before it removes your last way in, and says why
  when the server refuses (#1731).** Delete went out with no confirmation and a
  refusal landed in the generic banner. The question names the consequence and
  never promises the refusal: #1732 and #1733 are cases where it goes through.
- **The Test Connection, configuration export and configuration import progress
  lines go through the catalogue (#1739).** The three lines were written straight
  into the page and the ratchet could not see a one-word literal; the four sites
  now carry catalogue keys and a by-site arm refuses a literal there.
- **Eight short English sentences on the provider page now go through the
  translation catalogue (#1725).** The gate read only literals of twenty
  characters or more, so shorter sentences stayed English while it was green; the
  gate now has no length floor.
- **The login's completion page names both addresses when it cannot finish where
  it was opened (#1714).** A page opened at one address while the server built
  the login for another showed "Logging in..." for as long as the tab stayed
  open. It now compares the two first and, on a mismatch, shows both and says
  after twenty seconds what it is waiting for.
- **The Base URL Override field accepts the path a path-base deployment needs
  (#1712).** The Providers tab flagged every path as an error and saved it
  anyway; both validators now accept a path, while a `/sso/...` address, a query
  and a fragment are still refused.
- **A browser no longer keeps the previous build's scripts after an upgrade
  (#1705).** The asset tag was the assembly's file version, pinned at the line's
  three-part number, so the dashboard ran the old script against the new pages.
  The tag is now a digest of the assembly's bytes.
- **A settings tab returned to now shows what the server holds, instead of what
  it last loaded (#1576, #1572).** The dashboard hands a cached view back without
  re-running its controller. The four control-bearing tabs re-read on every
  return and refuse to while an editor is open or the page holds work.
- **The login audit line's `admin=` field now reports the rights the session was
  granted, not the role mapping's verdict (#1554).** `admin=True` could stand for
  a session never made administrator, and break-glass read `admin=False` while
  holding one. **A structured sink receives `IsAdmin` as a String, not a Boolean.**
- **A failed configuration read no longer leaves a pressed Save with no outcome
  at all (#1577).** Four of the reads that precede a write had no failure arm, so
  Save did nothing visible; all four now answer, and the two deletes say that
  nothing was changed.
- **A refused account-link import no longer logs a different sentence from the
  one it answers, and the default-provider line is sanitized (#1566).** The log
  substituted the whole composed sentence, so the `[truncated]` marker read
  `(truncated]` there; the values are now substituted where they enter it.
- **A discovery read whose caller has gone away now ends with the caller
  (#1558).** The read took no cancellation token, so a challenge whose browser had
  left held its connection for two fetch timeouts. The back-channel logout keeps
  its own budget, because the party depending on it is the user being signed out.
- **A declarative document that could not be written still locked its providers
  against the settings page (#1534).** The freeze was recorded before the write,
  and since #1521 a failed write is undone, so the plugin reverted every edit to
  values in effect nowhere. The freeze is now recorded only once the write lands.
- **A first login that failed half way left an account nobody could use (#1533).**
  An account created but not linked and without a usable password stayed behind
  and blocked that person from being provisioned again. It is now removed when the
  login cannot be completed, and the log says so.
- **A configuration write that could not reach the disk was applied anyway
  (#1521).** Every change was applied to the running plugin and only then written,
  so a failed write left the server behaving as though it had succeeded. The
  write now happens first and is rolled back if it fails (#1532).
- **Restoring an account-link backup restored nothing, and said it had worked
  (#1517).** The entries were dropped, because the property holding them could
  not be assigned by the host's serializer. **An operator who migrated on any beta
  from `4.3.0-beta.43` has an empty link table: re-run the import.**
- **The OpenID provider API stored a post-logout return URL the configuration page
  would have refused (#1504).** `OID/Add` did not check that the URI sits at or
  under the configured base URL, so it was stored, answered with success and then
  dropped at logout time. The door now refuses it with the page's message.
- **The configuration page could not see that a provisioning profile is decided by
  a configuration file (#1498).** Editing a frozen profile printed "Saved" while
  nothing changed, and renaming it left an unmanaged copy behind. The managed
  report now names profiles beside providers and each act refuses first.
- **The provider API stored a starting policy the configuration page would have
  refused (#1502).** `OID/Add` and `SAML/Add` ran no provisioning-template checks,
  so a template naming an unknown permission, mode or profile was stored and
  simply did nothing. Both doors now refuse such a body.
- **The sign-in buttons did not look like the login page's own buttons (#1372).**
  Jellyfin adds its own `button-link` class at runtime, which removes the padding
  the button classes set. Each button now carries the four declarations that
  restore it; found by [@teekennedy](https://github.com/teekennedy) in #1342.
- **A second, unremovable set of sign-in buttons on the login page (#1344).** The
  opening marker's wording changed in an earlier release, so the plugin stopped
  recognising its own region and added a second set nothing could remove. The
  region is recognised by the stable `SSO-LOGIN-BUTTONS:BEGIN` token alone now.

### Security

- **The break-glass check no longer accepts a password nobody can type (#1746).**
  It counted any stored password as proof, including the 64 random bytes this
  plugin mints, so a recovery door could be named that opens for nobody. An
  account sealed by a version that kept no record is not reached: a floor.
- **The self-unlink refusal now reaches the accounts it was written for (#1733).**
  A credential somebody holds and a seal nobody can open were the same bytes, so
  the guard answered "has a way in" for every account this plugin created. It now
  records a digest of the passwords it mints, which stops applying once anything
  else writes one.
- **An administrator can no longer strand their own server through Revoke either
  (#1741).** `POST sso/Unregister/{username}` asked nothing about the caller
  beyond elevation, the one-call route to the lockout #1732 closed. It refuses
  with a 403 naming the remedies where no other enabled administrator holds a
  link.
- **An administrator can no longer strand their own server through the
  self-service unlink (#1732).** `/SSOViews/linking` acts on the caller's own
  account, so the exemption written for acting on somebody else's link left an
  administrator one press from the lockout. A stored password is never counted.
- **A user whose account accepts no password can no longer lock themselves out by
  unlinking their last provider (#1720).** Delete removed it with no warning and
  no fallback, leaving an account only an administrator could reach. The refusal
  is in the server; an account on the built-in password provider reads as having
  a password and is outside this rule.
- **A foreign value can no longer plant an audit record in ANY line this plugin
  writes (#1557).** #1555 closed the forgery inside the audit emitter, and
  ordinary log lines still carried foreign text under the line-ending strip.
  Every logging call now substitutes the opening square bracket, so **such a
  value prints `(` in every plugin line.**
- **The account-link import no longer stores an issuer the provider could not have
  issued (#1518).** It wrote the issuer the backup named and compared it to
  nothing, so a migration where the provider also moved locked the userbase out.
  **The way through is to remove the `Issuer` field, never to switch
  `DoNotValidateIssuerName` on.**
- **An identity-provider-supplied value can no longer forge a second audit record
  inside an audit line (#1555).** Nothing bounded a value inside its sentence, so a
  presented username could close it and write a second plausible record on one
  line. Every foreign value the emitter prints now has that bracket replaced.
- **An account the plugin creates is now stored with the password and the login
  routing it is given (#1440).** Neither reached the database, so the account was
  persisted on Jellyfin's password provider with no password, which accepts the
  empty one. One save carries both, and a failed save deletes the half-made one.
- **Accounts an old version created without a password no longer accept the empty
  one on the login form (#1440).** Every release up to v3.4.0.2 provisioned
  accounts that way, and the fix at creation never reaches an account that exists.
  Every SSO-linked account without a stored password is given an unguessable one
  at server start.
- **A declared provider can no longer be altered or deleted through the plugin's
  other administrator endpoints (#1415).** Four endpoints and the configuration
  import wrote by other doors, so a provider a mounted file or the environment
  declared could be removed until the next restart put it back. All five refuse
  now, naming the provider and the source.
- **A back-channel logout token can no longer break the check that decides whether
  it is one (#1349).** A member name written with an unpaired surrogate escape has
  no decoding, so the lookup raised an error instead of refusing the token. The
  member is now looked up through a walk that skips a name it cannot decode.
- **A discovery document can no longer break the plugin's discovery checks with a
  member name it never had to look at (#1340).** The readers for PKCE `S256` and
  the RFC 9207 response `iss` decoded every candidate name, so an undecodable
  unrelated name could refuse every login under **Require PKCE**.
- **A token minted for one endpoint is no longer read as a token for the other
  (#1317).** Neither JWT had its `typ` header looked at, and a genuine logout token
  was measured validating on the login path. Both entry points now refuse a token
  declaring itself an access token, a DPoP proof or a logout token.
- **A single dropped discovery response no longer cancels a sign-out the identity
  provider ordered (#1183).** The read that obtains the logout token's keys was
  attempted once, so any failure left the sessions the provider had ended still
  running. A transient failure is retried once within a 21-second worst case.
- **An identity provider can no longer write unbounded log through a failed
  discovery read (#1194).** On the JWKS leg the provider chooses the URL the
  quoted error text names: a 200 KB `jwks_uri` produced a 205,042-character entry
  from one read. The text is now cut at 512 characters and marked `[truncated]`.
- **A back-channel logout that did not happen is now its own audit entry.** A
  termination the plugin could not verify was recorded with the same warning as a
  forged token, which is the opposite situation. The two are now separate entries
  at separate levels, and the uniform 400 response is unchanged.
- **A document that says two things about a user's roles now grants none of them.**
  A UserInfo response naming the role claim twice arrived as two clean claims whose
  roles were merged, so a second copy naming an extra role granted it. Copies that
  disagree are refused outright and the login proceeds with no roles.
- **A provider response that names a JSON member twice is refused before it is
  parsed.** Which value a consumer acts on is decided by parser internals rather
  than by the document, so discovery, JWKS and an uninspectable body are screened
  on the transport. **Such a document will fail to sign users in, and no
  configuration overrides that.**
- **A token whose JWS header marks an extension critical is refused (#1038).** The
  plugin implements no JWS extension and the library ignores `crit`, so a signed
  token carrying one was accepted with its declared constraint dropped. It was
  never exploitable without the provider's own signature.

## 4.3.0

A feature release. This line advances the plugin's maturity to **Beta** on the
back of a large login-hardening and code-quality pass.

### Added

- **SSO-only login enforcement (#165).** An optional mode that closes the
  built-in password door so accounts authenticate only through SSO. Activation is
  refused unless a designated break-glass administrator keeps a working password
  login, and the mode is fully reversible on disable.
- **Full role-based access control (#164).** Providers can map identity-provider
  roles to Jellyfin permissions through a generic permission-role mapping,
  validated fail-closed at save.
- **Redesigned configuration UI (#697).** The admin settings page was reworked
  into clearer, native accordion sections.

### Changed

- **The self-service linking and auth-completion pages were polished (#666,
  #667, #669).** The linking page renders a proper help label and an empty state,
  and the auth-completion status line is an `aria-live` region that offers a
  "Return to login" link.
- **Browser-navigated login errors are now styled (#668).** A rejection reached
  by direct navigation is a themed HTML page with a return link and a strict
  Content-Security-Policy instead of raw plain text.
- **Internal consolidation (#670, #671, #695).** The duplicated challenge
  redirect-path resolver and a single-caller OpenID wrapper were unified, with no
  behavioural change, locked in by conformance tests.

### Security

- **SAML parsing hardened (#698).**
- **SAML `DoNotValidateAudience` is now audited (#672).** Enabling this
  default-on protection's escape hatch leaves an `[SSO Audit]` trail on save and
  import, at parity with the OpenID insecure toggles.
- **Rate-limit endpoint-class bucket keys are typed (#694).** The per-client
  limiter keys are named constants rather than bare literals, so a typo can no
  longer silently split a security budget.
- **SSO-only no longer strips a third-party provider account's login path
  (#690).**
- **The OpenID authorize-state store is keyed on UTC (#696), and role-privilege
  mapping guards null folder sets (#693).**

## 4.2.1

A bug-fix release.

### Fixed

- **Admin-or-self authorization now denies explicitly on a null auth context
  (#626).** `RequestHelpers.AssertCanUpdateUser` failed closed by throwing a
  `NullReferenceException`, which could surface as a 500, and now returns an
  explicit `false`. Normal authenticated requests are unaffected.

## 4.2.0

A breaking release.

### Removed

- **`SAML/Auth` no longer accepts a raw SAML assertion (BREAKING, #528).** #251
  replaced the assertion round-trip with a one-time outcome token, and for one
  release `SAML/Auth` also accepted the older shape. That window has closed: a
  client POSTing a raw assertion is refused, and the browser flows are unaffected.

## 4.1.1

A bug-fix release that restores plugin loading on Jellyfin 10.11. No
configuration changes.

### Fixed

- **The plugin no longer fails to load on Jellyfin 10.11 (#590).** 4.1.0.0
  shipped an OIDC client referencing `Microsoft.Extensions.Logging.Abstractions`
  10.0.0.0, which a .NET 9 host does not provide, so the host disabled the plugin
  at startup. The client is pinned back to the 6.x line, with no behaviour change.

### Added

- **A conformance test locks the ABI floor in.**
  `ArchitectureConformanceTests.HostProvidedFrameworkAssemblies_StayOnTheHostNet9Abi`
  fails the build if a host-provided `Microsoft.Extensions.*` assembly is
  referenced above the .NET 9 host ABI.

## 4.1.0

The first feature release of the revived plugin: a security-parity pass over the
login path, provider secrets encrypted at rest, outgoing SAML request signing,
admin-UI toggles for config-only flags, and the login controller decomposed.

### Breaking

- **Provider secrets are now encrypted at rest (#158).** Secrets and signing keys
  are stored as an AES-256-GCM envelope (`ssoenc:` values), and upgrading is
  transparent. **Downgrading is breaking:** re-enter each secret in plaintext, or
  restore the pre-upgrade backup, before installing an older build.
- **OpenID logins that relied on legacy username matching are refused until you
  migrate (#358).** Links created by 4.0.0.4 and earlier are keyed on the
  username, which the identity provider controls, so they are no longer followed.
  The account is adopted only under `AllowExistingAccountLink` or by an admin.

### Security

The login path was hardened end to end and now fails closed by default.

- **SAML:** XXE-safe XML loading, strict single-assertion conformance, a signed
  algorithm allowlist, replay protection with a bounded cache, and enforced
  time-bound, audience and recipient checks.
- **OpenID Connect:** PKCE S256, `state` and RFC 9207 `iss` validation sourced
  from the login's own discovery document, full `id_token` validation, and a
  verified-email gate for account login and adoption.
- **Account linking:** OpenID links are bound to the issuer (#186) and to the
  stable `sub` / `NameID`, so a renamed account cannot be silently taken over.
- **Abuse resistance:** rate limiting across the login, link/unlink and
  unregister endpoints, session and token revocation when a user is unregistered,
  and provider-name validation.
- **Transport and supply chain:** security response headers and CSP on the plugin
  pages, SSRF-guarded avatar fetches, and a Trojan-Source guard in CI.

### Features

- **Outgoing SAML AuthnRequest signing (#167),** including ECDSA signing keys
  (#493) alongside RSA, for identity providers that require signed requests.
- **Admin-UI toggles for provider flags** that were previously config-file only,
  plus a real device name on linked sessions.
- **Provider-name hardening** so invalid names are rejected at configuration
  time.

### Architecture / internal

- The monolithic `SSOController` was decomposed into a thin controller over pure
  helpers and `Api/Flows/*Service` login services (#318), with a fail-closed
  `VerifiedIdentity` keystone and structural rules locked in as conformance
  tests. This is internal and changes no configuration.

### Fixes

- Login rejections consistently return their intended status codes and never
  surface as HTTP 500.
- Corrected avatar and disabled-provider handling across the login and linking
  flows, with smaller robustness fixes in state handling and session minting.
