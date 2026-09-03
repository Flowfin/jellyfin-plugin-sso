# Changelog

All notable changes to this plugin are documented here. Versions are three-part
`X.Y.Z` as described in the release policy - **X** a breaking / Jellyfin-ABI
change, **Y** a feature, **Z** a bug-fix or security patch (the two share the
digit and differ by release cadence). The channel and Jellyfin generation are a
suffix on the git tag and GitHub release name only (`-stable`, `-beta.<run>`,
`-JF12-*`), never part of the installed numeric version.

## Unreleased

### Added

- **A starting policy can seed the home screen (#1101).** The provisioning
  template gains a **Home screen sections** list: the sections of the web
  client's home screen, one per line, top slot first, in the exact names
  Jellyfin declares. It is written once, when the account is created, into the
  same document the web client reads its layout from, and it is written whole -
  the sections you list and nothing in the remaining slots - so a new account
  opens on exactly that layout rather than on your sections followed by the
  client's own defaults. An empty list writes nothing and the account keeps
  Jellyfin's own layout; an unknown name, or more entries than the ten slots
  the client renders, is refused at save. The layout is a second write beside
  the account itself and never fails a login: if the display-preferences store
  cannot be written, the account is created without it and the log says so. It
  seeds the web client only, because the section vocabulary and the ten-slot
  layout are the web client's. Two things this was first asked for are not
  here, for reasons read out of the client rather than decided: the app theme
  never reaches the server, because the web client keeps it in the browser,
  and a landing screen is set per library under keys that need a library id
  nobody has when an account is created.

- **Named provisioning profiles are editable from the dashboard (#1105).** A
  profile is a starting policy under a name that any number of providers can
  share - the `guest` profile beside the default one - and until now the only
  way to define one was to edit the plugin configuration by hand. The
  configuration page carries a **Provisioning Profiles** section: list, add,
  rename, delete, and the same nine controls the provider forms carry, with the
  same rules - a field you leave alone keeps Jellyfin's own default, and zero is
  a real value for the bitrate ceiling and the session limit. Each provider form
  gains the selector that points at one. Add copies the starting policy of a
  provider you choose, under the name you type, so a new profile begins as what
  that provider does today rather than as a blank form that silently writes
  nothing; adding one changes no account until you point a provider at it.
  Deleting a profile some provider or role rule still names is refused and the
  references are named, because clearing them would switch those providers to a
  different starting policy from a delete button. Renaming one repoints every
  reference in the same save, so nothing is ever left pointing at a name the
  configuration no longer defines. Pointing a provider at a profile clears that
  provider's own inline fields when you save, since new accounts get exactly one
  policy from one source; you are asked before that happens, and adding a
  profile from the provider's own policy first is the way to keep it. Existing
  configurations are untouched: a provider that names no profile keeps its
  inline policy exactly as it is.

- **The starting policy is on the provider forms (#1367).** Everything a
  provider writes onto a brand-new account - the permissions, the remote
  bitrate ceiling, the session limit, the two language preferences, the
  subtitle mode and the three playback switches - was configurable only by
  editing the plugin configuration by hand. Both provider forms now carry it,
  under **Starting policy for new accounts**. Every control has three states
  rather than two, because every field of the template does: a control you
  leave alone sends nothing at all and Jellyfin's own default governs, which
  is why the three playback switches are lists reading Yes, No or leave
  Jellyfin's own default and not checkboxes - a checkbox would post a
  deliberate No for a field you never touched, onto every account the provider
  creates. A form on which you set nothing sends no template rather than an
  empty one, so a provider that takes its policy from a named provisioning
  profile stays saveable from the dashboard; on such a provider the section
  says where the policy comes from and leaves its own fields alone. The
  subtitle mode is a list of exactly the mode names Jellyfin declares, so the
  spelling a save accepts is the only one you can pick. The permission rows
  offer the names the server publishes rather than a list kept on the page,
  which is why administrator, all-folders and Live TV access are absent - each
  keeps its own setting above - and why no account can be created disabled
  from here. A configuration written by hand is not rewritten by opening or
  saving a provider. Every label and help line is in the English and German
  catalogues.

- **The dashboard shows who is linked, and can cut one account off (#1121).**
  Finding out which Jellyfin accounts sign in through SSO meant asking the API,
  and revoking one meant the same; neither was on the settings page. It now
  carries a Linked Accounts panel: every account holding an SSO link, the
  provider and the identity-provider subject behind each link, and when that link
  was last used to sign in. Each row offers a revoke, which removes that
  account's links from every provider and ends every session it holds, on every
  device. It asks first, and the question names what the revoke does instead of
  asking whether you are sure: the account is switched back to Jellyfin's
  built-in password provider, so it can sign in with a password again even on a
  server that is otherwise SSO-only, and the server-wide setting is left exactly
  as it was. The panel is equally plain about what a revoke does not buy. Where a
  provider is permitted to link existing accounts, the same name can be adopted
  again at the next SSO login, so the local account has to be disabled or renamed
  as well when the cut has to hold. A link left behind by a deleted account is
  shown rather than hidden, because nothing else shows it, and it carries no
  revoke button: the revoke resolves an account by its username, which such a row
  no longer has, so a button there could only ever fail. Nothing new is exposed
  on the server - the panel reads the existing administrator-only roster and
  drives the existing administrator-only revoke, with its rate limit and its
  audit line unchanged - and every value it paints is written as text, never as
  markup, because a subject identifier is whatever the identity provider chose to
  send.
- **A group can decide who may start a SyncPlay session (#827).** Everything else
  the identity provider decides about an account is re-read at every login -
  administrator rights, folder access, Live TV, the permission surface, the
  parental-rating ceiling - but SyncPlay was not among them, so a deployment that
  expresses its access model in groups had one setting it could only manage by
  hand, per account, forever. A provider can now map its roles onto the account's
  SyncPlay access, and the mapping is re-asserted at every sign-in, so a group
  withdrawn at the identity provider withdraws the access with it. It is off
  until it is configured, and it is under the same authorization master switch as
  every other role-derived grant: turning that off leaves SyncPlay exactly as it
  was. A login that matches nothing changes nothing - an unmapped or misspelled
  claim can never widen access, only leave it where it stood. Where a login
  belongs to several mapped groups the STRICTEST of them wins, which is worth
  saying out loud because Jellyfin numbers its SyncPlay levels the other way
  round from its parental ratings: "least privilege" here is the highest value,
  not the lowest, and the plugin states the ranking itself rather than inheriting
  it from an order upstream is free to change. A level is written by name -
  `CreateAndJoinGroups`, `JoinGroups` or `None`, spelled exactly - and any other
  spelling, a number among them, is refused when the configuration is saved
  rather than silently ignored at the next login.
- **One action checks every configured provider at once (#1084).** The settings
  page could say whether the provider currently open in the editor looks
  complete, and nothing could say it about the others: an administrator with six
  providers had to open six forms to find the one that would refuse a login.
  A "Configuration check" section above the provider lists now answers for all
  of them in one press - every OpenID and SAML provider, whether a login against
  it would get past the configuration, and what is wrong where it would not. The
  answer comes from the server rather than from the form, which is what lets it
  cover providers nobody has opened, and it is the same judgement a save is
  refused by: the reason a row gives is the message the save path itself would
  produce, so the check and the settings page cannot disagree about one
  provider. Required settings that are still empty are named through the form's
  own labels, so the report speaks the page's language. Advisory in both
  directions - it never blocks a save and it changes nothing, so running it
  leaves every provider's stored values and toggles exactly as they were. A
  provider that is switched off is reported as switched off rather than as
  broken. What the check does NOT do is contact any identity provider, and it
  says so on every run: reachability is what Test Connection in a provider's own
  editor is for, and fanning out probes here would empty the throttle budget
  those routes share and report working providers as unreachable.
- **A provisioning policy can be named once and shared by several providers
  (#1105).** The policy written onto a brand-new account at creation used to
  exist only as a block inside one provider, so a deployment wanting the same
  starting permissions on two providers had to write them twice and keep the two
  copies in step by hand. A configuration can now hold named provisioning
  profiles, and a provider says which one its new accounts get - the `guest`
  profile beside the default one, pointed at from as many providers as should
  share it. Nothing changes for a provider that names no profile: it keeps its
  own inline template, which is every provider configured before this existed,
  and an existing configuration provisions exactly as it did. A profile is
  judged by the same checks an inline template is, so it cannot become a second
  route to the permissions the plugin refuses to write from configuration -
  administrator, all-folders, Live TV and the account-disable flag are rejected
  in a profile exactly as they are in a template. Two states are refused on
  save rather than persisted: a provider naming a profile the configuration does
  not define, and a provider naming a profile while still carrying an inline
  template, which would be two account-creation policies with nothing saying
  which one won. If a name somehow stops resolving anyway - a configuration file
  edited around the save path - the account is created with no policy written at
  all rather than falling back to the inline block, so a profile that was
  replaced can never come back on the next first login. Profiles travel with a
  configuration export and are merged back by an import, so a provider and the
  policy it points at do not arrive separately. The plugin's settings page does
  not yet offer a profile editor: profiles are configured through the admin API,
  a configuration file, or an import, and a dashboard save leaves them
  untouched.
- **A provider can pick which provisioning profile a new account gets from the
  login's own roles (#1106).** Naming one profile per provider (#1105) meant a
  deployment wanting guests to start narrower than staff needed a second
  provider, a second client registration at the identity provider, and a second
  sign-in button - for a difference that the identity provider already states in
  the roles it sends. A provider can now carry an ordered list of
  role-to-profile rows, so one provider provisions a `guest` login from the
  `guest` profile and everybody else from the provider's own default. The
  resolution order is one sentence and it is the order the rows are written in:
  the first row whose roles the login holds wins, then the provider's own named
  profile, then its inline template, then nothing. First-row-wins rather than
  some combination of the matches, because two profiles are two permission sets
  rather than two points on a scale - there is no "most restrictive" to pick -
  so the administrator states the precedence by ordering the rows, and
  re-ordering them is the whole of how it is changed. Nothing changes for a
  provider that configures no rows, which is every provider configured before
  this existed, and a stored configuration written without them provisions
  exactly as it did. The roles are the ones the login already produced for role
  mapping, so no new claim or attribute is read. Two states are refused on save
  rather than persisted: a row naming a profile the configuration does not
  define, and a row that names no profile or lists no roles - each would sit in
  the list looking like a rule while selecting nothing. If a row's profile stops
  resolving anyway - a configuration file edited around the save path - the
  account is created with no policy written at all, and in particular it does
  NOT fall back to the provider's default. That matters more here than one level
  up: a row exists to send one group somewhere narrower, so falling back would
  hand precisely those accounts the wider policy they were moved off, silently,
  at the moment they are created. As with profiles themselves, the settings page
  does not yet offer an editor for the rows: they are configured through the
  admin API, a configuration file, or an import, and a dashboard save leaves
  them untouched.

- **Counters for the sign-in path, on a metrics endpoint an operator can scrape
  (#1139).** Until now the only signal about logins was the log, and a log line
  cannot be alerted on: nobody can ask it how many sign-ins failed in the last
  five minutes. `GET /SSO/Metrics` answers that. It publishes, in the Prometheus
  text format any monitoring system reads, how many sign-ins succeeded per
  provider, how many were refused and for which of the reasons the plugin gives,
  how many accounts were created or taken over, how many requests the rate
  limiter turned away and for which kind of endpoint, and how many
  server-to-provider fetches failed, telling an unreadable discovery document
  apart from a failed code exchange because the two are fixed in different
  places. Every counter is published even at zero, so an alert on a rate can be
  written before the thing it watches for has ever happened. The route needs
  administrator rights like every other operator surface here: the counters name
  which providers a server has and how often sign-ins against them fail, which
  is reconnaissance for somebody who cannot sign in, so a scraper is given a
  token like any other client. No counter carries a username, an identity-
  provider subject or a claim value; a breakdown is either a provider name from
  the configuration or one member of a fixed list. The number of distinct
  breakdowns the plugin will hold is capped, and a scrape that hit that cap says
  so on the same scrape rather than looking complete. Nothing is persisted and
  the counts start again at each restart, which is what a monitoring system
  expects of a counter. Installations that scrape nothing are unaffected: the
  endpoint answers when it is asked and does nothing otherwise.

- **Providers can be declared entirely in environment variables (#1097).** A
  deployment that describes its identity providers in a mounted file can now
  describe them in its own environment instead, under the same rules and through
  the same apply. A variable names a path into the configuration with `__`
  between the steps, which is the separator a compose file or a Kubernetes
  manifest already uses elsewhere, so
  `JELLYFIN_SSO_CONFIG__OidConfigs__keycloak__OidClientId` sets the client id of
  the provider called `keycloak`, and `__Roles__0` sets the first entry of a
  list. The names are resolved against the configuration itself rather than
  against a list somebody maintains, so every field of an OpenID or SAML
  provider is settable under its own name, and a field added later is settable
  the day it arrives. Setting none of these leaves the server behaving exactly as
  it did before. A variable the plugin cannot place refuses the whole
  environment instead of applying the rest: a misspelled name, a value that is
  not the field's type, a gap in a numbered list, and a name aimed at something
  the server manages for itself are all refusals, and a refusal leaves the stored
  configuration untouched. Two things are worth knowing before writing one. A
  provider is declared whole, exactly as it is in a mounted file, because the
  merge works provider by provider: naming a single field of a provider that
  already exists leaves the rest of that provider at its defaults, and on an
  OpenID provider that counts as repointing it, which clears its account links.
  And where a file and the environment both describe the same provider, the
  environment is applied second and wins, while a provider neither of them names
  is left exactly as it was. The rate-limit tuning and the SSO-only switch are
  not settable this way, because no declarative source applies them; a variable
  naming one is refused rather than quietly ignored.

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
- **Jellyfin accounts can follow a rename at the identity provider (#1138).** A
  new per-provider option, **Follow Username Renames From The Provider**, renames
  a linked Jellyfin account on the user's next SSO login when their username has
  changed at the provider. Off by default, in which case the Jellyfin name stays
  as it was and the two drift apart, which is what happens today. This is the
  display name only: the account is found by its stable subject identifier
  either way, so turning it on cannot change which account a login reaches, and
  it adds no way to select an account by name. The new name is cleaned up the
  same way a newly created account's name is, so a rename can never put a name on
  an account that Jellyfin would have refused at creation. If another Jellyfin
  account already holds the name, the rename is skipped and both accounts keep
  their names rather than the outcome depending on who logged in last. A rename
  that fails for any other reason is logged and the login still succeeds, because
  a display name that has drifted is cosmetic and a refused login is not. Each
  rename is recorded as an audit event naming both the old and the new name. The
  option is in the provider forms for OpenID and SAML.

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
  Jellyfin. The template is set on each provider's form in the
  dashboard, under Starting policy for new accounts, and in the plugin
  configuration.
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
  the rest of the template, these are on the provider forms in the dashboard as
  well as in the plugin configuration.
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
- **An account can be linked to an identity before its first login (#1133).** A
  new administrator-only endpoint writes the link from an identity-provider
  subject to an existing Jellyfin account directly, so an account created by an
  invite or provisioning tool signs in through SSO the first time rather than
  starting as a password account somebody links by hand afterwards. The existing
  link write is unchanged and still requires the person being linked to complete
  a login at the identity provider; this one takes an administrator credential
  instead, and differs in one behaviour because of it: a subject already linked
  to a different account is refused and the existing link is left exactly as it
  was, where the older write would have moved it. Sending the same mapping twice
  succeeds, so a tool that retries a request whose answer it never saw does not
  have to tell the two cases apart. A link is refused for a provider that does
  not exist or is turned off, for an account id that no account holds, and for a
  blank subject. Every link made this way is recorded as an audit event naming
  the administrator, the provider and the account, and never the subject itself.

### Changed

- **A misspelled protocol segment on a link route now answers 400 (#1399).**
  The three account-link routes carry an `oid` or `saml` segment in their path,
  and a value that is neither used to throw. The refusal was correct and is
  unchanged; what the caller saw afterwards was not decided by this plugin but
  by whatever the server does with an exception, which made it the one refusal
  on that surface an integration could not rely on while its four neighbours
  each answer a chosen status with a chosen message. All three routes now answer
  `400` with the same fixed sentence naming the two accepted values. The
  sentence never repeats what was sent, so a mistyped segment is not reflected
  back into the response. This matters where the segment comes from a
  provisioning tool's own configuration, which is the ordinary way a wrong one
  arrives.

- **The redirect URI on the settings page now comes from the server (#1303).**
  The page used to work the value out for itself, in the browser, from the base
  URL override and a fixed path. That made two things compose a string an
  identity provider compares letter for letter, and when the two disagreed the
  login did not fail on this server: it failed at the provider, with a
  `redirect_uri` mismatch that looks like a plugin fault and that nobody here
  ever sees. The field now shows what the server answers, so what is registered
  at the provider and what the login sends are the same string with one author.
  There is no local fallback, which has one visible cost: the field is filled in
  for a provider that has been saved, and a provider still being typed shows
  "Save this provider to see its exact redirect URI" instead of a preview. One
  case is not covered and the field's help text names it: both sign-in routes
  stay live, and users who still start at the older `/sso/OID/p/<name>` address
  send the older `/sso/OID/r/<name>` form, which has to be registered as well.

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

- **The OpenID provider API stored a post-logout return URL the configuration
  page would have refused (#1504).** `OID/Add` writes the provider it is given
  without the configuration save's checks, and the check that a post-logout
  redirect URI sits at or under the configured base URL was not among the ones
  it ran at the door. Such a URL was stored and answered with success, and the
  logout path then dropped it, so the return never fired and nothing said why.
  The door now refuses it with the message the configuration page gives, and
  skips the check exactly where the page does: without a base URL override the
  base is the request host, unknown at save time, and the logout-time allow-list
  stays the only check.

- **The provider API stored a starting policy the configuration page would have
  refused (#1502).** `OID/Add` and `SAML/Add` write the provider they are given
  without running the configuration save's checks, and nothing ran the
  provisioning-template ones at that door. A template naming a permission that
  is not one Jellyfin declares, a subtitle mode or home-screen section it does
  not know, a negative ceiling, or a provisioning profile the configuration
  does not define was stored as posted and answered with success. Nothing was
  widened by it - every writer skips a value it cannot read - but the template
  did nothing, and the first sign was an account that arrived without the
  policy. Both doors now refuse such a body and store nothing. The reason is the
  same message the configuration page shows, naming the field; for an API caller
  it is written to the server log, because Jellyfin answers every refused request
  with a bare 400 outside a development host.

- **The sign-in buttons did not look like the login page's own buttons (#1372).**
  Jellyfin restyles every link in the login disclaimer at runtime: it adds its
  own `button-link` class, which is declared after `emby-button` at the same
  specificity and so wins. What that class takes away is the padding the button
  classes had set, and it underlines the label on hover. The button this plugin
  ships therefore rendered barely wider than its text, in link colour and
  underlined, and an administrator who wanted it to match the buttons above it
  had to write nine declarations of custom CSS. Each button now carries the four
  declarations that restore what the runtime class removed, as an inline style,
  which beats a class rule in every state including hover. Nothing else changes:
  the plugin still manages only its own region of the disclaimer, and your custom
  CSS stays yours. The buttons are still not stretched across the page, because
  the disclaimer is a flex item that shrinks to its content and widening it would
  mean restyling Jellyfin's own containers; the wiki carries that two-line
  snippet for anyone who wants it. Found and measured by
  [@teekennedy](https://github.com/teekennedy) in discussion #1342.

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

- **An account the plugin creates is now stored with the password and the login
  routing it is given (#1440).** Both were written onto the account object the
  server handed back at creation and neither reached the database: the session
  that follows a login re-reads the account by id and saves that copy, so the
  account was persisted routed at Jellyfin's own password provider with no
  password stored - which is an account that accepts the EMPTY password on the
  ordinary login form, reachable by anybody who can reach the server and without
  ever touching the identity provider. Found by driving a real login against a
  real server and reading the account back, not by any test in the suite: every
  one of those asserted on the copy in memory, where both values were always
  present. One save now carries the routing, the password and - where a provider
  holds new accounts for approval - the disabled flag, and a save that fails
  deletes the half-made account instead of leaving it behind enabled and
  reachable.

- **Accounts an old plugin version created without a password no longer accept
  the empty one on the ordinary login form (#1440).** A Jellyfin account created
  with no password accepts the empty password, and every release up to and
  including v3.4.0.2 provisioned SSO accounts that way - the account was stamped
  onto a provider id that accepts nothing, which shut the door until a provider's
  default-provider setting repointed the account at a real password provider and
  left the empty password behind it. Those accounts are still on servers that
  have since upgraded, and the fix at the point of creation, which has minted a
  random password since v3.5.0.0, never reaches an account that already exists.
  The plugin now gives every SSO-linked account with no stored password an
  unguessable one, once at server start. It changes nothing else: an account that
  already carries a password keeps exactly the one it has, no account's login
  provider routing is touched, and an account no provider links to is left alone
  because it is not this plugin's to change. A single line in the log says how
  many accounts were sealed and nothing that identifies them; a server with none
  to seal - every server provisioned since v3.5.0.0 - says nothing at all.

- **A provider a mounted file or the environment declared can no longer be
  altered or deleted through the plugin's other administrator endpoints
  (#1415).** The settings page already kept the declared value and discarded
  what was posted over it, but that only covered the one route the page saves
  through. Four endpoints wrote by a different door, and importing a
  configuration wrote by a fifth, so an administrator adding or deleting a
  declared provider through the API replaced or removed it until the next
  restart put it back, and every login against that provider could fail in the
  meantime with nothing in the log saying why. All five now refuse, and the
  refusal names the provider and the source that decided it, so the change can
  be made where it will survive a restart. A configuration import that names a
  declared provider is refused whole rather than applied with those providers
  quietly dropped, and it says how many it found, so a restore that cannot be
  completed is never reported as one that was. A provider no source declared
  adds, deletes and imports exactly as before, which is every provider on a
  server that declares none.

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
