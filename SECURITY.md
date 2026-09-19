# Security policy

This plugin is a login path for a Jellyfin server. Security reports are taken
seriously and handled with priority over all other work.

## Reporting a vulnerability

Please report vulnerabilities **privately** via GitHub's
[private vulnerability reporting](https://github.com/Flowfin/jellyfin-plugin-sso/security/advisories/new)
("Report a vulnerability" on the Security tab of this repository).

Please do **not** open a public issue for an exploitable vulnerability. A public
issue is created once a fix has been released.

If you used LLMs/AI tooling to find the issue, please verify it manually before
reporting.

## What to expect

- An initial response within a few days.
- Security fixes are released as soon as they are ready - they are never
  batched or delayed behind feature work.
- Coordinated disclosure: please allow a fix to be released before public
  disclosure.

## Supported versions & security updates

**Support model (best-effort, volunteer):** this is a volunteer-maintained
open-source project. The commitments below describe intent, applied
consistently - they are not a contractual SLA.

- **One active version line: 5.x, for Jellyfin 12 on .NET 10.** Security fixes
  land in a **new latest release** of that line; older releases are not patched
  in place. "Supported" means: update to the latest release.
- Each release is packaged for one server generation, Jellyfin **12.x** on
  .NET 10. The 4.x line for Jellyfin 10.11 on .NET 9 ended with `4.3.0-stable`
  on 2026-09-15: 4.3.0 stays installable from the same repository URL, and it
  receives no further fixes unless I decide otherwise
  ([#1770](https://github.com/Flowfin/jellyfin-plugin-sso/issues/1770)).
- Until 2026-09-19 this file said the intent was to keep shipping security
  fixes for a previous line for at least six months after the new line's first
  stable release. That was not kept for 4.x: the line was retired before 5.0.0
  shipped, by decision, and the sentence above is what holds. What happens when
  a later line replaces 5.x is decided when it happens and is not promised here.
- **End of support is announced**, not silent: in `CHANGELOG.md` and the
  release notes. The 4.x end is announced in the `CHANGELOG.md` entry for
  #1770; it came with no advance notice, which this file used to promise.

Release integrity, channels and the soak/promotion model are described in the
[Releasing](https://github.com/Flowfin/jellyfin-plugin-sso/wiki/Releasing)
wiki page.

## Verifying a release download

Every stable release asset ships with an `.md5` and a `.sha256` sidecar per
plugin `.zip`; the `.md5` is the checksum the Jellyfin manifest uses to validate
the download, and it is unchanged.

In addition, each stable release zip carries a **signed SLSA build-provenance
attestation** (SLSA v1.1, Build L3 - the package build runs in a reusable GitHub
Actions workflow, which is what raises the provenance from L2 to L3). After
downloading a release zip you can verify it was produced by this repository's
release pipeline and has not been tampered with:

```sh
gh attestation verify <plugin>.zip --repo Flowfin/jellyfin-plugin-sso
```

The provenance attestation complements the checksum sidecars - it does not
replace the manifest MD5.

### Software Bill of Materials (SBOM)

Every release also ships a **CycloneDX SBOM** (`sbom.cyclonedx.json`) enumerating
the plugin's direct and transitive dependency closure, generated from the
committed `packages.lock.json` restored in locked mode. It is the dependency
inventory a downstream redistributor needs for its own CRA Annex I duties
(and satisfies OSPS-QA-02.02). The SBOM covers the **whole restored closure**
of the net10.0 / Jellyfin 12 build, the one target since #1770 - a superset of
what the zip carries, never less. It ships with a `.sha256` sidecar. It deliberately carries no
`.md5`: the Jellyfin manifest generator picks a release's checksum by filename
and keeps the last `.md5` it sees, so a second one can silently become the
published plugin checksum and break every install (#942). SHA-256 is the
meaningful integrity value here in any case.

The SBOM is generated in an isolated job that deliberately does **not** hold the
release signing scopes, so the SBOM tool can never reach the provenance signing
identity; it is therefore checksummed rather than attested.

Honest framing: the SBOM documents the shipped dependency set - it is a
transparency artifact, not a compliance certificate or a statement that those
dependencies are free of vulnerabilities (that is what the dependency-review and
vulnerable-dependency scans below cover).

### Reproducible compile

The build is **deterministic**: `Directory.Build.props` sets `Deterministic` and
(in CI) `ContinuousIntegrationBuild`, and the dependency graph is pinned by
committed `packages.lock.json` files restored in locked mode. Together with the
pinned .NET SDK, an independent party can rebuild the plugin assembly from the
tagged source and compare it against the shipped, SLSA-attested binary:

```sh
# from a clean checkout of the release tag, in the pinned SDK:
GITHUB_ACTIONS=true dotnet build SSO-Auth/SSO-Auth.csproj -c Release
# then compare the produced SSO-Auth.dll against the one in the release zip
```

Honest caveat: **the compiled `SSO-Auth.dll` is reproducible; the release `.zip`
is not byte-identical** - the JPRM packaging step embeds build timestamps and
ordering into the archive. Reproducibility is therefore verified at the
**assembly** level (the code that runs), not the archive wrapper; the archive's
integrity is covered by the SLSA attestation and the checksum sidecars above.

## Repository security controls

- **Secret scanning** and **push protection** are enabled, so a leaked credential - an identity-provider client secret, a CI token - is blocked before it can be pushed.
- **Dependabot** opens dependency-update pull requests; a dependency-review check blocks a pull request that introduces or upgrades to a known-vulnerable dependency; and the build fails on any known-vulnerable dependency, transitive ones included.
- Pull requests to `main` run CodeQL, a Trojan-Source/Unicode check, and a build with warnings treated as errors; a GitHub Actions workflow audit (zizmor) and repository-specific security-invariant checks (Opengrep) run on every pull request. A scheduled OpenSSF Scorecard scan audits the repository's supply-chain posture and publishes its results to code scanning. Changes to the login path additionally go through an adversarial security review before they merge.

For how these controls together cover what an automated PR reviewer would catch - and the one accepted residual - see [Review Gate](https://github.com/Flowfin/jellyfin-plugin-sso/wiki/Review-Gate). The plugin's [OpenSSF Best Practices](https://www.bestpractices.dev/projects/13660) passing level reflects the same controls. For the authentication surface mapped to OWASP ASVS 5.0 and the OAuth 2.0 Security BCP (RFC 9700) - Met / Partial / N-A with source citations and honestly-recorded residuals - see the [Security Conformance self-assessment](https://github.com/Flowfin/jellyfin-plugin-sso/wiki/Security-Conformance).

## Single Logout security posture

Single Logout (SLO) propagates a sign-out between the identity provider and
Jellyfin. It is **opt-in and off by default** (`EnableSingleLogout`): with it
off, both the RP-initiated OIDC logout route and the inbound SAML
`LogoutRequest` endpoint reject without acting.

- **The inbound SAML `LogoutRequest` endpoint is unauthenticated but
  signature-gated, fail-closed.** An IdP-initiated logout can revoke sessions,
  so the request is validated with the same defenses as the login assertion
  before anything is revoked: a hardened XML parse (DTD/DOCTYPE prohibited,
  external resolver disabled, size-bounded), an enveloped signature bound to the
  request root by an exactly-one, `#id`, covers-root reference (XML
  signature-wrapping defense), a signature/digest/transform/canonicalization
  **algorithm allowlist** (SHA-1/MD5 rejected), and a certificate trial across
  the provider's configured verification certificate(s) with validity-window and
  signing-key-strength enforcement. Unsigned, wrong-key, wrapped, weak-algorithm,
  malformed, expired, or replayed requests are all rejected with a **uniform
  400** carrying no cause-distinguishing detail, and the request ID is consumed
  one-time to block replay. There is a negative test for each of these branches.
- **Blast radius is bounded.** A valid `LogoutRequest` revokes only the sessions
  of the `(provider, NameID)` it names - matched exactly, no normalization - and,
  when it carries `SessionIndex` elements, only sessions whose captured index
  matches; it can never reach another subject's or another provider's sessions.
  Jellyfin's token revocation is **user-scoped** (there is no per-token revoke),
  so a `SessionIndex`-scoped request still revokes the whole matched user's
  tokens - documented, and safe (it errs toward ending more of the named user's
  sessions, never someone else's). Success is reported only when at least one
  session was actually revoked; a request that matched sessions but revoked none
  fails closed with the uniform 400.
- **RP-initiated OIDC logout** ends the caller's own local session, then
  redirects to the IdP's discovered `end_session_endpoint` - **host-bound to the
  discovered issuer** (open-redirect/SSRF defense) - with the caller's own
  `id_token_hint`. Any `post_logout_redirect_uri` is **allow-listed against this
  server's canonical base URL** (an off-base value is rejected at config-save and
  ignored at runtime), and validated at both points by one shared predicate. A
  missing or unreachable `end_session_endpoint` degrades to a local-only logout -
  it never breaks sign-out.
- **The RP-initiated logout route accepts a one-time ticket, so a client never
  has to put an access token in a URL.** That route sends the browser on to the
  identity provider, so it is reached by a top-level navigation, and a
  navigation carries no `Authorization` header; the only form that worked
  before was the caller's own access token as an `api_key` query parameter, a
  long-lived credential that lands in browser history, in a referrer and in
  every proxy log on the way. An authenticated `POST` to
  `OID/logout-ticket/{provider}` now mints a **256-bit CSPRNG ticket bound to
  that caller's user and that provider**, carrying the caller's own session
  token so the redeem ends exactly the session the ticket was minted from,
  valid for one minute and redeemable **exactly once** by an atomic claim.
  Read the session binding for what it covers: the local sign-out. The
  `id_token_hint` the redeem sends to the provider is chosen per user, newest
  capture first, and the ticket carries nothing that names a captured entry,
  so with a browser and a television signed in through the same provider a
  ticket minted in the browser ends the browser session locally, sends the
  television's `id_token` as the hint, and removes the television's capture
  with it; that session stays signed in to Jellyfin with its provider session
  gone and its Single Logout state erased, so a later back-channel logout
  naming it can no longer match it. The effect stays within one account. The
  route refuses -
  it does not degrade to a local sign-out - when a ticket is unknown, expired,
  already spent, or minted for another provider, and refuses a request carrying
  neither a ticket nor a session. Read what that covers precisely: the route
  refuses in place of the attribute on the **session-bearing** path, where it
  requires a resolved, non-disabled user. On the **ticket-bearing** path it
  decides about the ticket - freshness, provider, one use - and makes no check
  of the account the ticket names, so a ticket minted in the second before an
  account is disabled stays spendable for the rest of its minute. What that
  reaches is a sign-out of that account's own session. A refusal on either path
  records a fixed reason code in the audit trail, as every other logout refusal
  does, and a ticket-bearing request that completes records a line of its own,
  naming the provider and whether the browser was sent on to the provider's
  end-session endpoint or returned to this server; the ticket and the session
  token never reach it. The mint records nothing on issuance, deliberately: a
  spent ticket and a guessed one are already told apart where the ticket is
  spent, and a per-mint line would be writable at request rate by any signed-in
  account on an endpoint that is deliberately not throttled.
  The ticket-bearing form charges the Logout rate-limit class on a **failed**
  redeem - never on a successful one, so a legitimate sign-out is never
  throttled; the credential-less form charges it too, before it audits. The
  charge is made **after** the redeem has been evaluated, so what the limiter
  bounds is the answer and the audit line rather than the guessing or the work.
  Read all of that as a floor and not as a guarantee: the
  limiter is **off unless `EnableRateLimit` is set** (it is unset on a fresh
  install), and it deliberately creates no bucket for a non-public source, so
  behind a reverse proxy whose address Jellyfin has not been told to resolve
  nothing is throttled even when the setting is on. The mint is behind the
  `EnableSingleLogout` switch like the surfaces it serves; the redeem is not,
  so turning the switch off does not invalidate tickets already outstanding.
  The ticket store is
  held **in memory and never in
  the plugin configuration**, bounded globally and **per account** at a
  hundredth of the global cap, so no single signed-in user can refuse everybody
  else a sign-out - a hundred accounts holding their full share can, and the
  mint is deliberately not rate-limited. The `api_key`
  form still works for a client that cannot mint **where it carries a user's own
  access token**; a Jellyfin server API key names no user and is refused here,
  which a bare `[Authorize]` used to admit.
- **The residual the ticket leaves, stated because this entry's own framing is
  what creates it.** A ticket is presented as a query parameter of a top-level
  navigation, so it travels the same three channels the access token was
  condemned for above: browser history, the server's own request log, and every
  reverse-proxy access log between the browser and Jellyfin. The redeem binds
  nothing about the presenting request - not its address, not its user agent -
  so whoever reads a ticket out of one of those channels inside its minute and
  wins the race against the user's own navigation can spend it: they end that
  user's Jellyfin session and receive that user's `id_token` in the redirect to
  the identity provider. The trade against a long-lived access token in the same
  place is a large improvement and it is not an elimination, and the property
  the ticket removes is the credential's LIFETIME rather than its presence in a
  URL.
- **SP-initiated outbound SAML logout** ends the caller's own local session and
  then redirects the browser to the provider's configured `SamlSloEndpoint` (a
  validated absolute-`https` URL, never request-derived) with a `LogoutRequest`
  carrying only the caller's own `NameID`/`SessionIndex`, **signed** with the
  service-provider key through the shared redirect-binding signer. It is
  fail-safe: a missing SLO endpoint, an unloadable signing key, or no captured
  session degrades to a local-only logout - an unsigned request is never emitted
  and the local session is always ended.
- **The inbound endpoint answers with a signed `LogoutResponse`.** After a
  validated request revokes a session, the SP closes the IdP's Single-Logout loop
  by redirecting the browser to the provider's configured `SamlSloEndpoint` with
  a **signed** `LogoutResponse` (`Status=Success`, `InResponseTo` bound to the
  request ID, `Destination` pinned to that endpoint), signed with the
  service-provider key through the same shared redirect-binding signer. It is
  emitted **only on the success path** - every rejection keeps the uniform 400,
  so no rejection cause can leak through a status-bearing response - and is
  **fail-safe**: with no SLO endpoint or no loadable signing key the endpoint
  answers a bare `200` (an unsigned response is never emitted). Any inbound
  `RelayState` is echoed only within the 80-byte SAML binding cap. Logout events
  (`LogoutRequested`/`LogoutRejected`) are audited by reason code - never raw
  `NameID`/`SessionIndex` - and the inbound endpoint is rate-limited.

## EU Cyber Resilience Act (CRA) position

- **This is a non-commercial FLOSS project.** It is developed and published
  without monetization of any kind, which places it outside the CRA's
  manufacturer obligations; the project also matches the spirit of the CRA's
  **open-source software steward** role (Art. 24), whose obligations it meets
  voluntarily: this document **is** the project's coordinated
  vulnerability-handling and cybersecurity policy (reporting channel, response
  expectations, supported versions above), and actively-exploited
  vulnerabilities would be handled through the private-advisory process
  described here.
- **No conformity claim.** The project does **not** claim CRA conformity or CE
  marking, and nothing here should be read as such - the statements above
  describe only which obligations are voluntarily met.
- **Commercial redistributors carry their own obligations.** Anyone who
  integrates or redistributes this plugin **commercially** becomes responsible
  for the CRA manufacturer obligations for their product; this project's
  artifacts help (release provenance and checksums above, a dependency SBOM is
  planned - [#763](https://github.com/Flowfin/jellyfin-plugin-sso/issues/763)
  tracks OpenVEX), but do not transfer that responsibility.
