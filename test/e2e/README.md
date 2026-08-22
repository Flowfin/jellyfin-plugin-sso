# End-to-end SSO login harness

An automated, reproducible end-to-end login test (#720/#727) that boots a **real Jellyfin 10.11
server with the packaged plugin installed** and a **real Keycloak identity provider**, then drives
full login round-trips headlessly and asserts the outcomes. It supplements - it does **not** replace -
the manual `Release-QA-Checklist`.

It runs in CI via [`.github/workflows/e2e-login.yml`](../../.github/workflows/e2e-login.yml) and can
be run locally with one command once you have built the plugin.

## Provider matrix (release/beta, or an explicit dispatch)

Keycloak is the **canonical** harness and the only one that runs on a pull request touching the harness,
on the nightly schedule, and on a **default** manual dispatch (there is deliberately no `push` trigger -
the PR run already validated it). Additional self-hostable identity providers get their own harness under
`test/e2e/<provider>/`. **Authelia** (`test/e2e/authelia/`, OIDC), **authentik**
(`test/e2e/authentik/`, OIDC **and** SAML), **Dex** (`test/e2e/dex/`, OIDC), **Zitadel**
(`test/e2e/zitadel/`, OIDC), **Pocket ID** (`test/e2e/pocket-id/`, OIDC) and **Kanidm**
(`test/e2e/kanidm/`, OIDC) are all implemented - every self-hostable provider in the README table now has
one. The programme is tracked in
[#919](https://github.com/iderex/jellyfin-plugin-sso/issues/919). The **full provider matrix runs at a
release and a beta-release** - never on a routine merge, so the cross-provider pass is release-gate
evidence, not a per-commit cost - **and on a manual dispatch with `providers: all`**, which is how a newly
added harness is proven green before a release rather than on release day. A provider joins that matrix by
adding one `{ name, compose }` object to the list in the workflow's `select` job, pointing at its
`test/e2e/<provider>/docker-compose.yml`.
Cloud providers (Google, Entra ID) cannot run in ephemeral CI, so they are verified manually and marked as
such in the README provider table.

The shared driver (`harness/harness.sh`) keeps the Jellyfin setup and the assertions common and swaps only
the provider-specific browser login (`idp_oidc_login` / `idp_saml_login`, selected by `IDP_KIND`): Keycloak
and Dex render a server-side HTML form (differing only in the form's user field name, a parameter, and in
whether the form action is absolute or site-relative, which the driver detects), Zitadel is a **chain** of
single-form pages (login name → password → a two-factor setup prompt this stack skips) driven generically by
each page's form action - an action the driver does not know is a loud failure naming it, never a silent
skip. Authelia is a single JSON
first-factor call, and
authentik is a **stateful
multi-stage flow-executor** that CHAINS flows (the authentication flow, then the provider's authorization
flow) and must be driven with exactly one request per step - for SAML it ends in an `autosubmit` stage that
carries the POST-binding fields as JSON rather than rendered HTML, which the driver renders back into the
equivalent form so the shared parser can consume it. Provider
shape is passed entirely through the
compose `environment` (issuer/discovery, the role claim and scopes, `RUN_SAML`, whether to load the
profile, and `DISABLE_HTTPS`), so the defaults reproduce the Keycloak run unchanged. The **Authelia**
harness additionally serves TLS with a self-signed cert (Authelia 4.38 requires a secure session URL); the
cert is appended to Jellyfin's system CA bundle at container start (never replacing it) and trusted by the
harness via `CURL_CA_BUNDLE`, so the plugin's real https OIDC path is exercised.

**Kanidm has the hardest bootstrap and the strictest defaults.** It is TLS-only, ships **no shell** in its
image (so its container command cannot sequence `recover-account` before `server`), has no provisioning file
and no default admin password. The way in is its **admin unix socket**, which speaks one-line JSON and hands
out a recovery password - so its `/data` is a **named volume** the harness mounts too; over a bind mount the
socket file appears but every connect is refused, which would break the local run. Three further defaults
shape the harness and are worth knowing before configuring Kanidm for real:

- Its account policy **requires MFA**, so a password-only credential cannot be committed
  (`can_commit=false, warnings=["MfaRequired"]`). The harness relaxes it deliberately; a real deployment
  should not.
- Its OAuth2 **scope map is what grants access to the client at all**. Mapping it onto the role group would
  make Kanidm itself refuse `bob` with a 403 and the plugin's role gate would never be reached, so the
  harness uses **two** groups: `jellyfin-users` grants both users access, `jellyfin-access` is the role the
  plugin gates on and only `alice` holds it. That is also how a real deployment should separate "may use
  this app" from "has this role".
- Its `groups` claim carries **SPNs** (`jellyfin-access@idm.example.com`), not bare names, so the allow-list
  is spelled that way. So does `preferred_username`, until the resource server opts into
  `prefer_short_username` - which the seeding does, because otherwise every Jellyfin account would be named
  `alice@idm.example.com`. Pointing the plugin at the `name` claim instead looks like it works and is
  wrong: `name` is the OIDC profile claim and carries the **display name**. The harness seeds display names
  that are unlike the usernames precisely so its `Name='alice'` assertion can tell the two apart - with them
  seeded equal, as they were in the first draft, it would have passed either way.

Together with Authelia it is one of the two harnesses exercising the plugin's real https path, and its
`ES256` signing is what the widened asymmetric-algorithm assertion exists for.

**Pocket ID has no password login at all** - it authenticates with passkeys only. The browser role is
played through the provider's own **one-time-access-token** flow, the mechanism it ships for a lost passkey:
a token is exchanged for the same session cookie a passkey login would mint. Its `/authorize` is a
single-page app rather than an endpoint, so the driver posts the authorize request to Pocket ID's API
exactly as that page does - taking every parameter from the URL the **plugin** issued, so the test keeps
exercising what the plugin actually sends. The response carries the issuer, which the callback must include:
the plugin enforces the **RFC 9207 mix-up check** and refuses an authorization response whose `iss` is
absent or wrong. Its one cost is stated in its compose file: a fresh Pocket ID has no non-interactive way in
at all, so the harness seeds the first admin and the one-time tokens directly into its SQLite file - the
only place in this matrix that reaches past a provider's API into its database. A schema change there
breaks the harness rather than the plugin: a false red, never a false green.

**Zitadel is the one provider that cannot be seeded from a file.** Only its first instance, org and a
machine account with a personal access token come from environment; the project, the OIDC application, the
role and the user grants exist only through its management API - and the client id and secret are
_generated_ by that call, so they can only be known after seeding. The harness therefore seeds it in a
Phase-0b step before any assertion, using the token Zitadel writes to a shared volume. Two Zitadel quirks
are handled there and documented in its compose file: it panics at startup without an RFC1918 address (so
it identifies itself by hostname instead, since these networks are deliberately public-looking), and it
publishes an **empty JWKS** until its `webKey` feature is enabled - which makes every login fail with
`invalid_signature` and nothing in the login path say why. Its roles arrive as an **object map**, read
through the plugin's `RoleClaimIsObjectMap` option (#934).

## What it verifies

- The **packaged JPRM zip** loads on Linux (the `#181` packaged-crypto-DLL load path that
  `dotnet test` cannot see), proven by the plugin's anonymous `GET /sso/OID/GetNames` listing the
  configured, enabled provider.
- A **full OIDC round-trip** for `alice` (challenge → Keycloak login → callback → `OID/Auth`) mints a
  Jellyfin session token that works against `GET /Users/Me`.
- A **full SAML round-trip** for `carol` (challenge → Keycloak login → ACS POST → `SAML/Auth`) mints a
  Jellyfin session token that works against `GET /Users/Me` - exercising the packaged SAML crypto DLLs
  (#181) and the signed-assertion validation path.
- **Asymmetric id_token signing**: the provider's discovery must advertise an **asymmetric** algorithm
  (any of `RS*`/`ES*`/`PS*`/`EdDSA` - not RS256 alone, since a correctly configured provider may default to
  ES256) **and its JWKS must publish at least one key**. An identity provider that falls back to symmetric
  HS256 (authentik does this when its provider has no signing key), or that advertises RS256 while
  publishing an empty key set (Zitadel, until its `webKey` feature is enabled), makes the plugin reject
  every login with `invalid_signature`, so both halves are asserted before any login is driven.
- **Role gating**: `bob` (OIDC) and `dave` (SAML), who lack the `jellyfin-access` role, are refused at
  the callback - and the refusal must be the role gate's **exact HTTP 401**, not merely "some error", so a
  token-exchange failure or a 500 cannot masquerade as a passing role-gate test. A provider that cannot
  express group membership at all (Dex's local password database) is configured with an **empty allow-list**
  and the phase is skipped - driven off that one configured value, so a run can never skip a gate it did
  configure, nor assert one it did not.
- **Fail-closed negatives**: a replayed one-time OIDC state, and a replayed one-time SAML login-outcome
  token, are both refused - and, like the role gate, with the redeem miss's **exact HTTP 400**, so a
  connection failure, a throttle or a 500 cannot masquerade as "one-time-use holds".

## Architecture (avoiding the issuer-hostname trap)

Everything runs in one `docker compose` stack on a shared network, **including the harness**. Every
service is addressed by its service-DNS name, so the OIDC issuer and redirect URLs are byte-identical
whether Jellyfin resolves them server-to-server (discovery, token exchange) or the harness resolves
them in its browser role:

- issuer: `http://keycloak:8080/realms/e2e`
- Jellyfin: `http://jellyfin:8096`
- plugin redirect: `http://jellyfin:8096/sso/OID/redirect/keycloak`

The Keycloak realm (`test/e2e/keycloak/e2e-realm.json`) defines the `jellyfin-oidc` and `jellyfin-saml`
clients, the `jellyfin-access` realm role, and four users: `alice`/`carol` (in the role) and
`bob`/`dave` (not). OIDC uses `alice`/`bob`; SAML uses the distinct `carol`/`dave` so the two protocols
never contend over the same Jellyfin account. A protocol mapper emits the realm roles into the id_token
as `realm_access.roles` (read by the plugin's OIDC `RoleClaim`) and into the SAML assertion as a `Role`
attribute (read by the SAML role gate). The SAML IdP signing certificate is fetched at run time from
Keycloak's SAML descriptor and configured through the plugin's `SAML/Add` admin API.

## Run it locally

Local Docker must be working. The harness installs the **packaged** plugin, so build the zip first.

```sh
# 1. Build the packaged plugin zip (requires the .NET 9 SDK and JPRM: `pip install jprm`).
#    jprm refuses an output directory that does not exist, and `artifacts/` is git-ignored,
#    so a clean checkout has to create it. Everything jprm reports goes to stderr except the
#    path of the archive it wrote, which is its only line of stdout - capture that instead of
#    naming the file, because the name is derived from `name:` in build.yaml and moves with it.
mkdir -p ./artifacts
plugin_zip=$(jprm --verbosity=debug plugin build . --output ./artifacts --dotnet-framework net9.0)

# 2. Unpack it into the Jellyfin plugins directory the compose stack mounts.
mkdir -p test/e2e/jellyfin/config/plugins/SSO-Auth
unzip -o "$plugin_zip" -d test/e2e/jellyfin/config/plugins/SSO-Auth
chmod -R 0777 test/e2e/jellyfin

# 3. Boot the stack and run the harness (its exit code is the run's exit code).
docker compose -f test/e2e/docker-compose.yml up \
  --abort-on-container-exit --exit-code-from harness

# 4. Tear down.
docker compose -f test/e2e/docker-compose.yml down -v
```

A green run prints `ALL E2E CHECKS PASSED`. In CI, container logs are dumped automatically on
failure.

### A second pass over the same server (`RELOGIN_ONLY`)

Step 3 configures everything it then asserts, which overwrites exactly the state a mutation test
needs to survive. `RELOGIN_ONLY=true` runs the same driver without any of that setup: the
identity-provider seed, the Jellyfin first-run wizard and the two provider `Add` calls are skipped
and reported as skipped, the admin token and the provider configuration are read back from the
persisted `/config`, and every login round-trip and assertion runs as before. So a phase can change
server state and a following pass can observe what the logins do with it.

```sh
# First pass: the ordinary run above, which initialises Jellyfin and configures both providers.
docker compose -f test/e2e/docker-compose.yml up \
  --abort-on-container-exit --exit-code-from harness

# Second pass: same stack, no reconfiguration.
RELOGIN_ONLY=true docker compose -f test/e2e/docker-compose.yml up \
  --abort-on-container-exit --exit-code-from harness
```

Run the second pass with `up` on the stopped stack rather than after a `down`. Only the harness
container's environment changed, so Keycloak and Jellyfin restart in place and keep the realm's SAML
signing key. A `down` removes the Keycloak container, the realm is re-imported into a fresh instance
with a **new** signing certificate, and the certificate the first pass wrote into the plugin's SAML
configuration no longer matches the assertions the IdP signs.

A relogin-only pass refuses to run against an uninitialised server: it needs a Jellyfin whose wizard
is already complete and whose provider configuration is already persisted, so pointing it at a wiped
`test/e2e/jellyfin/config` is a fatal error rather than a silent re-initialisation.

### Legacy plaintext secret migrates on load

`test/e2e/phases/legacy-secret-migration.sh` is a phase built on that second pass. It replaces the
persisted `ssoenc:v1` envelope with the plaintext a pre-#158 configuration carried, restarts Jellyfin
against it, and requires two things: the login keeps working, and the value is rewritten as an
envelope with the plaintext gone from the file. A third pass then drives one more login, so the login
that proves the migrated secret still decrypts is one made after the envelope exists.

It runs on the host rather than in the harness container, which mounts only `/harness` and can
therefore neither read the persisted configuration nor restart Jellyfin. Run it after a green
canonical pass, with the stack stopped but not torn down:

```sh
docker compose -f test/e2e/docker-compose.yml up \
  --abort-on-container-exit --exit-code-from harness

test/e2e/phases/legacy-secret-migration.sh
```

A green run prints `LEGACY SECRET MIGRATION PHASE PASSED`. In CI it runs on a release, a beta
release, or a `providers: all` dispatch, on the Keycloak entry only.

### Losing the at-rest key fails closed

`test/e2e/phases/kek-loss-fails-closed.sh` takes away the key that wraps the provider secrets and
requires the next login to be refused rather than fall back to plaintext or mint a replacement key.
It renames the key aside and renames it back, because a regenerated key is a different key: the
stored envelope would not open under it and the phase would end up proving that a restored backup
fails. After the key is back a `RELOGIN_ONLY` pass must go green, so the phase proves fail-closed
rather than a permanently broken stack.

A rename rather than a copy, and that is forced rather than chosen. The server writes the key as
root inside the container with owner-only permissions, so on the bind mount nothing running as the
ordinary user can read it. Renaming needs write and execute on the directory and no permission at
all on the file, and it is the stronger statement anyway: the file that comes back is the same
inode, which the phase pins, so "byte for byte" is a property of the operation rather than a
checksum to trust.

The refusal is driven by the phase itself, one request against `/sso/OID/start/<provider>`, and the
same endpoint is probed **before** the key goes away. The harness exits non-zero on any failed
login, so its exit code alone cannot separate a fail-closed refusal from a stack that broke for an
unrelated reason; the control probe is what makes the refusal attributable. Jellyfin publishes no
port to the host, so both probes run in a throwaway container on the compose network, running
`test/e2e/phases/probe-oid-start.sh` from a read-only bind mount. That probe never exits non-zero:
it reports its own failures as `PROBE-ERROR` lines and the phase decides what a missing answer
means, so a broken probe cannot be read as a refused login.

The key lives inside the unpacked plugin drop, at
`test/e2e/jellyfin/config/plugins/SSO-Auth/sso-secret.key`, rather than beside the configuration.
Run the phase after a green canonical pass, on the stopped but not torn-down stack:

```sh
docker compose -f test/e2e/docker-compose.yml up \
  --abort-on-container-exit --exit-code-from harness

bash test/e2e/phases/kek-loss-fails-closed.sh
```

Through `bash`, because every tracked `.sh` in this repository is mode 644 and none of them carries
an executable bit.

A green run prints `KEK LOSS FAILS CLOSED PHASE PASSED`. In CI it runs under the same gate as the
migration phase and immediately ahead of it. Its precondition is an `ssoenc:v1` envelope in the
persisted configuration, which the secrets-at-rest assertion has just made, and taking the key away
from a stack whose secret is plaintext proves nothing: that is the documented genuine-first-run
path, where the server mints a fresh key and every login succeeds. The phase asserts the envelope
itself rather than assuming what ran before it, and it leaves the stack as it found it.

### Two clients behind one proxy are budgeted apart

`test/e2e/phases/proxy-client-attribution.sh` puts an nginx front end in front of Jellyfin, names it
in the server's known proxies, and requires that exhausting one forwarded client's rate-limit budget
does not throttle a second forwarded client arriving through the same proxy. Until it existed
nothing here put a proxy in front of Jellyfin at all, and a regression that collapsed every client
behind a proxy into one bucket would have locked a whole site out on one client's noise.

**What is under test is not what it looks like.** The plugin deliberately never reads
`X-Forwarded-For`: `SsoRateLimiter` documents the connection's remote address as the only input,
because a client-supplied header would let an attacker rotate keys to evade the limiter or pin a
victim's address to lock them out. What the phase proves is that the plugin sits correctly on top of
the host's forwarded-headers handling. The known-proxies setting is therefore written by the phase
rather than assumed; without it both clients collapse to the proxy and the run would red for a
configuration reason rather than a plugin one.

**The forwarded addresses are not arbitrary.** `SsoRateLimiter.NormalizeClientKey` refuses to
attribute a non-public source at all, and the documentation ranges somebody reaches for first
(`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`) are all blocked by `IpAddressClassifier`. A
phase written with them would exhaust nothing, prove nothing, and look like a passing test. The two
clients are on `11.0.9.0/24`, for the same reason the harness network itself is on `11.0.0.0/24`,
and outside that subnet so they cannot collide with a container.

**The assertion that carries the phase is the second client's first request.** If the limiter keyed
on the proxy hop, the first client's exhaustion would be the second client's exhaustion, and that
request would answer 429. A control request before the exhaust loop keeps the 429 attributable: a
stack that was already refusing would produce one for free.

The proxy sits behind a compose profile, so an ordinary `docker compose up` of this stack never
starts it and the per-PR path is unchanged. The phase edits only Jellyfin's own persisted files, the
plugin configuration and the network configuration, copies both aside first and puts them back on
every exit path, and finishes with a `RELOGIN_ONLY` pass so it proves the stack was left working
rather than merely left.

The audit half of #1125 is deliberately absent. The audit trail records no client address and is not
going to start, so there is nothing there to assert against.

### The SAML signing certificate is rotated mid-run

`test/e2e/phases/saml-cert-rollover.sh` rotates the Keycloak realm's SAML signing key while the stack
is up, imports the new certificate into the plugin, and requires three things in one run: an
assertion signed by the rotated-in key mints a usable Jellyfin session, an assertion signed by the
retired key is refused with a pinned 400, and the plugin's stored `SamlCertificate` observably
changes across the rotation. The wrong-certificate rejection is unit covered and a live rotation was
demonstrated by hand once in the #717 pass, but nothing had driven rotate-then-relogin end to end.

**The old-certificate assertion is a fresh one, not a replay,** and the difference is the whole
value of the phase. A replayed assertion is refused by the one-time cache whatever certificate the
plugin holds, so a 400 would have proved the replay guard rather than the rotation. Every assertion
here comes from its own `/start` and is never presented twice, so the only thing wrong with the
refused one is the key that signed it. The plugin answers both cases with the same uniform body,
which is exactly why the two must not be confused at the door.

**The falsifier is the part to read.** A refusal sitting between two successes could be the clock
rather than the certificate: assertions carry a `NotOnOrAfter` and rotating takes time. So a second
pre-rotation assertion is captured in the same breath as the first, held through the rotation, and
posted after the original certificate has been imported back. It is strictly older at that moment
than the refused one was at its refusal, and it is accepted. If age explained the refusal, it would
be refused too.

The rotation adds an `rsa-generated` key provider at a higher priority rather than disabling the old
one, so the retired key stays in the realm and merely stops being used, and deleting the added
component at the end restores the realm exactly. Disabling would also remove the key from the JWKS
the OpenID half of this stack reads, which is a second change the phase is not about.

It authenticates as `realmadmin`, a user of the e2e realm seeded with the realm-management
`realm-admin` role, and not as the server's bootstrap administrator. That is forced rather than
chosen: the master realm keeps Keycloak's default `sslRequired: external`, which refuses a plaintext
request from any address Keycloak does not treat as private, and this compose network sits on
`11.0.0.0/24` precisely because the plugin's SSRF guard has to treat it as public. The e2e realm sets
`sslRequired: none`, so a realm-admin token minted there is the route to the admin API that this
stack's plaintext http leaves open.

Like the two phases above it, the work happens in a throwaway container on the compose network
(`test/e2e/phases/probe-saml-rollover.sh`), because neither Jellyfin nor Keycloak publishes a port to
the host, and the probe never exits non-zero: it reports `PROBE-PASS` / `PROBE-FAIL` / `PROBE-ERROR`
lines and the host half decides what each one means. A transcript with no final `PROBE-DONE` line is
a failure here rather than a clean pass, because a probe killed half way leaves exactly the same
absence of failures as one that passed. The host half is what reads the persisted configuration off
the bind mount, so the claim that the stored certificate changed rests on the file on disk and not
only on what the plugin says about itself.

Run it after a green canonical pass, on the stopped but not torn-down stack:

```sh
docker compose -f test/e2e/docker-compose.yml up \
  --abort-on-container-exit --exit-code-from harness

bash test/e2e/phases/saml-cert-rollover.sh
```

A green run prints `SAML SIGNING-CERT ROLLOVER PHASE PASSED`. In CI it runs under the same gate as
the two phases above and last of the three, because it is the only one that writes to the identity
provider rather than to Jellyfin.

**The Zitadel, Pocket ID and Kanidm stacks cannot be re-run in place.** Every other provider is seeded from a file
(an imported realm, a reapplied blueprint, or a static config) and the driver deliberately reuses an
already-initialised Jellyfin. These three are seeded imperatively against stateful storage and their seeds
are not idempotent: a second `up` on the same stack hits `ALREADY_EXISTS` on Zitadel's project create, a
duplicate-primary-key error on Pocket ID's bootstrap admin, or an already-exists error on Kanidm's groups,
and dies there. Always tear them down with `down -v` between runs - that also drops the volumes holding
Zitadel's access token, Pocket ID's database, and Kanidm's database and admin socket. CI is unaffected: each
matrix entry gets a fresh runner and tears the stack down with `-v`.

**Running more than one provider locally:** every provider's compose bind-mounts the same
`test/e2e/jellyfin/config`, and `docker compose down -v` does not clear a bind mount. Wipe it (and re-unpack
the plugin) between providers - otherwise the second run reuses a Jellyfin that already completed the wizard
and already has `alice` linked to the first provider, which is not what CI does (each matrix entry runs on a
fresh runner).

To run the **Authelia** harness instead, generate its self-signed TLS cert first (never committed), then
point `docker compose` at its file - the plugin drop from step 2 is reused unchanged:

```sh
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout test/e2e/authelia/tls.key -out test/e2e/authelia/tls.crt \
  -days 3650 -subj "/CN=login.example.com" -addext "subjectAltName=DNS:login.example.com"

docker compose -f test/e2e/authelia/docker-compose.yml up \
  --abort-on-container-exit --exit-code-from harness
```

**Kanidm** needs its cert the same way, and skipping the step fails in a way that does not point at the
cause: Docker creates _directories_ where the certificate files should be bind-mounted, Jellyfin's
entrypoint then cannot read one, and the run dies minutes later saying Jellyfin never became ready. The
recovery is not obvious either - `openssl … -out chain.pem` then refuses because the path is a directory,
and `.gitignore` matches it, so `git status` stays clean. If that happens, delete
`test/e2e/kanidm/chain.pem` and `test/e2e/kanidm/key.pem` (they will be directories) and start over:

```sh
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout test/e2e/kanidm/key.pem -out test/e2e/kanidm/chain.pem \
  -days 3650 -subj "/CN=idm.example.com" -addext "subjectAltName=DNS:idm.example.com"

docker compose -f test/e2e/kanidm/docker-compose.yml up \
  --abort-on-container-exit --exit-code-from harness
docker compose -f test/e2e/kanidm/docker-compose.yml down -v
```
