#!/usr/bin/env bash
# The start-up pass that seals password-less SSO accounts, exercised against a real server for the
# first time (#1440). The plugin ships two halves against that defect: the create arm, which the
# canonical harness already proves, and this pass, which has never run outside a unit test. The issue
# says why the two had not been exercised together - reaching the pass needs a server that already
# holds a password-less linked account, and every account the stack makes is made by a current build,
# which no longer produces one.
#
# THIS PHASE MAKES THAT ACCOUNT RATHER THAN WAITING FOR ONE. It puts alice into the exact shape a
# build up to v3.4.0.2 stored her in - routed at Jellyfin's built-in password provider with no
# password - through the server's own admin API, and only then restarts.
#
# THE SEED IS ALSO THE CONTROL, and without it this phase would be worth nothing. It asserts that the
# empty password MINTS A SESSION on the seeded account before the restart. A run that skipped that
# and only checked the refusal afterwards would pass identically on a build whose sweep does nothing,
# because alice is refused for a second reason the whole time: her routing. The control is what makes
# the refusal afterwards attributable to the password the pass minted.
#
# It runs on the HOST rather than inside the harness container, like the phases beside it: it has to
# restart Jellyfin, and the harness mounts only /harness. The readings are HTTP, so they happen in a
# probe container on the compose network - Jellyfin publishes no port to the host.
#
# The shape:
#
#   arrange   alice is repointed at the built-in password provider, dropped from administrator, and
#             her password is reset away. The admin flag has to go: Jellyfin refuses to empty an
#             administrator's password, and the first run of this phase died at exactly that, on a
#             400 from the reset, because the role this stack maps makes her one.
#   control   the empty password mints a session on her, so the door is demonstrably open.
#   restart   Jellyfin comes back and the plugin's hosted start-up service runs the pass.
#   assert    she holds a password again, the empty one is refused, her ROUTING is untouched, and the
#             audit line names one sealed account.
#   restore   the routing and the admin flag go back to what the probe read before it changed
#             anything, and a RELOGIN_ONLY pass proves the stack was left working rather than merely
#             left.
#
# Never `docker compose down` here: that removes Keycloak, the realm is re-imported into a fresh
# instance with a NEW SAML signing certificate, and the certificate the canonical pass wrote into the
# plugin's SAML configuration would no longer match. `stop` and `start` keep the containers.
set -euo pipefail

COMPOSE="${COMPOSE:-test/e2e/docker-compose.yml}"
CONFIG="${CONFIG:-test/e2e/jellyfin/config/plugins/configurations/SSO-Auth.xml}"

log() { printf '%s\n' "== $* =="; }
die() { printf '::error::%s\n' "$*" >&2; exit 1; }
pass() { printf 'PASS: %s\n' "$*"; }

PHASES_DIR="${PHASES_DIR:-$(cd "$(dirname "$0")" && pwd)}"
BUILTIN_PROVIDER="Jellyfin.Server.Implementations.Users.DefaultAuthenticationProvider"

log "Preconditions"
[ -s "$CONFIG" ] || die "the plugin persisted no configuration at $CONFIG - run the canonical pass first"
grep -q '<CanonicalLinks' "$CONFIG" \
    || die "no <CanonicalLinks> element in $CONFIG - the sweep's population is the accounts a canonical link names, so with none there the pass would correctly seal nothing and this phase would prove nothing"
pass "the persisted configuration is present and carries canonical links"

# The probe runs in a container on the harness network, the way the budget probe beside it does. A
# FILE rather than a string through `sh -c`, for the reason probe-oid-start.sh gives: a script that
# arrives as one argument through two layers is not readable in the log it fails in.
probe() { # $1 stage, $2.. extra -e arguments
    stage="$1"; shift
    docker compose -f "$COMPOSE" run --rm --no-deps -T \
        -v "$PHASES_DIR:/probe:ro" "$@" \
        --entrypoint sh harness /probe/probe-passwordless-sweep.sh "$stage"
}

field() { printf '%s\n' "$1" | sed -n "s/^$2 //p" | tail -1; }

log "Starting the stack"
# The phase before this one ends with `docker compose up --abort-on-container-exit`, which stops every
# container when the harness exits, so this phase inherits a stopped stack. Keycloak is started too:
# forgetting it cost a run on the phase beside this one, because the plugin's readiness route answers
# only once discovery can be read.
docker compose -f "$COMPOSE" start jellyfin keycloak >/dev/null
pass "Jellyfin and Keycloak are running"

log "Seeding the pre-v3.5.0.0 account shape on alice"
SEED_OUT="$(probe seed)" || die "the seed probe container could not be started"
printf '%s\n' "$SEED_OUT" | sed 's/^/  probe| /'

ALICE_ID="$(field "$SEED_OUT" PROBE-ALICE-ID)"
[ -n "$ALICE_ID" ] || die "the probe found no account named alice - its own output is above"
# Read from the probe's FIRST reading, before it changed anything, so the restore at the end puts back
# what the canonical pass left rather than what this phase happens to expect.
BEFORE_BLOCK="$(printf '%s' "$SEED_OUT" | sed -n '/^PROBE-BEFORE-SEED$/,/^PROBE-POLICY-STATUS/p')"
PROVIDER_BEFORE="$(printf '%s' "$BEFORE_BLOCK" | sed -n 's/^PROBE-PROVIDER //p' | head -1)"
ADMIN_BEFORE="$(printf '%s' "$BEFORE_BLOCK" | sed -n 's/^PROBE-ADMIN //p' | head -1)"
[ -n "$PROVIDER_BEFORE" ] && [ "$PROVIDER_BEFORE" != "null" ] \
    || die "could not read the provider id alice carried before this phase touched her, so the restore would be a guess"
case "$ADMIN_BEFORE" in
    true|false) : ;;
    *) die "could not read whether alice was an administrator before this phase touched her (got '$ADMIN_BEFORE'), so the restore would be a guess" ;;
esac
pass "alice is $ALICE_ID, routed at $PROVIDER_BEFORE with IsAdministrator=$ADMIN_BEFORE before this phase"

SEEDED_HASPASSWORD="$(printf '%s' "$SEED_OUT" | sed -n '/^PROBE-AFTER-SEED$/,$p' | sed -n 's/^PROBE-HASPASSWORD //p' | head -1)"
SEEDED_PROVIDER="$(printf '%s' "$SEED_OUT" | sed -n '/^PROBE-AFTER-SEED$/,$p' | sed -n 's/^PROBE-PROVIDER //p' | head -1)"
SEEDED_EMPTY="$(field "$SEED_OUT" PROBE-EMPTY-PASSWORD)"
SEEDED_RESET="$(field "$SEED_OUT" PROBE-RESET-STATUS)"

[ "$SEEDED_PROVIDER" = "$BUILTIN_PROVIDER" ] \
    || die "alice is routed at '$SEEDED_PROVIDER' rather than the built-in password provider, so the seed did not produce the shape this phase is about"
# THE PRECONDITION IS THE RESET, NOT WHAT THE DTO SAYS ABOUT IT (#1469). This asserted
# HasPassword=false, and that reading does not survive the server generation: on Jellyfin 12.0-rc2 an
# account whose stored password has just been reset away still reports HasPassword and
# HasConfiguredPassword TRUE, while the empty password mints a session for it. Measured on run
# 33358957106, where the sweep then sealed exactly that account:
#
#   PROBE-1469-READINGS seeded_haspassword=true sealed_haspassword=true seeded_empty=200 sealed_empty=401
#   [SSO Audit] Sealed 1 SSO-linked account(s) that had no stored password: ...
#
# The audit line is the plugin reporting on user.Password itself - the sweep emits it only where
# string.IsNullOrEmpty(user.Password) was true - so the stored password IS empty on that generation and
# the DTO derivation is what moved. The guard below therefore asserts the two things that hold on both:
# that the reset SUCCEEDED, and (as the control, further down) that the empty password mints a session.
#
# 2xx rather than 204 exactly: the point is that the server accepted the reset. A 400 is the case the
# old message named - Jellyfin refuses to empty an ADMINISTRATOR's password, which the first run of this
# phase hit - and it is still caught here, one reading earlier than before.
case "$SEEDED_RESET" in
    2*) : ;;
    *) die "the password reset on alice answered HTTP ${SEEDED_RESET:-<nothing>} rather than a 2xx, so she was never put into the shape this phase is about and a green result below would mean nothing. Jellyfin refuses to empty an ADMINISTRATOR's password, which is what the first run of this phase hit: the seed drops that flag and the restore puts it back" ;;
esac
# Reported, never asserted: on the JF12 line both of these read true for an account whose stored password
# is empty, so a reader comparing two runs sees the divergence rather than meeting it as a red gate.
printf '  dto| HasPassword=%s after the reset (not a precondition - see above)\n' "$SEEDED_HASPASSWORD"
pass "alice is seeded: routed at the built-in password provider, and the reset was accepted (HTTP $SEEDED_RESET)"

log "The control: the door is open before the restart"
[ "$SEEDED_EMPTY" = "200" ] \
    || die "the EMPTY password answered $SEEDED_EMPTY on the seeded account rather than minting a session. The seed did not open the door, so a refusal after the restart would not be attributable to the start-up pass - which is the only thing this phase exists to show"
pass "the empty password mints a session on the seeded account (HTTP $SEEDED_EMPTY) - the door is open"

log "Restarting Jellyfin so the start-up pass runs"
docker compose -f "$COMPOSE" stop jellyfin >/dev/null
docker compose -f "$COMPOSE" start jellyfin >/dev/null
VERIFY_OUT="$(probe verify)" || die "the verify probe container could not be started"
printf '%s\n' "$VERIFY_OUT" | sed 's/^/  probe| /'

SEALED_HASPASSWORD="$(field "$VERIFY_OUT" PROBE-HASPASSWORD)"
SEALED_PROVIDER="$(field "$VERIFY_OUT" PROBE-PROVIDER)"
SEALED_EMPTY="$(field "$VERIFY_OUT" PROBE-EMPTY-PASSWORD)"

log "Asserting"
# VACUOUS ON THE JF12 LINE AND KEPT ANYWAY (#1469). On 10.11 this moves false -> true across the restart
# and is the sealing. On 12.0 it reads true on both sides of it, so it asserts nothing there - the two
# readings that do are the empty-password refusal and the audit line below, and both are generation-
# independent. Kept because it still bites on the 10.11 line, which is the generation the shipped
# artifact runs on.
[ "$SEALED_HASPASSWORD" = "true" ] \
    || die "alice still holds no password after the restart (HasPassword=$SEALED_HASPASSWORD) - the start-up pass did not seal an account that was exactly its population"
pass "alice holds a password again after the restart"

[ "$SEALED_EMPTY" != "200" ] \
    || die "the EMPTY password STILL mints a session for alice after the restart - the account remains reachable without the identity provider, which is the whole of #1440"
pass "the empty password is refused on the sealed account (HTTP $SEALED_EMPTY)"

# The pass writes one field and the issue says so in as many words: it never changes an account's
# login routing. Asserted because a pass that repointed the account would ALSO produce the refusal
# above, and would be a different and much larger change than the one that shipped.
[ "$SEALED_PROVIDER" = "$BUILTIN_PROVIDER" ] \
    || die "alice's routing moved from '$BUILTIN_PROVIDER' to '$SEALED_PROVIDER' across the restart - the pass is meant to write a password and nothing else"
pass "alice's login routing is untouched by the pass, still $BUILTIN_PROVIDER"

log "The audit line"
# Quoted rather than paraphrased, against the leading words of what SsoAudit.PasswordlessAccountsSealed
# emits. Only the stable head of the message is matched: the tail explains the population in a sentence
# that may be reworded, and pinning the whole of it would redden this phase for a documentation edit.
AUDIT="$(docker compose -f "$COMPOSE" logs jellyfin 2>/dev/null | grep -F 'Sealed' | grep -F 'SSO-linked account' | tail -3)"
[ -n "$AUDIT" ] \
    || die "the Jellyfin log carries no line about sealed SSO-linked accounts, so the pass either did not run or sealed silently - an operator meeting this on a real server would have no record of it at all"
printf '%s\n' "$AUDIT" | sed 's/^/  log| /'
printf '%s\n' "$AUDIT" | grep -qE 'Sealed 1 SSO-linked account' \
    || die "the audit line does not name ONE sealed account. Exactly one was seeded, so a different count means the pass reached accounts this phase did not put in front of it"
pass "the pass audited exactly one sealed account"

log "Putting alice's routing and admin flag back"
RESTORE_OUT="$(probe restore -e "RESTORE_PROVIDER=$PROVIDER_BEFORE" -e "RESTORE_ADMIN=$ADMIN_BEFORE")" || die "the restore probe container could not be started"
printf '%s\n' "$RESTORE_OUT" | sed 's/^/  probe| /'
[ "$(field "$RESTORE_OUT" PROBE-PROVIDER)" = "$PROVIDER_BEFORE" ] \
    || die "alice's routing is not back at $PROVIDER_BEFORE, so this phase left the stack in a state the canonical pass did not create"
[ "$(field "$RESTORE_OUT" PROBE-ADMIN)" = "$ADMIN_BEFORE" ] \
    || die "alice's IsAdministrator is not back at $ADMIN_BEFORE, so this phase left the stack in a state the canonical pass did not create"
docker compose -f "$COMPOSE" stop >/dev/null
pass "alice is routed and privileged as the canonical pass left her"

log "A login after the restore"
# STOPPED above and brought up by this `up` rather than started separately, for the reason the phase
# beside this one records: `start` returns when the container is running, not when the server is
# listening, and the harness then races it. RELOGIN_ONLY skips the seed, the wizard and the two
# provider Add calls and reads the persisted configuration back (#1123).
RELOGIN_ONLY=true docker compose -f "$COMPOSE" up \
    --abort-on-container-exit --exit-code-from harness \
    || die "the login after the restore failed - the phase left the stack broken rather than as it found it"
pass "the stack still logs in, and phase 6e still refuses the manual form for alice"

printf '\nPASSWORDLESS ACCOUNT SWEEP PHASE PASSED\n'
