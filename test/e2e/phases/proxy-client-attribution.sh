#!/usr/bin/env bash
# Two clients behind ONE reverse proxy are budgeted apart by the plugin's per-client rate limiter
# (#1125). Verified by hand once in the #717 live pass, and nothing in test/e2e put a proxy in
# front of Jellyfin at all until this phase, so a regression that collapsed every client behind a
# proxy into a single bucket would ship silently and lock a whole site out on one client's noise.
#
# WHAT IS UNDER TEST IS NOT WHAT IT LOOKS LIKE. The plugin deliberately never reads
# X-Forwarded-For; SsoRateLimiter documents the connection's remote address as the only input,
# because a client-supplied header would let an attacker rotate keys to evade the limiter or pin a
# victim's address to lock them out. So the thing this phase proves is that the plugin sits
# correctly on top of the host's forwarded-headers handling: with Jellyfin's own "Known proxies"
# setting naming the proxy, the real client reaches the limiter, and two of them get separate
# budgets. Without that setting both collapse to the proxy and the phase reds - which is the false
# red worth designing out, so the setting is written by this phase rather than assumed.
#
# It runs on the HOST rather than inside the harness container, like the phases beside it: the
# harness mounts only /harness, and this phase is made of edits to persisted configuration files
# and a compose profile.
#
# THE ADDRESSES ARE NOT ARBITRARY. SsoRateLimiter.NormalizeClientKey refuses to attribute a
# non-public source at all and returns null, which exempts it from throttling entirely. The
# documentation ranges somebody would reach for first - 192.0.2.0/24, 198.51.100.0/24,
# 203.0.113.0/24 - are all blocked by IpAddressClassifier, so a phase written with them would
# exhaust nothing, prove nothing, and look like a passing test. The forwarded clients are
# therefore on 11.0.9.0/24, for the same reason the harness network itself is on 11.0.0.0/24, and
# outside that subnet so they cannot collide with a container address.
#
# The shape:
#
#   arrange   the limiter is switched on with a small budget and a window long enough that it
#             cannot refill mid-run, and the proxy's address goes into Jellyfin's known proxies.
#             Both files are copied aside first and restored on every exit path.
#   restart   Jellyfin re-reads both, and the proxy comes up under its compose profile.
#   probe     a control request, then client A until it is throttled, then ONE request as client B.
#   assert    the control redirected, A was throttled, and B was not. That last one is the whole
#             phase: if the limiter had keyed on the proxy hop, A's exhaustion would be B's.
#   restore   the files go back, the proxy goes away, and a RELOGIN_ONLY pass proves the stack was
#             left working rather than merely left.
#
# Never `docker compose down` here: that removes Keycloak, the realm is re-imported into a fresh
# instance with a NEW SAML signing certificate, and the certificate the canonical pass wrote into
# the plugin's SAML configuration would no longer match. `stop` and `start` keep the containers.
set -euo pipefail

COMPOSE="${COMPOSE:-test/e2e/docker-compose.yml}"
CONFIG="${CONFIG:-test/e2e/jellyfin/config/plugins/configurations/SSO-Auth.xml}"
NETWORK_CONFIG="${NETWORK_CONFIG:-test/e2e/jellyfin/config/config/network.xml}"
JELLYFIN_DIR="${JELLYFIN_DIR:-test/e2e/jellyfin/config}"

# The proxy's fixed address on the harness network, as the compose file assigns it. Written into
# Jellyfin's known proxies below; the two must agree or the server ignores the forwarded header.
PROXY_ADDR="${PROXY_ADDR:-11.0.0.200}"
# Small enough that the exhaust loop is a handful of requests, and a window that outlives the run
# so a refill cannot hand client A a fresh budget halfway through.
MAX_ATTEMPTS="${MAX_ATTEMPTS:-2}"
WINDOW_SECONDS="${WINDOW_SECONDS:-600}"

log() { printf '%s\n' "== $* =="; }
die() { printf '::error::%s\n' "$*" >&2; exit 1; }
pass() { printf 'PASS: %s\n' "$*"; }

PHASES_DIR="${PHASES_DIR:-$(cd "$(dirname "$0")" && pwd)}"

log "Preconditions"
[ -s "$CONFIG" ] || die "the plugin persisted no configuration at $CONFIG - run the canonical pass first"
if [ ! -s "$NETWORK_CONFIG" ]; then
    printf 'configuration files found under %s:\n' "$JELLYFIN_DIR" >&2
    find "$JELLYFIN_DIR" -maxdepth 3 -name '*.xml' -print >&2 || true
    die "no Jellyfin network configuration at $NETWORK_CONFIG - without it the known-proxies setting cannot be written and the phase would red for a configuration reason rather than a plugin one"
fi
grep -q '<KnownProxies' "$NETWORK_CONFIG" \
    || die "no <KnownProxies> element in $NETWORK_CONFIG - this Jellyfin does not carry the setting this phase depends on, and writing one blindly would be a guess"
RATE_BEFORE="$(grep -o '<EnableRateLimit>[^<]*</EnableRateLimit>' "$CONFIG" | head -1)"
[ -n "$RATE_BEFORE" ] \
    || die "no <EnableRateLimit> element in $CONFIG - the phase would have nothing to switch on and nothing to put back"
pass "both configuration files are present, the known-proxies element exists, and the limiter reads $RATE_BEFORE"

CONFIG_KEPT="$CONFIG.kept"
NETWORK_KEPT="$NETWORK_CONFIG.kept"
[ ! -e "$CONFIG_KEPT" ] || die "$CONFIG_KEPT already exists - a previous run left a copy aside and this one would overwrite it"
[ ! -e "$NETWORK_KEPT" ] || die "$NETWORK_KEPT already exists - a previous run left a copy aside and this one would overwrite it"

# EVERY WRITE UNDER THE BIND MOUNT HAPPENS INSIDE A CONTAINER, and that is a constraint rather than
# a preference (#1391, measured again here). `plugins/configurations/` is created by the SERVER at
# runtime, so the `chmod -R 0777 test/e2e/jellyfin` in the install step never reaches it: that step
# runs before the stack comes up and the directory does not exist yet. Both files are written by the
# server as root, and copying one aside needs write permission on the DIRECTORY, which the ordinary
# workflow user has none of - the first run of this phase died on exactly that, at `cp`, before it
# asserted anything.
#
# The jellyfin service already bind-mounts ./jellyfin/config at /config and runs as root, so its own
# definition is the shortest route to a writable handle: no second mount to keep in step with the
# compose file, and no elevation on the host. `--no-deps` starts nothing else, `--rm` leaves nothing
# behind, and the entrypoint is replaced so no server starts in it. Reads stay on the host, where
# they work.
in_jellyfin() { # $1 the shell program to run as root against /config
    docker compose -f "$COMPOSE" run --rm --no-deps -T \
        -e "PROXY_ADDR=$PROXY_ADDR" \
        -e "MAX_ATTEMPTS=$MAX_ATTEMPTS" \
        -e "WINDOW_SECONDS=$WINDOW_SECONDS" \
        --entrypoint sh jellyfin -c "$1"
}

CONTAINER_CONFIG="/config/plugins/configurations/SSO-Auth.xml"
CONTAINER_NETWORK="/config/config/network.xml"

in_jellyfin "set -eu; cp -p '$CONTAINER_CONFIG' '$CONTAINER_CONFIG.kept'; cp -p '$CONTAINER_NETWORK' '$CONTAINER_NETWORK.kept'" \
    || die "the two configuration files could not be copied aside"

restore_config() {
    in_jellyfin "set -eu
        [ -e '$CONTAINER_CONFIG.kept' ] && mv -f '$CONTAINER_CONFIG.kept' '$CONTAINER_CONFIG'
        [ -e '$CONTAINER_NETWORK.kept' ] && mv -f '$CONTAINER_NETWORK.kept' '$CONTAINER_NETWORK'
        exit 0" >/dev/null 2>&1 || printf 'the restore on exit did not complete - check %s and %s\n' "$CONFIG" "$NETWORK_CONFIG" >&2
    docker compose -f "$COMPOSE" --profile proxy stop proxy >/dev/null 2>&1 || true
    return 0
}
trap restore_config EXIT
pass "both files are copied aside and restored on every exit path"

log "Switching the limiter on with a small budget"
# The limiter's settings are deliberately NOT importable through the API (ConfigImport refuses
# them, so a foreign document cannot silently disable a DoS control), which is why this is an edit
# to the persisted configuration and a restart rather than an HTTP call.
in_jellyfin "set -eu; sed -i \
    -e \"s|<EnableRateLimit>[^<]*</EnableRateLimit>|<EnableRateLimit>true</EnableRateLimit>|\" \
    -e \"s|<RateLimitMaxAttempts>[^<]*</RateLimitMaxAttempts>|<RateLimitMaxAttempts>\$MAX_ATTEMPTS</RateLimitMaxAttempts>|\" \
    -e \"s|<RateLimitWindowSeconds>[^<]*</RateLimitWindowSeconds>|<RateLimitWindowSeconds>\$WINDOW_SECONDS</RateLimitWindowSeconds>|\" \
    '$CONTAINER_CONFIG'" \
    || die "the limiter settings could not be written into $CONFIG"
grep -q "<EnableRateLimit>true</EnableRateLimit>" "$CONFIG" \
    || die "the limiter is still off in $CONFIG after the edit - the element was not where the edit expected it: $(grep -o '<EnableRateLimit>[^<]*</EnableRateLimit>' "$CONFIG" || echo 'element absent')"
grep -q "<RateLimitMaxAttempts>$MAX_ATTEMPTS</RateLimitMaxAttempts>" "$CONFIG" \
    || die "the attempt budget was not written into $CONFIG"
pass "the limiter is on with $MAX_ATTEMPTS attempts per ${WINDOW_SECONDS}s"

log "NOT naming the proxy in Jellyfin's known proxies (falsifier branch, never merged)"
# THIS BRANCH EXISTS TO BE RED. The known-proxies write is deleted, so Jellyfin has no reason to
# trust the forwarded header and both clients collapse to the proxy's own address. If the phase
# still passes without it, the phase is not measuring what it claims to measure.
pass "the known-proxies list is deliberately left empty"

log "Restarting Jellyfin against both edits, and bringing the proxy up"
# KEYCLOAK IS STARTED TOO, AND FORGETTING IT COST A RUN. The phase before this one ends with
# `docker compose up --abort-on-container-exit`, which stops every container when the harness exits,
# so this phase inherits a stopped stack rather than a running one. Starting only Jellyfin left the
# identity provider down, the challenge answered 400 with "the authorization server's discovery
# document could not be read", and the control refused to let the run mean anything - which is what
# the control is for. The phase beside this one starts both for the same reason.
docker compose -f "$COMPOSE" stop jellyfin >/dev/null
docker compose -f "$COMPOSE" start jellyfin keycloak >/dev/null
docker compose -f "$COMPOSE" --profile proxy up -d proxy >/dev/null
pass "the stack is running with a proxy in front of Jellyfin"

log "Driving the two clients"
PROBE_OUT="$(docker compose -f "$COMPOSE" run --rm --no-deps -T \
    -v "$PHASES_DIR:/probe:ro" --entrypoint sh harness /probe/probe-proxy-client-budget.sh)" \
    || die "the probe container could not be started"
printf '%s\n' "$PROBE_OUT" | sed 's/^/  probe| /'

field() { printf '%s\n' "$PROBE_OUT" | sed -n "s/^$1 //p" | tail -1; }
CONTROL="$(field PROBE-CONTROL)"
EXHAUST_STATUSES="$(field PROBE-EXHAUST-STATUSES)"
THROTTLED_AT="$(field PROBE-EXHAUST-THROTTLED-AT)"
OTHER="$(field PROBE-OTHER-CLIENT)"
[ -n "$CONTROL" ] && [ -n "$OTHER" ] \
    || die "the probe returned no statuses - its own output is above"

log "Asserting"
case "$CONTROL" in
    3??) pass "the control request through the proxy redirects to the identity provider ($CONTROL)" ;;
    429) die "the control request was already throttled ($CONTROL) - the budget was spent before this phase started, so nothing below would be attributable to it" ;;
    *) die "the control request through the proxy answered $CONTROL rather than a redirect - the stack is not healthy through the proxy, so a 429 afterwards would not be attributable to the limiter" ;;
esac

[ "$THROTTLED_AT" != "none" ] \
    || die "client A was never throttled after the exhaust loop (statuses:$EXHAUST_STATUSES). Either the limiter is not running, or the forwarded address is not being attributed at all - NormalizeClientKey returns null for a non-public source and exempts it from throttling, which looks exactly like a passing limiter from the outside"
pass "client A is throttled after $THROTTLED_AT request(s) past the control (statuses:$EXHAUST_STATUSES)"

[ "$OTHER" != "429" ] \
    || die "client B was throttled ($OTHER) on its FIRST request, having spent nothing. The limiter is keying on the proxy hop rather than on the forwarded client, so one noisy client behind a proxy throttles every other client at the same site"
case "$OTHER" in
    3??) pass "client B, through the SAME proxy, is not throttled and gets its own redirect ($OTHER) - the two clients are budgeted apart" ;;
    *) die "client B answered $OTHER: not a throttle, but not the redirect the control got either, so this run does not show two clients budgeted apart" ;;
esac

log "Putting the configuration back"
docker compose -f "$COMPOSE" --profile proxy stop proxy >/dev/null
in_jellyfin "set -eu; mv -f '$CONTAINER_CONFIG.kept' '$CONTAINER_CONFIG'; mv -f '$CONTAINER_NETWORK.kept' '$CONTAINER_NETWORK'" \
    || die "the two configuration files could not be put back"
[ ! -e "$CONFIG_KEPT" ] && [ ! -e "$NETWORK_KEPT" ] \
    || die "a copy is still sitting beside the configuration, so the restore did not complete"
[ "$(grep -o '<EnableRateLimit>[^<]*</EnableRateLimit>' "$CONFIG" | head -1)" = "$RATE_BEFORE" ] \
    || die "the limiter setting in $CONFIG is not what this phase found ($RATE_BEFORE), so the restore left the stack in a state the canonical pass did not create"
docker compose -f "$COMPOSE" stop >/dev/null
pass "the limiter settings and the known-proxies list are back as the canonical pass left them"

log "A login after the restore"
# STOPPED above and brought up by this `up`, rather than started separately first. `start` returns
# when the container is running, not when the server is listening, and the harness then raced it:
# its own readiness check passed against a server still coming up and the next request answered
# "Failed to connect to jellyfin port 8096 after 1 ms". Letting `up` bring the stack up cold is what
# the phase beside this one does, and the harness's wait is written for exactly that.
#
# RELOGIN_ONLY, so the seed, the wizard and the two provider Add calls are skipped and the
# persisted provider configuration this phase spent the run not touching is read back (#1123).
RELOGIN_ONLY=true docker compose -f "$COMPOSE" up \
    --abort-on-container-exit --exit-code-from harness \
    || die "the login after the restore failed - the phase left the stack broken rather than as it found it"
pass "the stack still logs in with the proxy gone and the limiter off"

printf '\nPROXY CLIENT ATTRIBUTION PHASE PASSED\n'
