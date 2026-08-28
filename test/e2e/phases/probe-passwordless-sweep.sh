#!/bin/sh
# The two readings the passwordless-sweep phase is made of, in one script run twice (#1440). Jellyfin
# publishes no port to the host, so both halves have to happen from inside a container on `ssonet`,
# and both are HTTP against the server rather than edits to a file - the account state this phase is
# about lives in Jellyfin's own database, which nothing outside the server may touch.
#
# STAGE is the argument. `seed` puts alice into the shape every account provisioned by a build up to
# v3.4.0.2 was stored in, and proves the door is open on it. `verify` reads her back after the
# restart the caller made in between, when the plugin's start-up pass has run.
#
# It never exits non-zero, like the probes beside it: a failure here prints PROBE-ERROR and the
# caller decides what a missing answer means, so a broken probe cannot be read as a sealed account.
set -u

STAGE="${1:-}"

say() { printf '%s\n' "$*"; }

if ! apk add --no-cache curl jq >/tmp/apk.out 2>&1; then
  say "PROBE-ERROR could not install curl and jq:"
  sed 's/^/  /' /tmp/apk.out
  exit 0
fi

EMBY_AUTH='MediaBrowser Client="e2e-sweep", Device="probe", DeviceId="e2e-sweep-probe", Version="1.0.0"'

# READINESS IS THE PLUGIN'S OWN ROUTE, for the reason probe-oid-start.sh states: /System/Info/Public
# answers while the server is still coming up, and on the verify stage that would read alice back
# BEFORE the hosted service that seals her has run - a false red that looks exactly like a sweep that
# does nothing. /sso/OID/GetNames only answers once the plugin is loaded.
i=0
until curl -fsS -o /dev/null "$JELLYFIN_URL/sso/OID/GetNames" 2>/tmp/ready.err; do
  i=$((i + 1))
  if [ "$i" -ge 150 ]; then
    say "PROBE-ERROR the plugin did not answer $JELLYFIN_URL/sso/OID/GetNames within 300s:"
    sed 's/^/  /' /tmp/ready.err
    exit 0
  fi
  sleep 2
done
say "PROBE-STAGE plugin ready after $i retries ($((i * 2))s)"

AUTH_JSON="$(curl -fsS -X POST "$JELLYFIN_URL/Users/AuthenticateByName" \
  -H "Content-Type: application/json" -H "Authorization: $EMBY_AUTH" \
  -d "{\"Username\":\"$JF_ADMIN_USER\",\"Pw\":\"$JF_ADMIN_PASS\"}" 2>/tmp/auth.err)" || {
  say "PROBE-ERROR admin authentication failed:"
  sed 's/^/  /' /tmp/auth.err
  exit 0
}
TOKEN="$(printf '%s' "$AUTH_JSON" | jq -r '.AccessToken // empty')"
[ -n "$TOKEN" ] || { say "PROBE-ERROR no admin access token minted"; exit 0; }
AUTHZ="Authorization: MediaBrowser Token=\"$TOKEN\""

ALICE_ID="$(curl -fsS "$JELLYFIN_URL/Users" -H "$AUTHZ" 2>/tmp/users.err \
  | jq -r '.[] | select(.Name == "alice") | .Id' | head -1)"
if [ -z "$ALICE_ID" ]; then
  say "PROBE-ERROR no account named alice on this server - the canonical login pass has to have run first:"
  sed 's/^/  /' /tmp/users.err
  exit 0
fi
say "PROBE-ALICE-ID $ALICE_ID"

# Both stages report the same three facts about the account, so the caller compares like with like and
# a reader of the log sees the state move rather than two differently-shaped readings. jq -r with no
# `// "?"` fallback, for the reason the harness states at the same reading: the fallback takes its
# alternative for FALSE as well as for absent, and "no password stored" and "field not there" are the
# two answers that must never print the same.
report_state() {
  rec="$(curl -fsS "$JELLYFIN_URL/Users/$ALICE_ID" -H "$AUTHZ" 2>/dev/null)" || rec=""
  say "PROBE-HASPASSWORD $(printf '%s' "$rec" | jq -r '.HasPassword')"
  say "PROBE-CONFIGURED $(printf '%s' "$rec" | jq -r '.HasConfiguredPassword')"
  say "PROBE-PROVIDER $(printf '%s' "$rec" | jq -r '.Policy.AuthenticationProviderId')"
  say "PROBE-ADMIN $(printf '%s' "$rec" | jq -r '.Policy.IsAdministrator')"
}

# The empty password against the ordinary login form. This is the whole subject: an account with no
# stored password accepts it, and that is how an SSO account becomes reachable without the identity
# provider. 200 means a session was minted.
empty_password_status() {
  curl -sS -o /dev/null -w '%{http_code}' -X POST "$JELLYFIN_URL/Users/AuthenticateByName" \
    -H "Content-Type: application/json" -H "Authorization: $EMBY_AUTH" \
    -d '{"Username":"alice","Pw":""}' 2>/dev/null
}

case "$STAGE" in
  seed)
    say "PROBE-BEFORE-SEED"
    report_state

    # ROUTING FIRST, PASSWORD SECOND, and the order is not cosmetic. The account is stored routed at
    # the plugin's own provider id, which resolves to no registered IAuthenticationProvider, so core
    # substitutes InvalidAuthenticationProvider - and a password reset against that provider has
    # nothing to reset. Repointing it at Jellyfin's built-in provider first is also exactly how the
    # historical population came about: a provider's DefaultProvider setting moved SSO accounts onto
    # a real password provider, and the account had no password to meet it with.
    #
    # THE ADMIN FLAG COMES OFF IN THE SAME WRITE, and it is not tidiness. Jellyfin refuses to empty an
    # administrator's password - UserManager.ChangePassword throws for an empty one on an account
    # holding IsAdministrator - and the reset answered 400 for exactly that reason on the first run of
    # this phase. alice carries the realm role this stack maps to Jellyfin admin, so she is one. It is
    # put back at the restore stage from the value read here, not from a constant.
    POLICY="$(curl -fsS "$JELLYFIN_URL/Users/$ALICE_ID" -H "$AUTHZ" 2>/dev/null | jq -c '.Policy')"
    [ -n "$POLICY" ] || { say "PROBE-ERROR could not read alice's policy"; exit 0; }
    NEW_POLICY="$(printf '%s' "$POLICY" | jq -c '.AuthenticationProviderId = "Jellyfin.Server.Implementations.Users.DefaultAuthenticationProvider" | .IsAdministrator = false')"
    POLICY_STATUS="$(curl -sS -o /tmp/policy.out -w '%{http_code}' -X POST "$JELLYFIN_URL/Users/$ALICE_ID/Policy" \
      -H "Content-Type: application/json" -H "$AUTHZ" -d "$NEW_POLICY" 2>/dev/null)"
    say "PROBE-POLICY-STATUS $POLICY_STATUS"

    RESET_STATUS="$(curl -sS -o /tmp/pw.out -w '%{http_code}' -X POST "$JELLYFIN_URL/Users/$ALICE_ID/Password" \
      -H "Content-Type: application/json" -H "$AUTHZ" \
      -d '{"CurrentPw":"","NewPw":"","ResetPassword":true}' 2>/dev/null)"
    say "PROBE-RESET-STATUS $RESET_STATUS"

    say "PROBE-AFTER-SEED"
    report_state
    say "PROBE-EMPTY-PASSWORD $(empty_password_status)"
    ;;
  verify)
    # BOUNDED WAIT, AND THE BOUND IS REPORTED. The pass runs in an IHostedService.StartAsync, and
    # whether that completes before the server answers a request depends on the order the host starts
    # its services in - which is not this phase's to assert. Reading once and finding no password
    # would be indistinguishable from a pass that does nothing, so the reading is repeated for a
    # stated interval and the log carries how long it took. A pass that never runs still fails: the
    # loop ends and the state below is the unsealed one.
    j=0
    while [ "$j" -lt 30 ]; do
      sealed="$(curl -fsS "$JELLYFIN_URL/Users/$ALICE_ID" -H "$AUTHZ" 2>/dev/null | jq -r '.HasPassword')"
      [ "$sealed" = "true" ] && break
      j=$((j + 1))
      sleep 2
    done
    say "PROBE-SEALED-AFTER $((j * 2))s of at most 60s"
    say "PROBE-AFTER-RESTART"
    report_state
    say "PROBE-EMPTY-PASSWORD $(empty_password_status)"
    ;;
  restore)
    # Put the routing and the admin flag back where the canonical pass left them, so the phase after
    # this one meets the stack it expects. The password cannot be put back and is not meant to be:
    # what is on the account now is the unguessable one the pass minted, which is the state every
    # sealed account is left in on a real server.
    POLICY="$(curl -fsS "$JELLYFIN_URL/Users/$ALICE_ID" -H "$AUTHZ" 2>/dev/null | jq -c '.Policy')"
    [ -n "$POLICY" ] || { say "PROBE-ERROR could not read alice's policy"; exit 0; }
    NEW_POLICY="$(printf '%s' "$POLICY" | jq -c --arg p "$RESTORE_PROVIDER" --argjson a "$RESTORE_ADMIN" '.AuthenticationProviderId = $p | .IsAdministrator = $a')"
    RESTORE_STATUS="$(curl -sS -o /dev/null -w '%{http_code}' -X POST "$JELLYFIN_URL/Users/$ALICE_ID/Policy" \
      -H "Content-Type: application/json" -H "$AUTHZ" -d "$NEW_POLICY" 2>/dev/null)"
    say "PROBE-RESTORE-STATUS $RESTORE_STATUS"
    say "PROBE-AFTER-RESTORE"
    report_state
    ;;
  *)
    say "PROBE-ERROR unknown stage '$STAGE' - expected seed, verify or restore"
    ;;
esac
