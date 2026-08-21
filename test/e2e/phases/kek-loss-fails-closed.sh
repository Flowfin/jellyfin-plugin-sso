#!/usr/bin/env bash
# Losing the key that wraps the at-rest provider secrets makes a login fail CLOSED (#1130). No
# plaintext fallback, no silently regenerated key, no blanked secret - and the stack recovers
# completely once the key is restored. Verified by hand once in the #717 live pass; this is the
# scripted version, so a regression to a fallback path cannot reach a release unnoticed.
#
# It runs on the HOST rather than inside the harness container, for the same reason
# legacy-secret-migration.sh does: the harness mounts only /harness, so it can neither read the
# persisted configuration nor delete a file out of the plugin's data folder. Both are what this
# phase is made of.
#
# THE ONE THING THAT DECIDES WHETHER A RED RUN MEANS ANYTHING. The harness exits non-zero on any
# failed login, so its exit code cannot separate "refused because the key is gone" from "the stack
# broke for an unrelated reason". This phase therefore drives the refusal itself, one request
# against the OpenID challenge endpoint, and it probes that SAME endpoint BEFORE the key is
# removed and requires a redirect. That control is what makes the 500 afterwards attributable: a
# stack that was already broken fails the control and the phase says so, instead of reporting a
# fail-closed refusal it did not cause.
#
# The shape, and why each step is where it is:
#
#   control    the stack is started WITHOUT the harness and the challenge is probed once. A
#              redirect here is the baseline the refusal below is measured against.
#   take away  the key is RENAMED aside with the stack STOPPED, never regenerated afterwards. A
#              fresh key is a DIFFERENT key: the stored envelope would not open under it and the
#              phase would end up proving that a restored backup fails, which is the opposite of
#              its claim. Stopped, because SecretStore caches the key in memory for the process
#              lifetime and taking it from a live server proves nothing until a restart.
#   refuse     the stack is started again and the same challenge is probed. It must answer 500
#              with the fail-closed message, and the persisted secret must still be the SAME
#              ssoenc:v1 envelope - not plaintext, not blank, and not re-wrapped under a fresh key.
#   restore    the key goes back and a RELOGIN_ONLY harness pass must go green, so the phase
#              proves fail-closed rather than a permanently broken stack.
#
# Never `docker compose down` anywhere in here: that removes Keycloak, the realm is re-imported
# into a fresh instance with a NEW SAML signing certificate, and the certificate the canonical
# pass wrote into the plugin's SAML configuration would no longer match the assertions the
# identity provider signs. `stop` and `start` keep the containers.
set -euo pipefail

COMPOSE="${COMPOSE:-test/e2e/docker-compose.yml}"
CONFIG="${CONFIG:-test/e2e/jellyfin/config/plugins/configurations/SSO-Auth.xml}"
# SSOPlugin puts the key in the plugin's own data folder (SSOPlugin.cs, "sso-secret.key"), which
# for this stack is inside the unpacked plugin drop rather than beside the configuration.
KEYFILE="${KEYFILE:-test/e2e/jellyfin/config/plugins/SSO-Auth/sso-secret.key}"
PLUGIN_DIR="${PLUGIN_DIR:-test/e2e/jellyfin/config/plugins}"

log()  { printf '%s\n' "== $* =="; }
die()  { printf '::error::%s\n' "$*" >&2; exit 1; }
pass() { printf 'PASS: %s\n' "$*"; }

secret_element() { grep -o '<OidSecret>[^<]*</OidSecret>' "$CONFIG" | head -1; }

# One throwaway container on the compose network, because Jellyfin publishes no port to the host:
# every service is reachable only by its service-DNS name from inside `ssonet`. --no-deps so this
# never starts or restarts anything else, and the harness service is reused only for its image and
# its network membership - its own command is replaced by the probe script, which is bind-mounted
# in rather than handed over as a string. The first version passed the probe to `sh -c` and came
# back with a status nothing in it can produce and a missing body file, and a script that arrives
# as one argument through two layers cannot be read in the log it failed in.
PHASES_DIR="${PHASES_DIR:-$(cd "$(dirname "$0")" && pwd)}"
probe_container() {
  docker compose -f "$COMPOSE" run --rm --no-deps -T \
    -v "$PHASES_DIR:/probe:ro" --entrypoint sh harness /probe/probe-oid-start.sh
}

PROBE_STATUS=""
PROBE_BODY=""
probe_challenge() { # $1 label; sets PROBE_STATUS and PROBE_BODY
  local out
  out="$(probe_container)" || die "$1: the probe container could not be started"
  # Everything the probe said, indented, so a run that ends here says why rather than only that it
  # got no answer.
  printf '%s\n' "$out" | sed 's/^/  probe| /'
  PROBE_STATUS="$(printf '%s\n' "$out" | sed -n 's/^PROBE-STATUS //p' | tail -1)"
  PROBE_BODY="$(printf '%s\n' "$out" | sed -n 's/^PROBE-BODY //p' | tail -1)"
  [ -n "$PROBE_STATUS" ] || die "$1: the probe returned no status - its own output is above"
  printf '  %s: status=%s body=%s\n' "$1" "$PROBE_STATUS" "$PROBE_BODY"
}

log "Preconditions"
[ -s "$CONFIG" ] || die "the plugin persisted no configuration at $CONFIG - run the canonical pass first"
case "$(secret_element)" in
  *"<OidSecret>ssoenc:v1:"*) pass "the starting state is an ssoenc:v1 envelope" ;;
  *) die "the starting state is not an ssoenc:v1 envelope, so destroying the key would prove nothing: $(secret_element)" ;;
esac
if [ ! -s "$KEYFILE" ]; then
  printf 'key files found under %s:\n' "$PLUGIN_DIR" >&2
  find "$PLUGIN_DIR" -name '*.key' -print >&2 || true
  die "no key file at $KEYFILE - the phase would delete nothing and the login below would prove nothing"
fi
SECRET_BEFORE="$(secret_element)"
pass "the at-rest key file is present at $KEYFILE"

# The key is moved aside FIRST, and put back on any exit path that left it aside. A phase that
# died between the two would otherwise leave a stack whose secrets are permanently unrecoverable,
# and locally that is a real directory rather than a runner about to be discarded.
#
# A RENAME rather than a copy, into the same directory, and that is a constraint rather than a
# preference. SecretStore creates the key with owner-only permissions and the server writes it as
# root inside the container, so on the bind mount the file is mode 600 owned by root and nothing
# running as the ordinary user can READ it. A rename needs write and execute on the DIRECTORY and
# no permission at all on the file, and the plugin drop is created by the workflow and made
# world-writable before the stack comes up. It is also the stronger statement: the file that comes
# back is the same inode, so "byte for byte" is a property of the operation instead of a checksum
# somebody has to trust. The inode is pinned below to say so out loud.
KEPT="$KEYFILE.kept"
[ ! -e "$KEPT" ] || die "$KEPT already exists - a previous run left a key aside and this one would overwrite it"
KEY_INODE="$(stat -c %i "$KEYFILE")"
KEY_SIZE="$(stat -c %s "$KEYFILE")"
restore_key() {
  if [ ! -e "$KEYFILE" ] && [ -e "$KEPT" ]; then
    mv "$KEPT" "$KEYFILE"
    printf 'restored %s on exit\n' "$KEYFILE" >&2
  fi
}
trap restore_key EXIT
pass "the key to move aside is inode $KEY_INODE, $KEY_SIZE bytes"

log "Control: the challenge answers normally while the key is present"
docker compose -f "$COMPOSE" start jellyfin keycloak >/dev/null
probe_challenge "control"
case "$PROBE_STATUS" in
  3??) pass "the OpenID challenge redirects to the identity provider ($PROBE_STATUS)" ;;
  *) die "the control probe did not redirect ($PROBE_STATUS) - the stack is not healthy, so a refusal after the key is destroyed would not be attributable to the key" ;;
esac

log "Taking the at-rest key away"
# Stopped first: SecretStore caches the key for the process lifetime, so taking the file away from
# a running server changes nothing until it restarts, and the phase would then be reading a cached
# key as if the server had a fallback.
docker compose -f "$COMPOSE" stop >/dev/null
mv "$KEYFILE" "$KEPT"
[ ! -e "$KEYFILE" ] || die "the key file is still at $KEYFILE"
pass "the key is gone from $KEYFILE while the configuration still holds the envelope"

log "The login is refused, fail-closed"
docker compose -f "$COMPOSE" start jellyfin keycloak >/dev/null
probe_challenge "key-destroyed"
[ "$PROBE_STATUS" = "500" ] || die "the OpenID challenge answered $PROBE_STATUS with the key destroyed; a fail-closed refusal is 500, and a 3xx means the login proceeded without the secret"
case "$PROBE_BODY" in
  *"could not be decrypted"*) pass "the refusal names the undecryptable client secret rather than failing for some other reason" ;;
  *) die "the challenge answered 500 but not with the fail-closed secret message, so this may be an unrelated server error: $PROBE_BODY" ;;
esac

log "Asserting the stored secret survived the refusal"
case "$(secret_element)" in
  "") die "the persisted secret element is gone from $CONFIG" ;;
  *"<OidSecret>ssoenc:v1:"*) pass "the stored secret is still an ssoenc:v1 envelope" ;;
  *) die "the stored secret is no longer an envelope - it was rewritten as plaintext or blanked: $(secret_element)" ;;
esac
# Byte-identity is the stronger half and it is the one that catches a silent recovery: a server
# that minted a replacement key and re-wrapped the value would still leave an ssoenc:v1 envelope
# here, while every secret written under the lost key had become unrecoverable.
[ "$(secret_element)" = "$SECRET_BEFORE" ] \
  || die "the stored envelope changed while the key was missing, so something re-wrapped it under a new key: $(secret_element)"
pass "the stored envelope is byte-identical to the one written before the key was destroyed"

log "Putting the key back"
docker compose -f "$COMPOSE" stop >/dev/null
mv "$KEPT" "$KEYFILE"
[ "$(stat -c %i "$KEYFILE")" = "$KEY_INODE" ] && [ "$(stat -c %s "$KEYFILE")" = "$KEY_SIZE" ] \
  || die "the key back at $KEYFILE is not the file that was taken away (inode $(stat -c %i "$KEYFILE"), $(stat -c %s "$KEYFILE") bytes)"
pass "the original key is back: same inode, same size, and never copied"

log "A login after the restore"
# RELOGIN_ONLY, so the seed, the wizard and the two provider Add calls are skipped: a re-seed
# would rewrite the very secret this phase spent the run not touching (#1123).
RELOGIN_ONLY=true docker compose -f "$COMPOSE" up \
  --abort-on-container-exit --exit-code-from harness \
  || die "the login after the key was restored failed - the phase proved a broken stack rather than a fail-closed one"
pass "the stack recovered completely once the key was back"

printf '\nKEK LOSS FAILS CLOSED PHASE PASSED\n'
