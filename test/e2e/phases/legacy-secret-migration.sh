#!/usr/bin/env bash
# A pre-#158 PLAINTEXT provider secret is migrated to an ssoenc:v1 envelope, and logins keep working
# across the migration (#1140). Verified by hand once in the #717 live pass; this is the scripted
# version, so a migration regression cannot reach a release unnoticed.
#
# It runs on the HOST rather than inside the harness container, for the same reason the workflow's
# secrets-at-rest assertion does: the harness mounts only /harness, so it can neither read the
# persisted config nor restart Jellyfin. Both are what this phase is made of.
#
# The shape, and why each step is where it is:
#
#   pass 1     the ordinary canonical run, which the caller has already made green. It leaves a
#              configured Jellyfin whose secret is an ssoenc:v1 envelope, and it leaves the
#              containers STOPPED rather than removed, which is what makes the rest possible.
#   plant      the envelope is replaced on disk with the plaintext a pre-#158 config carried. Done
#              with the stack down, so nothing is racing the write.
#   pass 2     RELOGIN_ONLY, which restarts Jellyfin against the planted config and skips the seed,
#              the wizard and the provider Add - without that the re-seed would rewrite the very
#              secret the phase just planted and the run would assert nothing (#1123).
#   pass 3     a second RELOGIN_ONLY pass, so the login that proves the migrated secret still
#              decrypts is one driven AFTER the envelope exists. Pass 2's login happens while the
#              plaintext is still on disk and is what triggers the rewrite, so it cannot be that
#              login.
#
# Never `docker compose down` between the passes: that removes Keycloak, the realm is re-imported
# into a fresh instance with a NEW SAML signing certificate, and the certificate pass 1 wrote into
# the plugin's SAML configuration would no longer match the assertions the IdP signs.
set -euo pipefail

COMPOSE="${COMPOSE:-test/e2e/docker-compose.yml}"
CONFIG="${CONFIG:-test/e2e/jellyfin/config/plugins/configurations/SSO-Auth.xml}"

log()  { printf '%s\n' "== $* =="; }
die()  { printf '::error::%s\n' "$*" >&2; exit 1; }
pass() { printf 'PASS: %s\n' "$*"; }

# The plaintext to plant is read out of the resolved compose configuration rather than written here.
# It has to be the secret the identity provider actually expects: a wrong value would make pass 2's
# login fail, and the phase would go red while the product behaved correctly, which is the worst
# shape a regression gate can take.
PLAINTEXT="$(docker compose -f "$COMPOSE" config 2>/dev/null \
  | sed -n 's/^[[:space:]]*OIDC_CLIENT_SECRET:[[:space:]]*//p' | head -1 | tr -d '"')"
[ -n "$PLAINTEXT" ] || die "could not read OIDC_CLIENT_SECRET out of $COMPOSE - nothing to plant"

secret_element() { grep -o '<OidSecret>[^<]*</OidSecret>' "$CONFIG" | head -1; }

log "Preconditions"
[ -s "$CONFIG" ] || die "the plugin persisted no configuration at $CONFIG - run the canonical pass first"
case "$(secret_element)" in
  *'<OidSecret>ssoenc:v1:'*) pass "the starting state is an ssoenc:v1 envelope" ;;
  *) die "the starting state is not an ssoenc:v1 envelope, so this phase would prove nothing: $(secret_element)" ;;
esac

log "Planting a pre-#158 plaintext secret"
# THE EDIT HAPPENS INSIDE A CONTAINER, and that is a constraint rather than a preference (#1391).
# `plugins/configurations/` is created by the SERVER at runtime, not by the workflow, so the
# `chmod -R 0777 test/e2e/jellyfin` in the install step never reaches it: that step runs before the
# stack comes up and the directory does not exist yet. An in-place edit writes a new file beside the
# target and renames it over, which needs write permission on that DIRECTORY, and the ordinary
# workflow user has none - `perl -i` answered "Cannot make temp name: Permission denied" and the
# step died before it asserted anything. The file itself is written by the server as root, so a
# plain redirect over it is refused for the same reason.
#
# The jellyfin service already bind-mounts ./jellyfin/config at /config and runs as root, so its own
# definition is the shortest route to a writable handle: no second mount to keep in step with the
# compose file, and no elevation on the host. `--no-deps` starts nothing else, `--rm` leaves nothing
# behind, and the entrypoint is replaced so no server starts in it.
#
# The rewrite is a SPLIT rather than a pattern substitution, because the value being planted is a
# secret read out of the compose configuration and every substitution syntax reserves characters a
# secret may legitimately contain - sed and awk both re-read `&` in the replacement as the match.
# Splitting on the tags and reassembling puts the value in verbatim, whatever is in it.
#
# One element, the FIRST, matched on its own tags, so a value containing markup could not widen the
# edit: `%%` cuts at the first opening tag and `#` at the first closing one.
docker compose -f "$COMPOSE" run --rm --no-deps -T \
  -e "PLANT=$PLAINTEXT" --entrypoint sh jellyfin -c '
    set -eu
    f=/config/plugins/configurations/SSO-Auth.xml
    c=$(cat "$f")
    case "$c" in
      *"<OidSecret>"*"</OidSecret>"*) ;;
      *) echo "no OidSecret element to replace in $f" >&2; exit 1 ;;
    esac
    printf "%s<OidSecret>%s</OidSecret>%s" "${c%%<OidSecret>*}" "$PLANT" "${c#*</OidSecret>}" > "$f"
  ' || die "the plant could not be written - the container edit of $CONFIG failed"
grep -qF ">${PLAINTEXT}<" "$CONFIG" || die "the plant did not take - $CONFIG still holds no plaintext secret"
grep -q 'ssoenc:v1:' "$CONFIG" && die "an ssoenc:v1 envelope survived the plant, so the config is not in the legacy shape"
pass "the persisted secret is now plaintext, exactly as a pre-#158 config carried it"

log "Pass 2: restart against the planted config and drive a login"
RELOGIN_ONLY=true docker compose -f "$COMPOSE" up \
  --abort-on-container-exit --exit-code-from harness \
  || die "the login against the planted plaintext secret failed - a legacy config is no longer readable"
pass "the login succeeded with a plaintext secret on disk"

log "Asserting the migration"
case "$(secret_element)" in
  *'<OidSecret>ssoenc:v1:'*) pass "the persisted secret is an ssoenc:v1 envelope again" ;;
  *) die "the secret was not migrated: $(secret_element)" ;;
esac
# Over the whole file rather than the one element: a migration that re-wrapped the provider secret
# while leaving a copy of the plaintext anywhere else in the document has not removed the secret.
if grep -qF "$PLAINTEXT" "$CONFIG"; then
  die "the plaintext secret still appears in $CONFIG after the migration"
fi
pass "the plaintext value appears nowhere in the persisted configuration"

log "Pass 3: a login driven after the migration"
RELOGIN_ONLY=true docker compose -f "$COMPOSE" up \
  --abort-on-container-exit --exit-code-from harness \
  || die "the login after the migration failed - the migrated envelope does not decrypt to the right value"
pass "the migrated secret still decrypts to the value the provider accepts"

printf '\nLEGACY SECRET MIGRATION PHASE PASSED\n'
