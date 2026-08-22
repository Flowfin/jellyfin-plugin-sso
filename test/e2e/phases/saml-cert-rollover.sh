#!/usr/bin/env bash
# The identity provider's SAML signing key is rotated while the stack is up, the new certificate is
# imported into the plugin, and one run answers all three of #1128's clauses: an assertion signed by
# the rotated-in key mints a usable Jellyfin session, an assertion signed by the retired key is
# refused with a pinned status, and the plugin's stored SamlCertificate observably changes across the
# rotation. A live rotation was demonstrated by hand once in the #717 pass and nothing has re-checked
# it since, so a regression to accepting a retired certificate would ship silently.
#
# The work happens in probe-saml-rollover.sh, inside a container on the compose network, because
# neither Jellyfin nor Keycloak publishes a port to the host: the ACS, the plugin's admin API and the
# identity provider's admin API are all only reachable from `ssonet`. What this file adds is the one
# thing that container cannot do. It reads the persisted configuration off the bind mount, so the
# claim that the STORED certificate changed rests on the file on disk as well as on what the plugin
# says about itself, and a phase that changed only the plugin's opinion of its configuration could
# not pass.
#
# WHY THE PROBE IS NOT ALLOWED TO FAIL THE STEP. The probe never exits non-zero. It reports
# PROBE-PASS / PROBE-FAIL / PROBE-ERROR lines and this file decides what each one means, so a probe
# that broke on its way to the assertion cannot be read as a login that was refused. The absence of
# the final PROBE-DONE line is itself a failure here: a probe killed half way would otherwise leave a
# transcript with no FAIL lines in it, which reads exactly like a clean pass.
#
# It leaves the stack as it found it. The rotated-in key provider is deleted, the original
# certificate is imported back, and both are asserted rather than assumed: the certificate on disk
# after the run has to be the one that was there before it.
set -euo pipefail

COMPOSE="${COMPOSE:-test/e2e/docker-compose.yml}"
CONFIG="${CONFIG:-test/e2e/jellyfin/config/plugins/configurations/SSO-Auth.xml}"
# The realm administrator the rotation is performed as: a user of the e2e realm seeded in
# `test/e2e/keycloak/e2e-realm.json` with the realm-management `realm-admin` role, NOT the server's
# bootstrap administrator in the master realm. The master realm keeps Keycloak's default
# `sslRequired: external` and refuses a plaintext request from any address it does not consider
# private, which this compose network deliberately is not; the e2e realm sets `sslRequired: none`.
# Passed in rather than only defaulted inside the probe, so the credentials this phase uses are
# readable in the file that runs it.
KC_ADMIN_USER="${KC_ADMIN_USER:-realmadmin}"
KC_ADMIN_PASS="${KC_ADMIN_PASS:-realmadmin}"

log()  { printf '%s\n' "== $* =="; }
die()  { printf '::error::%s\n' "$*" >&2; exit 1; }
pass() { printf 'PASS: %s\n' "$*"; }

# The stored identity-provider signing certificate as the persisted configuration holds it, reduced
# to the SHA-256 over its DER bytes - the same number SAML/Test reports, so the file and the plugin's
# own account of itself are directly comparable.
stored_cert_b64() {
  grep -o '<SamlCertificate>[^<]*</SamlCertificate>' "$CONFIG" | head -1 \
    | sed -e 's#<SamlCertificate>##' -e 's#</SamlCertificate>##'
}
fingerprint_of() {
  printf '%s' "$1" | base64 -d 2>/dev/null | sha256sum | cut -d' ' -f1 | tr 'a-f' 'A-F'
}

log "Preconditions"
[ -s "$CONFIG" ] || die "the plugin persisted no configuration at $CONFIG - run the canonical pass first"
CERT_BEFORE="$(stored_cert_b64)"
[ -n "$CERT_BEFORE" ] || die "no SamlCertificate in $CONFIG - the canonical SAML pass has not configured a provider, so there is nothing to rotate"
FP_BEFORE="$(fingerprint_of "$CERT_BEFORE")"
[ -n "$FP_BEFORE" ] || die "the stored SamlCertificate is not decodable Base64, so no rotation could be observed against it"
pass "the persisted configuration holds a SAML certificate with thumbprint $FP_BEFORE"

log "Starting the stack"
# The canonical run ends with --abort-on-container-exit, which stops every container, so the servers
# have to be brought back up. `start`, never `up`: `up` would run the harness again, and `down` would
# take Keycloak's realm with it - the realm is re-imported into a fresh instance with a NEW signing
# certificate, which is the very thing this phase rotates on purpose and would then be unable to
# distinguish from its own work.
docker compose -f "$COMPOSE" start jellyfin keycloak >/dev/null

log "Rotating the identity provider's SAML signing key"
# One throwaway container on the compose network, built from the harness service so it inherits that
# service's environment and its network membership, with its command replaced by the probe. The probe
# is bind-mounted in as a FILE rather than handed over as a string: probe-oid-start.sh records what
# passing a script through two layers of `sh -c` cost the last time somebody tried it.
PHASES_DIR="${PHASES_DIR:-$(cd "$(dirname "$0")" && pwd)}"
OUT="$(docker compose -f "$COMPOSE" run --rm --no-deps -T \
  -e "KC_ADMIN_USER=$KC_ADMIN_USER" -e "KC_ADMIN_PASS=$KC_ADMIN_PASS" \
  -v "$PHASES_DIR:/probe:ro" --entrypoint sh harness /probe/probe-saml-rollover.sh)" \
  || die "the probe container could not be started"

# Everything the probe said, indented, so a run that ends here says why rather than only that it got
# no answer.
printf '%s\n' "$OUT" | sed 's/^/  probe| /'

log "Reading the probe's verdict"
if ! printf '%s\n' "$OUT" | grep -q '^PROBE-DONE$'; then
  die "the probe did not run to completion - its transcript is above, and a transcript without PROBE-DONE has assertions it never reached"
fi
if printf '%s\n' "$OUT" | grep -q '^PROBE-ERROR '; then
  die "the probe could not judge the rotation: $(printf '%s\n' "$OUT" | grep '^PROBE-ERROR ' | head -1)"
fi
if printf '%s\n' "$OUT" | grep -q '^PROBE-FAIL '; then
  printf '%s\n' "$OUT" | grep '^PROBE-FAIL ' | sed 's/^/::error::/'
  die "the rotation phase failed - every PROBE-FAIL line is above"
fi
pass "every assertion the probe made was met, and it ran to completion"

log "The stored certificate changed across the rotation"
# Read off the probe's own three readings of the plugin's stored certificate. The point of asserting
# these HERE, against the fingerprint taken from the file before anything ran, is that a phase which
# skipped the re-import would still have driven a login and could still have printed passes.
probe_fp() { printf '%s\n' "$OUT" | sed -n "s/^PROBE-CERT-$1 //p" | tail -1; }
FP_PROBE_BEFORE="$(probe_fp BEFORE)"
FP_PROBE_ROTATED="$(probe_fp ROTATED)"
FP_PROBE_RESTORED="$(probe_fp RESTORED)"
[ -n "$FP_PROBE_BEFORE" ] && [ -n "$FP_PROBE_ROTATED" ] && [ -n "$FP_PROBE_RESTORED" ] \
  || die "the probe did not report all three certificate readings (before='$FP_PROBE_BEFORE' rotated='$FP_PROBE_ROTATED' restored='$FP_PROBE_RESTORED')"

[ "$FP_PROBE_BEFORE" = "$FP_BEFORE" ] \
  || die "the plugin reported $FP_PROBE_BEFORE as its stored certificate while the file on disk holds $FP_BEFORE, so the two are not describing the same configuration"
pass "the plugin's view of its stored certificate matches the file on disk ($FP_BEFORE)"

[ "$FP_PROBE_ROTATED" != "$FP_BEFORE" ] \
  || die "the stored certificate did not change across the rotation, so the re-import was skipped and the phase proved nothing"
pass "the stored certificate became $FP_PROBE_ROTATED across the rotation"

[ "$FP_PROBE_RESTORED" = "$FP_BEFORE" ] \
  || die "the plugin was left holding $FP_PROBE_RESTORED rather than the original $FP_BEFORE"

log "The stack is as it was found"
CERT_AFTER="$(stored_cert_b64)"
[ -n "$CERT_AFTER" ] || die "the persisted configuration holds no SamlCertificate after the phase"
FP_AFTER="$(fingerprint_of "$CERT_AFTER")"
[ "$FP_AFTER" = "$FP_BEFORE" ] \
  || die "the certificate on disk after the phase is $FP_AFTER, not the $FP_BEFORE it started with"
pass "the persisted certificate is the one the phase found, and the rotated-in key provider was removed"

printf '\nSAML SIGNING-CERT ROLLOVER PHASE PASSED\n'
