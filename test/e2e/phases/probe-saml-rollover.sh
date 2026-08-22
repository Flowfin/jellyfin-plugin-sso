#!/bin/sh
# The identity provider's SAML signing key is rotated mid-run, the new certificate is imported into
# the plugin, and three questions are answered in one pass (#1128): does an assertion signed by the
# rotated-in key still log a user in, is an assertion signed by the retired key refused, and did the
# plugin's stored certificate actually change.
#
# It runs INSIDE a container on the compose network, because everything it touches is only reachable
# from there. Jellyfin publishes no port to the host and neither does Keycloak, so a host-side curl
# reaches neither the plugin's ACS nor the identity provider's admin API. The host half of this phase
# (saml-cert-rollover.sh) starts the stack, runs this file, and reads the persisted configuration off
# the bind mount, which is the one thing a container on the network cannot see.
#
# WHY THE OLD-CERTIFICATE ASSERTION IS A FRESH ONE RATHER THAN A REPLAY. The issue asks for a replay
# of the pre-rotation assertion. A replay is refused by the one-time cache whatever certificate the
# plugin holds, so a 400 would have proved the replay guard and said nothing about the rotation. Each
# assertion here comes from its own /start, so it is unused, and its ONLY defect is the key that
# signed it. The plugin answers both cases with one body ("SAML response validation failed", the
# uniform SAML rejection), which is exactly why the two must not be confused at the door.
#
# THE FALSIFIER IS THE PART TO READ. A refusal between two successes could be the clock rather than
# the certificate: every assertion carries a NotOnOrAfter, Keycloak's default window is short, and
# the rotation takes time. So a SECOND pre-rotation assertion is captured in the same breath as the
# first, held through the whole rotation, and posted AFTER the original certificate has been put
# back. It is strictly OLDER at that moment than the refused one was at its refusal, so if age
# explained the refusal, this one would be refused too. It is accepted. That is what makes the
# refusal attributable to the certificate rather than to the time it took to rotate.
#
# It never exits non-zero. Every finding is a PROBE-PASS / PROBE-FAIL / PROBE-ERROR line and the host
# decides what a missing answer means, so a broken probe cannot be read as a refused login. The last
# line of a complete run is PROBE-DONE; a run that dies half way prints no such line and the host
# reds on its absence rather than on the assertions it never reached.
set -u

JELLYFIN="${JELLYFIN_URL:-http://jellyfin:8096}"
KEYCLOAK="${KEYCLOAK_URL:-http://keycloak:8080}"
REALM="${REALM:-e2e}"
PROVIDER="${PROVIDER:-keycloak}"
ADMIN_USER="${JF_ADMIN_USER:-e2eadmin}"
ADMIN_PASS="${JF_ADMIN_PASS:-e2e-admin-pw}"
# The identity provider's bootstrap administrator. These are the credentials the canonical compose
# file states for its own test Keycloak (KC_BOOTSTRAP_ADMIN_USERNAME / _PASSWORD); nothing secret is
# introduced by naming them, and the host passes them in so this file carries no default the host
# cannot see.
KC_ADMIN_USER="${KC_ADMIN_USER:-admin}"
KC_ADMIN_PASS="${KC_ADMIN_PASS:-admin}"
# carol is the SAML user the canonical round-trip drives, and she carries the jellyfin-access role
# the stored provider configuration gates on.
SAML_USER="${SAML_USER:-carol}"
SAML_PASS="${SAML_PASS:-carol}"
SAML_ENDPOINT="${SAML_ENDPOINT:-$KEYCLOAK/realms/$REALM/protocol/saml}"
SAML_CLIENT_ID="${SAML_CLIENT_ID:-jellyfin-saml}"
SAML_BASE_URL_OVERRIDE="${SAML_BASE_URL_OVERRIDE:-}"
# Always Secure, so curl stores it but will not send it back over this stack's plaintext http; the
# same explicit replay the harness performs (#415).
SAML_BINDING_COOKIE_NAME="__Host-sso_saml_state_binding"
EMBY_AUTH='MediaBrowser Client="e2e-rollover", Device="rollover", DeviceId="e2e-rollover-device", Version="1.0.0"'
# The component this phase creates, named so a leftover is recognisable rather than mysterious.
ROLLOVER_COMPONENT_NAME="e2e-rollover-rsa"

stage() { printf 'PROBE-STAGE %s\n' "$*"; }
ok()    { printf 'PROBE-PASS %s\n' "$*"; }
bad()   { printf 'PROBE-FAIL %s\n' "$*"; }
oops()  { printf 'PROBE-ERROR %s\n' "$*"; }

# --------------------------------------------------------------------------------------------------
# Tools and readiness
# --------------------------------------------------------------------------------------------------
if ! apk add --no-cache curl jq >/tmp/apk.out 2>&1; then
  oops "could not install curl/jq:"
  sed 's/^/  /' /tmp/apk.out
  exit 0
fi

# READINESS IS THE PLUGIN'S OWN ROUTE, NOT THE SERVER'S, for the reason probe-oid-start.sh measured:
# /System/Info/Public answers while Jellyfin is still coming up and the route under test then returns
# a startup page. SAML/GetNames answers only once the plugin is loaded, and it is the SAML twin of
# the gate that phase settled on.
i=0
until curl -fsS -o /dev/null "$JELLYFIN/sso/SAML/GetNames" 2>/tmp/ready.err; do
  i=$((i + 1))
  if [ "$i" -ge 150 ]; then
    oops "the plugin did not answer $JELLYFIN/sso/SAML/GetNames within 300s:"
    sed 's/^/  /' /tmp/ready.err
    exit 0
  fi
  sleep 2
done
stage "the plugin answers SAML/GetNames after $i retries ($((i * 2))s)"

i=0
until curl -fsS -o /dev/null "$KEYCLOAK/realms/$REALM/protocol/saml/descriptor" 2>/tmp/kcready.err; do
  i=$((i + 1))
  if [ "$i" -ge 90 ]; then
    oops "the identity provider did not serve its SAML descriptor within 180s:"
    sed 's/^/  /' /tmp/kcready.err
    exit 0
  fi
  sleep 2
done
stage "the identity provider serves its SAML descriptor after $i retries ($((i * 2))s)"

# --------------------------------------------------------------------------------------------------
# Credentials
# --------------------------------------------------------------------------------------------------
JF_TOKEN="$(curl -sS -X POST "$JELLYFIN/Users/AuthenticateByName" \
  -H 'Content-Type: application/json' -H "Authorization: $EMBY_AUTH" \
  -d "{\"Username\":\"$ADMIN_USER\",\"Pw\":\"$ADMIN_PASS\"}" 2>/dev/null | jq -r '.AccessToken // empty')"
if [ -z "$JF_TOKEN" ]; then
  oops "could not authenticate as the Jellyfin administrator, so the re-import could not be performed"
  exit 0
fi
stage "Jellyfin administrator token acquired"

KC_TOKEN="$(curl -sS -X POST "$KEYCLOAK/realms/master/protocol/openid-connect/token" \
  -d 'client_id=admin-cli' -d 'grant_type=password' \
  --data-urlencode "username=$KC_ADMIN_USER" --data-urlencode "password=$KC_ADMIN_PASS" 2>/dev/null \
  | jq -r '.access_token // empty')"
if [ -z "$KC_TOKEN" ]; then
  oops "could not authenticate against the identity provider's admin API, so no key could be rotated"
  exit 0
fi
stage "identity-provider admin token acquired"

kc() { curl -sS -H "Authorization: Bearer $KC_TOKEN" "$@"; }

REALM_ID="$(kc "$KEYCLOAK/admin/realms/$REALM" 2>/dev/null | jq -r '.id // empty')"
if [ -z "$REALM_ID" ]; then
  oops "could not read the realm id, which the new key provider has to be parented to"
  exit 0
fi

# --------------------------------------------------------------------------------------------------
# Helpers: the plugin's stored certificate, and the identity provider's signing keys
# --------------------------------------------------------------------------------------------------
# The plugin's OWN view of what it stores. SAML/Test parses the configured certificate and reports
# its SHA-256 thumbprint, so this reads the value in use rather than a file somebody hopes it read.
stored_thumbprint() {
  curl -sS -H "Authorization: MediaBrowser Token=\"$JF_TOKEN\"" "$JELLYFIN/sso/SAML/Test/$PROVIDER" 2>/dev/null \
    | jq -r '.Details[]? | select(startswith("SHA-256 thumbprint: "))' \
    | sed 's/^SHA-256 thumbprint: //' | tr -d ' \r'
}

# The SHA-256 over the DER bytes, which is what a certificate thumbprint is, so the plugin's report
# and the identity provider's key listing can be compared without either having to trust the other's
# spelling of the same certificate.
thumb_of() { printf '%s' "$1" | base64 -d 2>/dev/null | sha256sum | cut -d' ' -f1 | tr 'a-f' 'A-F'; }

# The realm's active RS256 signing key, and the one belonging to a named provider component. The
# certificate is read from the admin key listing rather than from the SAML descriptor: while two
# signing keys are active the descriptor carries both, and "the first X509Certificate element" is
# then whichever one the serialiser happened to put first.
active_sig_cert() {
  kc "$KEYCLOAK/admin/realms/$REALM/keys" 2>/dev/null \
    | jq -r '[.keys[] | select(.use=="SIG" and .algorithm=="RS256" and .status=="ACTIVE")]
             | sort_by(.providerPriority // 0) | reverse | .[0].certificate // empty'
}
cert_of_component() {
  kc "$KEYCLOAK/admin/realms/$REALM/keys" 2>/dev/null \
    | jq -r --arg id "$1" '.keys[] | select(.providerId==$id and .use=="SIG" and .algorithm=="RS256") | .certificate' \
    | head -1
}

# SAML/Add replaces the stored provider wholesale, so changing one field means re-stating the rest.
# The body below is the canonical harness's SAML configuration with the certificate swapped; a field
# this phase got wrong would fail the login it drives rather than persist unnoticed.
import_certificate() { # $1 certificate
  curl -sS -o /tmp/samladd.out -w '%{http_code}' -X POST "$JELLYFIN/sso/SAML/Add/$PROVIDER" \
    -H 'Content-Type: application/json' \
    -H "Authorization: MediaBrowser Token=\"$JF_TOKEN\"" \
    -d "{\"SamlEndpoint\":\"$SAML_ENDPOINT\",\"SamlClientId\":\"$SAML_CLIENT_ID\",\"BaseUrlOverride\":\"$SAML_BASE_URL_OVERRIDE\",\"SamlCertificate\":\"$1\",\"Enabled\":true,\"EnableAuthorization\":true,\"Roles\":[\"jellyfin-access\"]}" \
    2>/dev/null
}

# --------------------------------------------------------------------------------------------------
# Helpers: one SAML browser leg, captured rather than posted
# --------------------------------------------------------------------------------------------------
# capture <label> : drives /start and the identity provider's credential form, and files away the
# assertion, the ACS URL, the RelayState and the browser-binding cookie WITHOUT posting anything.
# Holding an assertion instead of posting it is the whole mechanism of this phase: it is what lets an
# assertion signed before the rotation be presented after it.
capture() {
  label="$1"
  jar="/tmp/$label.jar"; hdr="/tmp/$label.hdr"
  : > "$jar"
  start_out="$(curl -sS -D "$hdr" -o /dev/null -c "$jar" -b "$jar" -w '%{http_code} %{redirect_url}' \
    "$JELLYFIN/sso/SAML/start/$PROVIDER" 2>/dev/null)" || { oops "$label: SAML/start could not be reached"; return 1; }
  auth_url="${start_out#* }"
  if [ -z "$auth_url" ]; then
    oops "$label: SAML/start returned no redirect (HTTP ${start_out%% *})"
    return 1
  fi
  grep -i '^set-cookie:' "$hdr" 2>/dev/null | grep -o "$SAML_BINDING_COOKIE_NAME=[^;]*" \
    | head -1 | cut -d= -f2- > "/tmp/$label.bind"

  login_page="$(curl -sSL -c "$jar" -b "$jar" "$auth_url" 2>/dev/null)" \
    || { oops "$label: the identity provider's login page could not be fetched"; return 1; }
  form_action="$(printf '%s' "$login_page" | grep -oE 'action="[^"]*"' | head -1 \
    | sed -e 's/^action="//' -e 's/"$//' -e 's/&amp;/\&/g')"
  if [ -z "$form_action" ]; then
    oops "$label: no credential form on the identity provider's page"
    return 1
  fi
  post_page="$(curl -sSL -c "$jar" -b "$jar" \
    --data-urlencode "username=$SAML_USER" --data-urlencode "password=$SAML_PASS" \
    --data-urlencode 'credentialId=' "$form_action" 2>/dev/null)" \
    || { oops "$label: the credential POST failed"; return 1; }

  printf '%s' "$post_page" | grep -oE 'form[^>]*action="[^"]*"' | head -1 \
    | sed -E 's/.*action="//; s/".*//; s/&amp;/\&/g' > "/tmp/$label.acs"
  printf '%s' "$post_page" | grep -oE 'name="SAMLResponse"[^>]*value="[^"]*"' | head -1 \
    | sed -E 's/.*value="//; s/".*//' > "/tmp/$label.resp"
  printf '%s' "$post_page" | grep -oE 'name="RelayState"[^>]*value="[^"]*"' | head -1 \
    | sed -E 's/.*value="//; s/".*//' > "/tmp/$label.relay"
  if [ ! -s "/tmp/$label.resp" ] || [ ! -s "/tmp/$label.acs" ]; then
    oops "$label: the identity provider returned no SAML POST-binding form; first 400 chars: $(printf '%s' "$post_page" | head -c 400)"
    return 1
  fi
  # An epoch stamp per assertion, so the transcript can say how old each one was when it was posted
  # and the falsifier's claim to be the older of the two is readable rather than asserted.
  date +%s > "/tmp/$label.at"
  stage "$label: assertion captured ($(wc -c < "/tmp/$label.resp") base64 chars), held unposted"
  return 0
}

# present <label> : posts a captured assertion to the plugin's ACS. Sets ACS_STATUS, ACS_BODY,
# ACS_TOKEN (the login-outcome token a successful callback hands the browser) and ACS_AGE. No -f: a
# refusal is an expected outcome here and has to come back with its status rather than as an error.
ACS_STATUS=""; ACS_BODY=""; ACS_TOKEN=""; ACS_AGE=""
present() {
  label="$1"
  acs="$(cat "/tmp/$label.acs")"; resp="$(cat "/tmp/$label.resp")"
  relay="$(cat "/tmp/$label.relay" 2>/dev/null || true)"
  ACS_AGE="$(( $(date +%s) - $(cat "/tmp/$label.at") ))"
  if [ -n "$relay" ]; then
    ACS_STATUS="$(curl -sS -o /tmp/acs.out -w '%{http_code}' -X POST "$acs" \
      --data-urlencode "SAMLResponse=$resp" --data-urlencode "RelayState=$relay" 2>/dev/null)" || ACS_STATUS=""
  else
    ACS_STATUS="$(curl -sS -o /tmp/acs.out -w '%{http_code}' -X POST "$acs" \
      --data-urlencode "SAMLResponse=$resp" 2>/dev/null)" || ACS_STATUS=""
  fi
  if [ -z "$ACS_STATUS" ]; then
    oops "$label: the ACS could not be reached at all"
    return 1
  fi
  ACS_BODY="$(tr -d '\r\n' < /tmp/acs.out | cut -c1-200)"
  ACS_TOKEN="$(grep -oE 'var data = "[^"]*"' /tmp/acs.out 2>/dev/null | head -1 \
    | sed -e 's/^var data = "//' -e 's/"$//')"
  if [ -n "$ACS_TOKEN" ]; then tokseen=yes; else tokseen=no; fi
  stage "$label: ACS answered $ACS_STATUS after ${ACS_AGE}s, login-outcome token: $tokseen"
  return 0
}

# redeem <label> : exchanges a login-outcome token for a Jellyfin session at the same-origin mint leg
# and uses that session against /Users/Me. Minting is what "a usable session token" means; a callback
# that returned a token minting nothing would otherwise read as a successful login.
redeem() {
  label="$1"
  bind="$(cat "/tmp/$label.bind" 2>/dev/null || true)"
  if [ -z "$bind" ]; then
    bad "$label: /start set no SAML browser-binding cookie, so the mint leg cannot be exercised"
    return 1
  fi
  auth="$(curl -sS -H "Cookie: $SAML_BINDING_COOKIE_NAME=$bind" \
    -X POST "$JELLYFIN/sso/SAML/Auth/$PROVIDER" -H 'Content-Type: application/json' \
    -d "{\"deviceId\":\"e2e-rollover-device\",\"appName\":\"Jellyfin Web\",\"appVersion\":\"10.8.0\",\"deviceName\":\"rollover\",\"data\":\"$ACS_TOKEN\"}" 2>/dev/null)"
  tok="$(printf '%s' "$auth" | jq -r '.AccessToken // empty' 2>/dev/null)"
  if [ -z "$tok" ]; then
    bad "$label: the login-outcome token minted no Jellyfin session: $(printf '%s' "$auth" | head -c 200)"
    return 1
  fi
  me="$(curl -sS -H "Authorization: MediaBrowser Token=\"$tok\"" "$JELLYFIN/Users/Me" 2>/dev/null | jq -r '.Name // empty')"
  if [ -z "$me" ]; then
    bad "$label: the minted session token is not usable against /Users/Me"
    return 1
  fi
  stage "$label: minted a session usable as '$me'"
  return 0
}

# --------------------------------------------------------------------------------------------------
# Cleanup: the realm and the plugin go back to what they were, on every exit path
# --------------------------------------------------------------------------------------------------
NEW_COMPONENT_ID=""
ORIGINAL_CERT=""
cleanup() {
  if [ -n "$NEW_COMPONENT_ID" ]; then
    st="$(kc -o /dev/null -w '%{http_code}' -X DELETE \
      "$KEYCLOAK/admin/realms/$REALM/components/$NEW_COMPONENT_ID" 2>/dev/null || true)"
    stage "cleanup: removed the rotated-in key provider (HTTP $st)"
  fi
  if [ -n "$ORIGINAL_CERT" ]; then
    st="$(import_certificate "$ORIGINAL_CERT")"
    stage "cleanup: put the original certificate back into the plugin (HTTP $st)"
  fi
}
trap cleanup EXIT

# --------------------------------------------------------------------------------------------------
# The starting state
# --------------------------------------------------------------------------------------------------
ORIGINAL_CERT="$(active_sig_cert)"
if [ -z "$ORIGINAL_CERT" ]; then
  oops "the identity provider reports no active RS256 signing key, so there is nothing to rotate away from"
  exit 0
fi
IDP_FP_BEFORE="$(thumb_of "$ORIGINAL_CERT")"
STORED_FP_BEFORE="$(stored_thumbprint)"
printf 'PROBE-CERT-BEFORE %s\n' "$STORED_FP_BEFORE"
if [ -z "$STORED_FP_BEFORE" ]; then
  oops "SAML/Test reported no thumbprint for the stored certificate, so no change to it could be observed"
  exit 0
fi
if [ "$STORED_FP_BEFORE" = "$IDP_FP_BEFORE" ]; then
  ok "the plugin stores the identity provider's current signing certificate ($STORED_FP_BEFORE)"
else
  bad "the stored certificate ($STORED_FP_BEFORE) is not the identity provider's active signing certificate ($IDP_FP_BEFORE), so this phase would be measuring something else"
  exit 0
fi

# --------------------------------------------------------------------------------------------------
# Control: the captured-assertion route works before anything is rotated
# --------------------------------------------------------------------------------------------------
stage "control: a captured assertion is accepted while nothing has changed"
capture control || { oops "the control assertion could not be captured, so nothing below would be attributable"; exit 0; }
present control || exit 0
if [ "$ACS_STATUS" = "200" ] && [ -n "$ACS_TOKEN" ]; then
  ok "the control assertion was accepted and minted a login-outcome token (HTTP 200)"
else
  bad "the control assertion was not accepted (HTTP $ACS_STATUS, body '$ACS_BODY'); the stack is not in a state where a later refusal would mean anything"
  exit 0
fi

# The two assertions that outlive the rotation. Captured back to back so they are the same vintage:
# one is refused after the rotation, the other accepted after the restore, and their ages at those
# two moments are what rules the clock out.
capture stale || { oops "the pre-rotation assertion could not be captured"; exit 0; }
capture falsifier || { oops "the falsifier assertion could not be captured"; exit 0; }

# --------------------------------------------------------------------------------------------------
# Rotate
# --------------------------------------------------------------------------------------------------
stage "rotating the realm's SAML signing key"
# A key provider at a HIGHER priority, which Keycloak then signs with, rather than disabling the old
# one. Disabling would take the retired key out of the descriptor AND out of the JWKS the OpenID side
# of this stack reads, which is a second change this phase is not about; adding one leaves the old
# key present and merely unused, and removing the new component at the end restores the realm exactly.
CREATE_STATUS="$(kc -o /tmp/comp.out -D /tmp/comp.hdr -w '%{http_code}' -X POST \
  "$KEYCLOAK/admin/realms/$REALM/components" -H 'Content-Type: application/json' \
  -d "{\"name\":\"$ROLLOVER_COMPONENT_NAME\",\"parentId\":\"$REALM_ID\",\"providerId\":\"rsa-generated\",\"providerType\":\"org.keycloak.keys.KeyProvider\",\"config\":{\"priority\":[\"200\"],\"enabled\":[\"true\"],\"active\":[\"true\"],\"algorithm\":[\"RS256\"],\"keySize\":[\"2048\"]}}" 2>/dev/null)"
if [ "$CREATE_STATUS" != "201" ]; then
  oops "the identity provider refused the new key provider (HTTP $CREATE_STATUS): $(head -c 300 /tmp/comp.out 2>/dev/null)"
  exit 0
fi
NEW_COMPONENT_ID="$(grep -i '^location:' /tmp/comp.hdr | tr -d ' \r\n' | sed 's#.*/##')"
if [ -z "$NEW_COMPONENT_ID" ]; then
  oops "the new key provider was created but its id could not be read from the Location header, so it cannot be removed again"
  exit 0
fi
stage "the rotated-in key provider is $NEW_COMPONENT_ID"

ROTATED_CERT="$(cert_of_component "$NEW_COMPONENT_ID")"
if [ -z "$ROTATED_CERT" ]; then
  oops "the rotated-in key provider published no RS256 signing certificate"
  exit 0
fi
IDP_FP_AFTER="$(thumb_of "$ROTATED_CERT")"
if [ "$IDP_FP_AFTER" = "$IDP_FP_BEFORE" ]; then
  oops "the rotated-in certificate is the same as the old one, so nothing was rotated"
  exit 0
fi
NOW_ACTIVE="$(thumb_of "$(active_sig_cert)")"
if [ "$NOW_ACTIVE" = "$IDP_FP_AFTER" ]; then
  ok "the identity provider now signs with the rotated-in key ($IDP_FP_AFTER)"
else
  bad "the identity provider still signs with $NOW_ACTIVE after the rotation, so the login below would not be signed by the new key"
  exit 0
fi

IMPORT_STATUS="$(import_certificate "$ROTATED_CERT")"
if [ "$IMPORT_STATUS" != "200" ] && [ "$IMPORT_STATUS" != "204" ]; then
  oops "SAML/Add refused the rotated-in certificate (HTTP $IMPORT_STATUS): $(head -c 300 /tmp/samladd.out 2>/dev/null)"
  exit 0
fi
STORED_FP_AFTER="$(stored_thumbprint)"
printf 'PROBE-CERT-ROTATED %s\n' "$STORED_FP_AFTER"
if [ "$STORED_FP_AFTER" = "$IDP_FP_AFTER" ] && [ "$STORED_FP_AFTER" != "$STORED_FP_BEFORE" ]; then
  ok "the plugin's stored certificate changed across the rotation, from $STORED_FP_BEFORE to $STORED_FP_AFTER"
else
  bad "the plugin's stored certificate did not become the rotated-in one (stored $STORED_FP_AFTER, expected $IDP_FP_AFTER)"
  exit 0
fi

# --------------------------------------------------------------------------------------------------
# The two claims
# --------------------------------------------------------------------------------------------------
stage "the pre-rotation assertion is presented, unused, against the rotated-in certificate"
present stale || exit 0
if [ "$ACS_STATUS" = "400" ]; then
  ok "the assertion signed by the retired key was refused with HTTP 400 at ${ACS_AGE}s old"
else
  bad "the assertion signed by the retired key was answered HTTP $ACS_STATUS, not the 400 a failed signature check produces (body '$ACS_BODY')"
fi
case "$ACS_BODY" in
  *"SAML response validation failed"*)
    ok "the refusal carries the uniform SAML rejection body rather than a server error" ;;
  *)
    bad "the refusal body is not the uniform SAML rejection: '$ACS_BODY'" ;;
esac
if [ -n "$ACS_TOKEN" ]; then
  bad "the refused assertion still handed out a login-outcome token"
else
  ok "the refused assertion handed out no login-outcome token"
fi
STALE_AGE="$ACS_AGE"

stage "a fresh login under the rotated-in certificate"
if capture fresh && present fresh; then
  if [ "$ACS_STATUS" = "200" ] && [ -n "$ACS_TOKEN" ]; then
    ok "an assertion signed by the rotated-in key was accepted (HTTP 200)"
    if redeem fresh; then
      ok "the rotated-in key mints a usable Jellyfin session"
    fi
  else
    bad "the login under the rotated-in certificate was answered HTTP $ACS_STATUS (body '$ACS_BODY')"
  fi
else
  bad "the login under the rotated-in certificate could not be driven at all"
fi

# --------------------------------------------------------------------------------------------------
# The falsifier: put the original certificate back and present the older sibling of the refused one
# --------------------------------------------------------------------------------------------------
stage "restoring the original certificate and presenting the older pre-rotation assertion"
RESTORE_STATUS="$(import_certificate "$ORIGINAL_CERT")"
if [ "$RESTORE_STATUS" != "200" ] && [ "$RESTORE_STATUS" != "204" ]; then
  oops "the original certificate could not be put back (HTTP $RESTORE_STATUS)"
  exit 0
fi
STORED_FP_RESTORED="$(stored_thumbprint)"
printf 'PROBE-CERT-RESTORED %s\n' "$STORED_FP_RESTORED"
if [ "$STORED_FP_RESTORED" = "$STORED_FP_BEFORE" ]; then
  ok "the plugin stores the original certificate again"
else
  bad "the restore left the plugin holding $STORED_FP_RESTORED rather than the original $STORED_FP_BEFORE"
  exit 0
fi

present falsifier || exit 0
if [ "$ACS_STATUS" = "200" ] && [ -n "$ACS_TOKEN" ]; then
  ok "the same-vintage assertion was accepted at ${ACS_AGE}s old, older than the refused one was at ${STALE_AGE}s, so the refusal above was the certificate and not the clock"
else
  bad "the falsifier assertion was answered HTTP $ACS_STATUS at ${ACS_AGE}s old (body '$ACS_BODY'); the refusal above cannot be attributed to the certificate, because an assertion of the same vintage is refused even with the original certificate in place"
fi

printf 'PROBE-DONE\n'
exit 0
