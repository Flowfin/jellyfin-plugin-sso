#!/bin/sh
# One request against the plugin's OpenID challenge, from inside a container on the compose
# network (#1130). Jellyfin publishes no port to the host, so every service is reachable only by
# its service-DNS name from inside `ssonet`, and a host-side curl reaches nothing.
#
# It is a FILE rather than a string handed to `sh -c`, because the first version of this probe was
# the latter and came back with a status nothing in it can produce and a missing body file. A
# script that arrives as one argument through two layers is not readable in the log it fails in.
#
# It never exits non-zero. A failure here is reported as a PROBE-ERROR line and the caller decides
# what a missing answer means, so a broken probe cannot be read as a refused login.
set -u

say() { printf '%s\n' "$*"; }

if ! apk add --no-cache curl >/tmp/apk.out 2>&1; then
  say "PROBE-ERROR could not install curl:"
  sed 's/^/  /' /tmp/apk.out
  exit 0
fi
say "PROBE-STAGE curl $(curl --version 2>/dev/null | head -1)"

i=0
until curl -fsS -o /dev/null "$JELLYFIN_URL/System/Info/Public" 2>/tmp/ready.err; do
  i=$((i + 1))
  if [ "$i" -ge 150 ]; then
    say "PROBE-ERROR Jellyfin did not answer $JELLYFIN_URL/System/Info/Public within 300s:"
    sed 's/^/  /' /tmp/ready.err
    exit 0
  fi
  sleep 2
done
say "PROBE-STAGE ready after $i retries"

# No -L: the healthy answer is the redirect itself, and following it would report the identity
# provider's status instead of the plugin's.
code="$(curl -sS -o /tmp/probe.body -w '%{http_code}' "$JELLYFIN_URL/sso/OID/start/$PROVIDER" 2>/tmp/probe.err)" || {
  say "PROBE-ERROR the challenge request failed:"
  sed 's/^/  /' /tmp/probe.err
  exit 0
}
say "PROBE-STATUS $code"
if [ -s /tmp/probe.body ]; then
  say "PROBE-BODY $(tr -d '\r\n' < /tmp/probe.body | cut -c1-300)"
else
  say "PROBE-BODY "
fi
