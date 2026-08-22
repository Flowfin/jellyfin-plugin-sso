#!/bin/sh
# Drives the client-attribution phase's requests from inside the compose network (#1125). Jellyfin
# publishes no port to the host and neither does the proxy, so every request has to originate from
# a container on `ssonet`.
#
# It is a FILE rather than a string handed to `sh -c`, for the reason probe-oid-start.sh records:
# a script that arrives as one argument through two layers cannot be read in the log it failed in.
#
# It never exits non-zero. Every answer is printed as a PROBE- line and the caller decides what a
# missing one means, so a broken probe can never be read as a proven rate limit.
#
# What it does, in order:
#
#   ready     waits for the plugin's own route THROUGH THE PROXY. Waiting on Jellyfin directly
#             would leave the proxy unproven, and a first request that fails because nginx is not
#             up yet is indistinguishable here from one the plugin refused.
#   control   one challenge as client A. A redirect is the baseline; without it, a 429 later says
#             nothing, because a stack that was already refusing would produce one for free.
#   exhaust   the same challenge as client A until it answers 429. The budget the phase wrote is
#             small, so this is a handful of requests, and a run that never sees a 429 reports the
#             statuses it did see.
#   other     one challenge as client B, the assertion the phase exists for. B has spent nothing.
#             If the limiter keyed on the proxy hop rather than on the forwarded client, A's
#             exhaustion is B's exhaustion and this answers 429.
set -u

say() { printf '%s\n' "$*"; }

PROXY_URL="${PROXY_URL:-http://proxy}"
CLIENT_A="${CLIENT_A:-11.0.9.11}"
CLIENT_B="${CLIENT_B:-11.0.9.22}"
MAX_TRIES="${MAX_TRIES:-8}"

if ! apk add --no-cache curl >/tmp/apk.out 2>&1; then
    say "PROBE-ERROR could not install curl:"
    sed 's/^/  /' /tmp/apk.out
    exit 0
fi
say "PROBE-STAGE curl $(curl --version 2>/dev/null | head -1)"

# Readiness is the plugin's own route, not the server's: /System/Info/Public answers while Jellyfin
# is still coming up, and the challenge then returns a startup splash page rather than a redirect.
# /sso/OID/GetNames only answers once the plugin is loaded, which is the state this probe is about.
i=0
until curl -fsS -o /dev/null -H "X-Test-Client: $CLIENT_A" "$PROXY_URL/sso/OID/GetNames" 2>/tmp/ready.err; do
    i=$((i + 1))
    if [ "$i" -ge 150 ]; then
        say "PROBE-ERROR the plugin did not answer $PROXY_URL/sso/OID/GetNames through the proxy within 300s:"
        sed 's/^/  /' /tmp/ready.err
        exit 0
    fi
    sleep 2
done
say "PROBE-STAGE ready after $i retries ($((i * 2))s)"

# No -L: the healthy answer is the redirect itself, and following it would report the identity
# provider's status instead of the plugin's.
challenge() { # $1 forwarded client address; echoes the status
    curl -sS -o /dev/null -w '%{http_code}' \
        -H "X-Test-Client: $1" \
        "$PROXY_URL/sso/OID/start/$PROVIDER" 2>/tmp/challenge.err \
        || echo "000"
}

say "PROBE-CONTROL $(challenge "$CLIENT_A")"

# The exhaust loop reports every status it saw, not only the last one, so a run that ends without a
# 429 says what the endpoint answered instead of only that the expected one never arrived.
seen=""
throttled_at=""
n=1
while [ "$n" -le "$MAX_TRIES" ]; do
    code="$(challenge "$CLIENT_A")"
    seen="$seen $code"
    if [ "$code" = "429" ]; then
        throttled_at="$n"
        break
    fi
    n=$((n + 1))
done
say "PROBE-EXHAUST-STATUSES$seen"
say "PROBE-EXHAUST-THROTTLED-AT ${throttled_at:-none}"

say "PROBE-OTHER-CLIENT $(challenge "$CLIENT_B")"
say "PROBE-CLIENTS $CLIENT_A $CLIENT_B"
