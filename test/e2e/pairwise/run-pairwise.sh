#!/usr/bin/env bash
# Pairwise co-existence phase (#1247). This plugin claims it works alone and that it works with every
# supported sibling installed at the same time. The whole-family half of that claim is #1479 and lives
# elsewhere; what this proves is the half this board can prove on its own - the packaged artefact
# installs, and it co-exists with each sibling that has published a release, ONE PAIR AT A TIME.
#
# A green set of pairs is not a green family. Three plugins that each pair cleanly can still collide
# when all three are installed, and nothing here would see it. That bound is printed at the end of every
# run rather than left for a reader to remember.
#
# The set of pairs is DERIVED at run time from the owner's plugin repositories and their release
# listings, never written down here, so a board publishing its first release joins without an edit to
# this file and no count in this repository can go stale. A sibling with nothing to install is SKIPPED
# and the skip is reported with its reason; it never passes silently.
#
#   PLUGIN_ARTIFACT=<path to the JPRM zip> test/e2e/pairwise/run-pairwise.sh
#
# Environment:
#   PLUGIN_ARTIFACT     required - the packaged zip of THIS plugin, as a release ships it
#   SERVER_GENERATION   jf10.11 (default) or jf12 - decides which targetAbi a sibling must carry
#   JELLYFIN_IMAGE_TAG  the server image tag; defaults per generation
#   PAIRWISE_OWNER      the account whose plugin repositories are the sibling set (default Flowfin)
#   PAIRWISE_SELF       this repository's name, excluded from the sibling set
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
COMPOSE="$HERE/docker-compose.yml"
CONFIG_DIR="$HERE/config"

OWNER="${PAIRWISE_OWNER:-Flowfin}"
SELF="${PAIRWISE_SELF:-jellyfin-plugin-sso}"
GENERATION="${SERVER_GENERATION:-jf10.11}"

# The ABI line the booting server belongs to. A sibling built for the other line does not load there,
# and that is a fact about the two release lines rather than a collision between the plugins, so it is
# reported as a skip instead of being counted as a failed pair. Reporting it matters: a silently dropped
# sibling would make an empty run look like a clean one.
if [ "$GENERATION" = "jf12" ]; then
  ABI_PREFIX="12."
  DEFAULT_IMAGE="12.0-rc2"
else
  ABI_PREFIX="10.11"
  DEFAULT_IMAGE="10.11.11"
fi
export JELLYFIN_IMAGE_TAG="${JELLYFIN_IMAGE_TAG:-$DEFAULT_IMAGE}"

JELLYFIN="http://127.0.0.1:8096"
ADMIN_USER="e2eadmin"
ADMIN_PASS="e2e-admin-pw"
EMBY_AUTH='MediaBrowser Client="e2e-pairwise", Device="pairwise", DeviceId="e2e-pairwise-device", Version="1.0.0"'

# This plugin's identity, read from the artefact rather than typed here, so a rename or a GUID change
# cannot leave the assertions looking for a plugin that no longer exists under that name.
SELF_GUID=""
SELF_NAME=""

CONSIDERED=0
RAN=0
SKIPPED=0
FAILED=0
SUMMARY=""

log()  { printf '%s\n' "$*"; }
pass() { printf 'PASS: %s\n' "$*"; }
fail() { printf 'FAIL: %s\n' "$*"; FAILED=$((FAILED + 1)); }
die()  { printf 'FATAL: %s\n' "$*" >&2; exit 1; }
note() { SUMMARY="${SUMMARY}$1"$'\n'; }

[ -n "${PLUGIN_ARTIFACT:-}" ] || die "PLUGIN_ARTIFACT is unset - point it at the packaged plugin zip"
[ -s "$PLUGIN_ARTIFACT" ] || die "PLUGIN_ARTIFACT does not name a readable file: $PLUGIN_ARTIFACT"
command -v jq >/dev/null || die "jq is required"
command -v gh >/dev/null || die "the gh CLI is required to derive the sibling set"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# ---------------------------------------------------------------------------------------------------
# This plugin's own identity, out of the artefact under test
# ---------------------------------------------------------------------------------------------------
unzip -o -q "$PLUGIN_ARTIFACT" meta.json -d "$WORK/self" || die "the packaged plugin zip carries no meta.json"
SELF_GUID="$(jq -r '.guid' "$WORK/self/meta.json")"
SELF_NAME="$(jq -r '.name' "$WORK/self/meta.json")"
SELF_ABI="$(jq -r '.targetAbi' "$WORK/self/meta.json")"
[ -n "$SELF_GUID" ] && [ "$SELF_GUID" != "null" ] || die "the packaged plugin zip declares no guid"
log "This plugin: '$SELF_NAME' $SELF_GUID targetAbi=$SELF_ABI, against a $GENERATION server (jellyfin:$JELLYFIN_IMAGE_TAG)"

case "$SELF_ABI" in
  "$ABI_PREFIX"*) : ;;
  *) die "the artefact's targetAbi $SELF_ABI is not on the $ABI_PREFIX line the $GENERATION server boots - the wrong build metadata was packaged" ;;
esac

# ---------------------------------------------------------------------------------------------------
# Derive the sibling set
# ---------------------------------------------------------------------------------------------------
log "== Deriving the sibling set from $OWNER =="
SIBLINGS="$(gh api "orgs/$OWNER/repos?per_page=100" --paginate \
  --jq '.[] | select(.archived == false) | .name' \
  | grep '^jellyfin-plugin-' | grep -vx "$SELF" | sort)" || die "could not list $OWNER's repositories"
[ -n "$SIBLINGS" ] || die "no sibling plugin repository was found under $OWNER - the derivation is broken, not the family"
log "Sibling repositories considered:"
printf '%s\n' "$SIBLINGS" | sed 's/^/  /'

# ---------------------------------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------------------------------
jf_get() {
  # jf_get <path> [token]
  if [ -n "${2:-}" ]; then
    curl -fsS "$JELLYFIN$1" -H "Authorization: MediaBrowser Token=\"$2\""
  else
    curl -fsS "$JELLYFIN$1" -H "Authorization: $EMBY_AUTH"
  fi
}

jf_post() {
  curl -fsS -X POST "$JELLYFIN$1" -H "Content-Type: application/json" -H "Authorization: $EMBY_AUTH" -d "$2"
}

wait_for_jellyfin() {
  local i=0
  while [ "$i" -lt 90 ]; do
    if curl -fsS -o /dev/null "$JELLYFIN/System/Info/Public" 2>/dev/null; then
      return 0
    fi
    i=$((i + 1)); sleep 5
  done
  return 1
}

teardown() {
  docker compose -f "$COMPOSE" down -v >/dev/null 2>&1 || true
}

# ---------------------------------------------------------------------------------------------------
# One pair
# ---------------------------------------------------------------------------------------------------
run_pair() {
  local repo="$1" zip="$2" sibling_guid="$3" sibling_name="$4" sibling_version="$5"

  log ""
  log "===================================================================================="
  log "== Pair: '$SELF_NAME' + '$sibling_name' $sibling_version ($repo)"
  log "===================================================================================="

  teardown
  # The server writes its whole /config as ROOT, so directories it created are not removable by the
  # unprivileged user running this script - an ordinary rm -rf leaves the previous pair's completed
  # startup wizard in place, and every wizard call on the next pair is then answered 401 by a server
  # that is already set up. Measured on run 33477577867 before this used a container to do the removal.
  # The removal is therefore done AS root, from a throwaway container over the same bind mount, which
  # needs no privilege on the host and raises no prompt. It is asserted afterwards rather than assumed:
  # a reset that silently did nothing is the exact failure this replaces.
  if [ -e "$CONFIG_DIR" ]; then
    docker run --rm -v "$HERE:/w" alpine:3.20 rm -rf /w/config >/dev/null 2>&1 || true
    rm -rf "$CONFIG_DIR" 2>/dev/null || true
  fi
  [ ! -e "$CONFIG_DIR" ] || die "$repo: the previous pair's server state could not be removed from $CONFIG_DIR - every assertion after this would be about the wrong server"

  mkdir -p "$CONFIG_DIR/plugins/SSO-Auth" "$CONFIG_DIR/plugins/$repo"
  unzip -o -q "$PLUGIN_ARTIFACT" -d "$CONFIG_DIR/plugins/SSO-Auth"
  unzip -o -q "$zip" -d "$CONFIG_DIR/plugins/$repo"
  # World-writable so the Jellyfin container persists each plugin's configuration under /config
  # regardless of the uid it runs as.
  chmod -R 0777 "$CONFIG_DIR"

  local ok=1
  docker compose -f "$COMPOSE" up -d >/dev/null || { fail "$repo: the stack did not start"; teardown; return 1; }

  if ! wait_for_jellyfin; then
    fail "$repo: the server never answered /System/Info/Public with both plugins installed"
    docker compose -f "$COMPOSE" logs jellyfin --no-color | tail -60
    teardown
    return 1
  fi
  pass "$repo: the server came up with both plugins installed"

  # The startup wizard, then an admin token: /Plugins and /ScheduledTasks are both administrator-only,
  # and they are the two surfaces a collision is visible on.
  local w=0
  while [ "$w" -lt 30 ] && ! jf_get "/Startup/Configuration" >/dev/null 2>&1; do w=$((w + 1)); sleep 2; done
  local wizard_status
  wizard_status="$(curl -sS -o /dev/null -w '%{http_code}' "$JELLYFIN/Startup/Configuration" -H "Authorization: $EMBY_AUTH")" || wizard_status="000"
  if [ "$wizard_status" != "200" ]; then
    # The status is named rather than swallowed: a 401 here means the server is ALREADY set up, which is
    # a stale bind mount rather than a slow boot, and the two need opposite repairs.
    fail "$repo: the startup wizard answered HTTP $wizard_status (401 means this server was already set up, so the state from an earlier pair survived)"
    teardown
    return 1
  fi
  jf_post "/Startup/Configuration" '{"UICulture":"en-US","MetadataCountryCode":"US","PreferredMetadataLanguage":"en"}' >/dev/null || { fail "$repo: wizard configuration failed"; teardown; return 1; }
  jf_get  "/Startup/User" >/dev/null || true
  jf_post "/Startup/User" "{\"Name\":\"$ADMIN_USER\",\"Password\":\"$ADMIN_PASS\"}" >/dev/null || { fail "$repo: wizard admin creation failed"; teardown; return 1; }
  jf_post "/Startup/RemoteAccess" '{"EnableRemoteAccess":true,"EnableAutomaticPortMapping":false}' >/dev/null || true
  jf_post "/Startup/Complete" '' >/dev/null || { fail "$repo: wizard completion failed"; teardown; return 1; }

  local token
  token="$(jf_post "/Users/AuthenticateByName" "{\"Username\":\"$ADMIN_USER\",\"Pw\":\"$ADMIN_PASS\"}" | jq -r '.AccessToken')" || token=""
  if [ -z "$token" ] || [ "$token" = "null" ]; then
    fail "$repo: no admin token was minted, so nothing below could be compared"
    teardown
    return 1
  fi

  # ---- both plugins loaded ----
  local plugins
  plugins="$(jf_get "/Plugins" "$token")" || plugins=""
  if [ -z "$plugins" ]; then
    fail "$repo: /Plugins did not answer"
    teardown
    return 1
  fi
  log "--- plugins the server reports (compared: Id, Name, Status) ---"
  printf '%s' "$plugins" | jq -r '.[] | "  \(.Id)  \(.Name)  \(.Version)  \(.Status)"'

  # The list must actually hold the two plugins before anything is compared across it. Every duplicate
  # check below is an ABSENCE assertion, and an empty or one-entry list satisfies all of them while
  # comparing nothing - which is how a run that loaded neither plugin reported no collisions.
  local plugin_count
  plugin_count="$(printf '%s' "$plugins" | jq -r 'length')"
  if [ "${plugin_count:-0}" -lt 2 ]; then
    fail "$repo: the server reports $plugin_count loaded plugin(s), so the comparisons below would have inspected nothing"
    ok=0
  fi

  # Jellyfin serializes a Guid WITHOUT hyphens, while a plugin's meta.json declares it with them, so the
  # two are compared on the hyphen-free form. Written as a plain comparison first, this reported both
  # plugins as absent on a server whose own SSO route was answering 200 three lines later - the
  # contradiction is what gave it away, on run 33477577867.
  local self_key sibling_key
  self_key="$(printf '%s' "$SELF_GUID" | tr -d '-' | tr 'A-Z' 'a-z')"
  sibling_key="$(printf '%s' "$sibling_guid" | tr -d '-' | tr 'A-Z' 'a-z')"
  local self_row sibling_row
  self_row="$(printf '%s' "$plugins" | jq -r --arg g "$self_key" '[.[] | select((.Id | ascii_downcase | gsub("-";"")) == $g)] | .[0] // empty')"
  sibling_row="$(printf '%s' "$plugins" | jq -r --arg g "$sibling_key" '[.[] | select((.Id | ascii_downcase | gsub("-";"")) == $g)] | .[0] // empty')"

  if [ -z "$self_row" ]; then
    fail "$repo: THIS plugin ($SELF_GUID) is not loaded with '$sibling_name' installed"
    ok=0
  else
    local self_status
    self_status="$(printf '%s' "$self_row" | jq -r '.Status')"
    if [ "$self_status" = "Active" ]; then
      pass "$repo: this plugin is loaded and Active alongside '$sibling_name'"
    else
      fail "$repo: this plugin is loaded but its status is '$self_status', not Active"
      ok=0
    fi
  fi

  if [ -z "$sibling_row" ]; then
    fail "$repo: the sibling ($sibling_guid) did not load beside this plugin"
    ok=0
  else
    local sibling_status
    sibling_status="$(printf '%s' "$sibling_row" | jq -r '.Status')"
    if [ "$sibling_status" = "Active" ]; then
      pass "$repo: the sibling is loaded and Active alongside this plugin"
    else
      fail "$repo: the sibling is loaded but its status is '$sibling_status', not Active"
      ok=0
    fi
  fi

  # ---- collision scan: plugin identity ----
  local dup_ids dup_names
  dup_ids="$(printf '%s' "$plugins" | jq -r '[.[].Id | ascii_downcase | gsub("-";"")] | group_by(.) | map(select(length > 1) | .[0]) | join(", ")')"
  dup_names="$(printf '%s' "$plugins" | jq -r '[.[].Name] | group_by(.) | map(select(length > 1) | .[0]) | join(", ")')"
  if [ -n "$dup_ids" ]; then fail "$repo: two loaded plugins share a plugin id: $dup_ids"; ok=0; else pass "$repo: no two loaded plugins share a plugin id"; fi
  if [ -n "$dup_names" ]; then fail "$repo: two loaded plugins share a display name: $dup_names"; ok=0; else pass "$repo: no two loaded plugins share a display name"; fi

  # ---- collision scan: scheduled tasks ----
  local tasks
  tasks="$(jf_get "/ScheduledTasks" "$token")" || tasks=""
  if [ -z "$tasks" ]; then
    fail "$repo: /ScheduledTasks did not answer, so no task-name comparison was made"
    ok=0
  else
    log "--- scheduled tasks the server reports (compared: Key, Name) ---"
    if [ "$(printf '%s' "$tasks" | jq -r 'length')" -lt 2 ]; then
      fail "$repo: the server reports fewer than two scheduled tasks, so the key and name comparisons inspected nothing"
      ok=0
    fi
    printf '%s' "$tasks" | jq -r '.[] | "  \(.Key)  \(.Name)"'
    local dup_keys dup_task_names
    dup_keys="$(printf '%s' "$tasks" | jq -r '[.[].Key] | group_by(.) | map(select(length > 1) | .[0]) | join(", ")')"
    dup_task_names="$(printf '%s' "$tasks" | jq -r '[.[].Name] | group_by(.) | map(select(length > 1) | .[0]) | join(", ")')"
    if [ -n "$dup_keys" ]; then fail "$repo: two scheduled tasks share a key: $dup_keys"; ok=0; else pass "$repo: no two scheduled tasks share a key"; fi
    if [ -n "$dup_task_names" ]; then fail "$repo: two scheduled tasks share a name: $dup_task_names"; ok=0; else pass "$repo: no two scheduled tasks share a name"; fi
  fi

  # ---- this plugin's routes still answer ----
  # An administrator-only plugin route, so the assertion covers the whole pipeline the plugin installs:
  # its controller is discovered, its authorization policy resolves, and the sibling has displaced
  # neither. A 200 with a JSON body is the answer; anything else is the failure.
  local check_status
  check_status="$(curl -sS -o "$WORK/check.out" -w '%{http_code}' "$JELLYFIN/SSO/Config/Check" \
    -H "Authorization: MediaBrowser Token=\"$token\"")" || check_status="000"
  if [ "$check_status" = "200" ] && jq -e '.Providers | type == "array"' "$WORK/check.out" >/dev/null 2>&1; then
    pass "$repo: this plugin's SSO/Config/Check route answers 200 with the sibling installed"
  else
    fail "$repo: this plugin's SSO/Config/Check route answered HTTP $check_status with the sibling installed"
    head -c 400 "$WORK/check.out" || true
    ok=0
  fi

  # ---- collision scan: configuration files ----
  # Jellyfin derives a plugin's configuration file from the ASSEMBLY it ships rather than from its
  # display name. That is read off this stack rather than asserted: this plugin's display name is
  # "Community SSO for Jellyfin", it ships SSO-Auth.dll, and the file it persists is SSO-Auth.xml. So
  # two plugins that ship an assembly under one file name write one another's configuration, and the
  # duplicate-name check above cannot see it - their display names differ.
  #
  # The comparison is between the file each plugin ACTUALLY wrote and the assemblies each package
  # actually installed, so a dependency both happen to ship cannot be mistaken for a collision: a shared
  # assembly name matters here exactly when a configuration file resolves to it from both sides, which
  # is the collision itself.
  # Neither plugin writes its configuration file until something saves one, so on a bare boot the
  # directory this scan reads is EMPTY and the scan compares nothing - the same vacuity the plugin and
  # task comparisons were just given a floor against. So each plugin's own configuration is read and
  # posted straight back, unchanged, which is what makes the server write the file. A plugin that
  # refuses its own unmodified configuration is reported rather than ignored: that is a finding about
  # the pair too.
  local pid
  for pid in "$(printf '%s' "$self_row" | jq -r '.Id' 2>/dev/null)" "$(printf '%s' "$sibling_row" | jq -r '.Id' 2>/dev/null)"; do
    [ -n "$pid" ] && [ "$pid" != "null" ] || continue
    local current
    current="$(jf_get "/Plugins/$pid/Configuration" "$token")" || current=""
    if [ -z "$current" ]; then
      log "  (plugin $pid returned no configuration to write back)"
      continue
    fi
    curl -fsS -X POST "$JELLYFIN/Plugins/$pid/Configuration"       -H "Content-Type: application/json"       -H "Authorization: MediaBrowser Token=\"$token\""       -d "$current" >/dev/null 2>&1       || log "  (plugin $pid refused its own unmodified configuration, so it wrote no file)"
  done

  local conf_dir="$CONFIG_DIR/plugins/configurations"
  local self_dlls sibling_dlls conf_files claimed_twice=""
  self_dlls="$(cd "$CONFIG_DIR/plugins/SSO-Auth" && ls -1 ./*.dll 2>/dev/null | sed 's#^\./##; s#\.dll$##' | sort || true)"
  sibling_dlls="$(cd "$CONFIG_DIR/plugins/$repo" && ls -1 ./*.dll 2>/dev/null | sed 's#^\./##; s#\.dll$##' | sort || true)"
  conf_files="$(ls -1 "$conf_dir" 2>/dev/null | sed 's#\.xml$##' | sort || true)"

  log "--- configuration-file scan (compared: the .xml files written, against the assemblies each package installed) ---"
  log "  configuration files written:"
  if [ -n "$conf_files" ]; then printf '%s\n' "$conf_files" | sed 's/^/    /'; else log "    (none)"; fi
  log "  assemblies installed by this plugin:"
  printf '%s\n' "$self_dlls" | sed 's/^/    /'
  log "  assemblies installed by $repo:"
  printf '%s\n' "$sibling_dlls" | sed 's/^/    /'

  while IFS= read -r conf; do
    [ -n "$conf" ] || continue
    if printf '%s\n' "$self_dlls" | grep -qxF "$conf" && printf '%s\n' "$sibling_dlls" | grep -qxF "$conf"; then
      claimed_twice="$claimed_twice $conf.xml"
    fi
  done <<CONF
$conf_files
CONF

  if [ -z "$conf_files" ]; then
    fail "$repo: no plugin configuration file was written, so this scan compared nothing"
    ok=0
  elif [ -n "$claimed_twice" ]; then
    fail "$repo: a plugin configuration file resolves to an assembly BOTH packages install:$claimed_twice"
    ok=0
  else
    pass "$repo: no configuration file resolves to an assembly both packages install"
  fi

  # This plugin's own configuration must be the file it has always been. A sibling that displaced it
  # would leave the server loading this plugin against another plugin's settings, and the resolve scan
  # above cannot see that on its own: it asks whether a file is claimed twice, not whether OUR file is
  # still there at all.
  if grep -qxF "SSO-Auth" <<< "$conf_files"; then
    pass "$repo: this plugin's configuration is still SSO-Auth.xml"
  else
    fail "$repo: this plugin wrote no SSO-Auth.xml with '$sibling_name' installed"
    ok=0
  fi

  # ---- the server came up CLEAN, not merely up ----
  local logfile="$WORK/jellyfin-$repo.log"
  docker compose -f "$COMPOSE" logs jellyfin --no-color >"$logfile" 2>/dev/null || true
  log "read $(wc -c <"$logfile") bytes of Jellyfin log for this pair"
  if grep -qiE 'error (loading|while loading) plugin|failed to load plugin' "$logfile"; then
    fail "$repo: the Jellyfin log reports a plugin failing to load"
    grep -iE 'error (loading|while loading) plugin|failed to load plugin' "$logfile" | head -10
    ok=0
  else
    pass "$repo: the Jellyfin log reports no plugin failing to load"
  fi

  teardown

  [ "$ok" = "1" ]
}

# ---------------------------------------------------------------------------------------------------
# The loop
# ---------------------------------------------------------------------------------------------------
while IFS= read -r repo; do
  [ -n "$repo" ] || continue
  CONSIDERED=$((CONSIDERED + 1))

  release="$(gh api "repos/$OWNER/$repo/releases?per_page=100" \
    --jq '[.[] | select(.draft == false and .prerelease == false)] | .[0] // empty')" || release=""
  if [ -z "$release" ]; then
    SKIPPED=$((SKIPPED + 1))
    note "  SKIPPED $repo - no non-draft, non-prerelease release to install"
    log "SKIP $repo: no non-draft, non-prerelease release to install"
    continue
  fi

  tag="$(printf '%s' "$release" | jq -r '.tag_name')"
  zip_url="$(printf '%s' "$release" | jq -r '[.assets[] | select((.name | endswith(".zip")) and ((.name | endswith(".zip.meta.json")) | not))] | .[0].browser_download_url // empty')"
  if [ -z "$zip_url" ]; then
    SKIPPED=$((SKIPPED + 1))
    note "  SKIPPED $repo - release $tag carries no plugin zip asset"
    log "SKIP $repo: release $tag carries no plugin zip asset"
    continue
  fi

  zip_name="$(basename "$zip_url")"
  zip_path="$WORK/$zip_name"
  curl -fsSL -o "$zip_path" "$zip_url" || { SKIPPED=$((SKIPPED + 1)); note "  SKIPPED $repo - the release asset could not be downloaded"; log "SKIP $repo: could not download $zip_url"; continue; }

  # Verify the artefact against the release's own sha256 sidecar where it publishes one. This is not a
  # supply-chain guarantee - the sidecar travels with the file it describes - but it does refuse a
  # truncated or corrupted download, which would otherwise read as a sibling that does not load.
  # JPRM names the integrity sidecars after the artefact with its .zip suffix REPLACED, not appended
  # (requests_0.2.0.0.zip is published beside requests_0.2.0.0.sha256), so the name is derived by
  # stripping the suffix. Written the other way round first, this looked for a file no release publishes
  # and reported every artefact as unverified while saying so out loud - which is how it was caught.
  sha_name="${zip_name%.zip}.sha256"
  sha_url="$(printf '%s' "$release" | jq -r --arg n "$sha_name" '[.assets[] | select(.name == $n)] | .[0].browser_download_url // empty')"
  if [ -n "$sha_url" ]; then
    curl -fsSL -o "$zip_path.sha256" "$sha_url" || true
    if [ -s "$zip_path.sha256" ]; then
      expected="$(tr -d '\r' <"$zip_path.sha256" | awk '{print $1}' | head -1)"
      actual="$(sha256sum "$zip_path" | awk '{print $1}')"
      if [ "$expected" != "$actual" ]; then
        FAILED=$((FAILED + 1))
        note "  RED     $repo - the downloaded artefact does not match its published sha256"
        log "FAIL $repo: sha256 mismatch, published $expected, downloaded $actual"
        continue
      fi
      log "$repo: artefact matches its published sha256"
    fi
  else
    log "$repo: the release publishes no sha256 sidecar, so the download was not verified against one"
  fi

  unzip -o -q "$zip_path" meta.json -d "$WORK/meta-$repo" 2>/dev/null || true
  if [ ! -s "$WORK/meta-$repo/meta.json" ]; then
    SKIPPED=$((SKIPPED + 1))
    note "  SKIPPED $repo - the release zip carries no meta.json, so it is not an installable plugin package"
    log "SKIP $repo: the release zip carries no meta.json"
    continue
  fi

  sibling_guid="$(jq -r '.guid // empty' "$WORK/meta-$repo/meta.json")"
  sibling_name="$(jq -r '.name // empty' "$WORK/meta-$repo/meta.json")"
  sibling_version="$(jq -r '.version // empty' "$WORK/meta-$repo/meta.json")"
  sibling_abi="$(jq -r '.targetAbi // empty' "$WORK/meta-$repo/meta.json")"

  case "$sibling_abi" in
    "$ABI_PREFIX"*) : ;;
    *)
      SKIPPED=$((SKIPPED + 1))
      note "  SKIPPED $repo - its release targets ABI $sibling_abi, and this run boots the $ABI_PREFIX line"
      log "SKIP $repo: targetAbi $sibling_abi is not on the $ABI_PREFIX line this $GENERATION run boots"
      continue
      ;;
  esac

  RAN=$((RAN + 1))
  # The verdict is recorded HERE rather than inside run_pair: every early return in there - a stack that
  # would not start, a server that never answered - is a red pair too, and a note written only on the
  # path that reaches the end would leave exactly those out of the summary.
  if run_pair "$repo" "$zip_path" "$sibling_guid" "$sibling_name" "$sibling_version"; then
    note "  RAN     $repo ($sibling_name $sibling_version) - green"
  else
    note "  RAN     $repo ($sibling_name $sibling_version) - RED"
  fi
done <<EOF
$SIBLINGS
EOF

# ---------------------------------------------------------------------------------------------------
# The accounting, printed whether the run was green or red
# ---------------------------------------------------------------------------------------------------
log ""
log "===================================================================================="
log "Pairwise co-existence, $GENERATION (jellyfin:$JELLYFIN_IMAGE_TAG)"
log "  siblings considered: $CONSIDERED"
log "  pairs run:           $RAN"
log "  siblings skipped:    $SKIPPED"
log "  failing assertions:  $FAILED"
printf '%s' "$SUMMARY"
log ""
log "WHAT THIS RUN DOES NOT COVER: a green set of pairs is not a green family. Three plugins that each"
log "pair cleanly can still collide with all three installed, and nothing here would see it. That is"
log "#1479 and it is not checked on this board."
log "===================================================================================="

if [ "$FAILED" -gt 0 ]; then
  exit 1
fi
exit 0
