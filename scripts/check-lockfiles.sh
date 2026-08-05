#!/usr/bin/env bash
#
# Lockfile drift gate (issue #1150): report every tracked packages.lock.json that a local build
# modified, at the moment it happens.
#
# NuGet rewrites a lockfile whenever a restore resolves a package version other than the pinned one.
# The usual cause on this repository is an explicit -p:JellyfinVersion on an ordinary local build:
# both defaults in SSO-Auth/SSO-Auth.csproj are conditioned on that property being EMPTY, so any
# value defeats them and restore re-pins every lockfile. Nothing local notices today - the drift is
# found later in git status, or in CI where the --locked-mode restore fails with NU1004 after the
# commit is already pushed.
#
# The set of lockfiles is derived from the index rather than listed here, so a project added later
# is covered without editing this file, and an empty set fails instead of passing vacuously.
#
# This gate REPORTS. It never reverts and never commits: the drift is evidence about the build that
# produced it, and discarding it would hide the cause along with the symptom.
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

lockfiles=()
while IFS= read -r path; do lockfiles+=("$path"); done < <(git ls-files -- '*packages.lock.json')

if [[ ${#lockfiles[@]} -eq 0 ]]; then
  echo "::error::no tracked packages.lock.json found - this gate would pass without checking anything" >&2
  exit 1
fi

dirty=$(git status --porcelain -- "${lockfiles[@]}")

if [[ -z "$dirty" ]]; then
  echo "ok: ${#lockfiles[@]} tracked lockfile(s) unchanged"
  exit 0
fi

drifted=()
echo "::error::a local build modified pinned lockfile(s):" >&2
while IFS= read -r line; do
  echo "  ${line}" >&2
  drifted+=("${line:3}")
done <<<"$dirty"
echo "Do not commit the rewritten pins. Inspect what re-pinned them, then restore with:" >&2
echo "  git checkout -- ${drifted[*]}" >&2
echo "Set no JellyfinVersion property on an ordinary local build: the csproj defaults are conditioned" >&2
echo "on it being empty, so any explicit value re-pins both target frameworks." >&2
exit 1
