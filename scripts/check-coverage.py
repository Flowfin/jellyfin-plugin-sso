#!/usr/bin/env python3
"""Coverage gate for the RC coverage goal (#718, #1109).

Parses the Cobertura report `dotnet test --coverage` emits and enforces the
security-surface LINE and BRANCH bars: the modules that take security decisions
(SAML validation, OIDC state/issuer/PKCE, account linking, authz, rate limit,
avatar SSRF, network trust, logout, secrets, session mint, audit) must stay at
or above both pinned thresholds, or the job fails. The whole-codebase numbers
are reported but deliberately not enforced, so the gate cannot be tripped by a
trivially-thin non-critical path; only the security surface hard-gates.

Both bars are checked and both are reported before either verdict is returned,
so one run says everything that is wrong rather than hiding the second failure
behind the first.

Line counting is per executable line (lines-covered / lines-valid), never a
per-class average, so a large uncovered class cannot hide behind many small
covered ones. Branch counting is the same shape, read off the per-line
`condition-coverage="P% (c/v)"` the collector writes on every `branch="True"`
line: the c and v are summed across the population rather than the percentages
averaged, for the same reason. The class-level `branch-rate` attribute is
deliberately NOT used - it is already a ratio, so accumulating it would be the
per-class average this file exists not to compute.

Only each class's class-level <lines> block is counted - the per-method <line>
entries duplicate the same lines and would double-count. Fail-closed: a missing
report, an unparsable report, a branch line whose condition-coverage cannot be
read, or zero matched security-surface lines or branches is an error, not a
pass. A population with no branch points is that same error rather than 0%,
which would otherwise read as a total regression.

Usage: check-coverage.py <coverage.cobertura.xml>
"""

import re
import sys
import xml.etree.ElementTree as ET
from pathlib import PurePosixPath, PureWindowsPath

# The security-decision surface: every Api module whose classes decide an
# authentication, authorization, linking, session, network-trust, or
# abuse-control outcome. `Shared` carries the rate-limit gate and the
# served-flow responses; `Flows` is the per-protocol login orchestration; `Net`
# holds the SSRF/public-address verdicts; `Logout` the session-termination
# store; `Provider` the provider-identity validation. The deliberately ungated
# remainder is `Http` (the controller boundary, gated by its endpoint tests and
# the conformance rules), `Routing`/`LoginButtons` (page furniture), and the
# non-guard Config persistence types. Config's security-guard types are matched
# by file name below.
SECURITY_MODULES = {
    "Audit",
    "Authz",
    "Avatar",
    "Crypto",
    "Flows",
    "Identity",
    "Linking",
    "Logout",
    "Net",
    "Oidc",
    "Provider",
    "RateLimit",
    "Saml",
    "Secrets",
    "Session",
    "Shared",
}
SECURITY_CONFIG_FILES = {
    "SsoOnlyLoginGuard.cs",
    "ServerManagedFields.cs",
    "WriteOnlySecretConverter.cs",
    "ConfigImport.cs",
    "ProviderConfigValidator.cs",
    "ProviderConfigStore.cs",
}

# The pinned bars. Each is set just below its first honest measurement so real
# regressions fail while instrumentation jitter does not; ratchet them up as the
# numbers climb, never down without a documented decision.
#
# Line: 93.4% on 2026-07-21, over 5124 security-surface lines.
# Branch: 86.3% on 2026-08-10, over 2888 security-surface branches.
SECURITY_LINE_BAR = 92.0
SECURITY_BRANCH_BAR = 85.0

# The collector writes the branch counts only inside the percentage string, as
# `condition-coverage="66.67% (2/3)"`. The trailing pair is what is read; the
# percentage in front of it is derived from the same two numbers and is not.
CONDITION_COVERAGE = re.compile(r"\((\d+)/(\d+)\)\s*$")


def branch_counts(line: ET.Element) -> tuple[int, int]:
    """Returns (covered, valid) branches for one <line>, or (0, 0) if it has none.

    A line the collector marked `branch="True"` but whose condition-coverage
    cannot be read is a report this script does not understand, so it raises
    rather than contributing nothing: silently skipping such a line would shrink
    the denominator and let the measured percentage rise as the report drifts.
    """
    if (line.get("branch") or "").lower() != "true":
        return 0, 0
    match = CONDITION_COVERAGE.search(line.get("condition-coverage") or "")
    if match is None:
        raise ValueError(
            f"line {line.get('number')} is marked branch=\"True\" but its "
            f"condition-coverage {line.get('condition-coverage')!r} carries no (covered/valid) pair"
        )
    return int(match.group(1)), int(match.group(2))


def module_of(filename: str) -> str | None:
    """Returns the Api module name of a source path, or None.

    A file directly under Api/ (no module folder) yields None; that layout is
    structurally impossible - the FlatApi_HoldsNoSourceFiles conformance test
    keeps the flat Api root empty - so nothing can hide there from this gate.
    """
    parts = PureWindowsPath(filename.replace("/", "\\")).parts
    if "Api" in parts:
        idx = parts.index("Api")
        if idx + 1 < len(parts) - 1:
            return parts[idx + 1]
    if "Config" in parts and parts[-1] in SECURITY_CONFIG_FILES:
        return "Config-guard"
    return None


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: check-coverage.py <coverage.cobertura.xml>", file=sys.stderr)
        return 2
    try:
        root = ET.parse(sys.argv[1]).getroot()
    except (OSError, ET.ParseError) as err:
        print(f"::error::Could not read the coverage report: {err}", file=sys.stderr)
        return 1

    total_valid = total_covered = 0
    sec_valid = sec_covered = 0
    total_br_valid = total_br_covered = 0
    sec_br_valid = sec_br_covered = 0
    for cls in root.iter("class"):
        filename = cls.get("filename", "")
        module = module_of(filename)
        is_security = module in SECURITY_MODULES or module == "Config-guard"
        # The class-level <lines> child only: cls.iter("line") would also walk
        # the per-method <line> copies and double-count every line.
        lines_block = cls.find("lines")
        if lines_block is None:
            continue
        for line in lines_block.iter("line"):
            hits = int(line.get("hits", "0"))
            try:
                br_covered, br_valid = branch_counts(line)
            except ValueError as err:
                print(f"::error::Could not read the coverage report: {filename}: {err}", file=sys.stderr)
                return 1
            total_valid += 1
            total_covered += 1 if hits > 0 else 0
            total_br_valid += br_valid
            total_br_covered += br_covered
            if is_security:
                sec_valid += 1
                sec_covered += 1 if hits > 0 else 0
                sec_br_valid += br_valid
                sec_br_covered += br_covered

    if total_valid == 0 or sec_valid == 0:
        print("::error::The coverage report contains no matched lines - refusing to pass an empty measurement.", file=sys.stderr)
        return 1
    # Nothing on this surface is branch-free, so an empty branch denominator is
    # a report that stopped carrying condition-coverage rather than a codebase
    # without conditions. Refusing here is what keeps the branch bar from being
    # satisfied by a measurement that never happened.
    if total_br_valid == 0 or sec_br_valid == 0:
        print("::error::The coverage report contains no matched branches - refusing to pass an empty measurement.", file=sys.stderr)
        return 1

    overall = 100.0 * total_covered / total_valid
    security = 100.0 * sec_covered / sec_valid
    overall_branch = 100.0 * total_br_covered / total_br_valid
    security_branch = 100.0 * sec_br_covered / sec_br_valid
    print(f"Overall line coverage:            {overall:.1f}% ({total_covered}/{total_valid} lines)")
    print(f"Security-surface line coverage:   {security:.1f}% ({sec_covered}/{sec_valid} lines)")
    print(f"Security-surface line bar:        {SECURITY_LINE_BAR:.1f}%")
    print(f"Overall branch coverage:          {overall_branch:.1f}% ({total_br_covered}/{total_br_valid} branches)")
    print(f"Security-surface branch coverage: {security_branch:.1f}% ({sec_br_covered}/{sec_br_valid} branches)")
    print(f"Security-surface branch bar:      {SECURITY_BRANCH_BAR:.1f}%")

    failed = False
    if security < SECURITY_LINE_BAR:
        failed = True
        print(
            f"::error::Security-surface line coverage {security:.1f}% fell below the pinned "
            f"{SECURITY_LINE_BAR:.1f}% bar (#718). Cover the security-decision paths you touched, "
            "or raise coverage elsewhere on the surface - the bar does not move down.",
            file=sys.stderr,
        )
    if security_branch < SECURITY_BRANCH_BAR:
        failed = True
        print(
            f"::error::Security-surface branch coverage {security_branch:.1f}% fell below the pinned "
            f"{SECURITY_BRANCH_BAR:.1f}% bar (#1109). A branch left untaken on a security-decision "
            "path is a decision nothing exercised - cover it, or raise branch coverage elsewhere on "
            "the surface; the bar does not move down.",
            file=sys.stderr,
        )
    if failed:
        return 1
    print("Coverage gate: PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
