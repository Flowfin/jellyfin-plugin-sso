# Security remediation & secrets policy

The written policy behind the gates CI already enforces. Rule of this document:
it describes **what the tooling actually does** - if enforcement and policy
ever drift, the policy is corrected or the gate is fixed, never papered over.

## SCA - dependency vulnerabilities

- **Merge gate:** a pull request that introduces or upgrades to a dependency
  with a known vulnerability of **any severity (low and up)** is blocked
  (`dependency-review` runs with `fail-on-severity: low`), transitive
  dependencies included. The build itself also fails on known-vulnerable
  dependencies, so the gate holds even outside PR context.
- **Release gate:** a release is cut from a green `main`; the same checks make
  a release with a known-vulnerable dependency impossible without an explicit,
  documented exception (see _Accepted residuals_).
- **Remediation timeframe** (for a vulnerability newly published against an
  already-merged dependency): critical/high - patch or mitigate in the **next
  release, expedited if exploitation is likely** (target: days, not weeks);
  medium - next regular release; low - next regular release or batched with
  the following one. Dependabot PRs for security updates are prioritized over
  feature work (security before features).
- **Dependabot** watches both ecosystems (NuGet and GitHub Actions); its
  security PRs run the full gate like any other change.

### Publishing a not-exploitable disposition (VEX)

- **What may be dispositioned at all:** only a finding this plugin does not
  reach - a transitive component whose vulnerable code no plugin path executes.
  A vulnerability in code the login path runs is **fixed**, never dispositioned;
  the existence of VEX does not soften the merge gate above or the
  security-before-features ordering. "Upgrading is inconvenient" is not a
  disposition.
- **Who decides, and on what evidence:** I do, and the evidence is a
  reachability argument written down with the statement: which entry point would
  have to be reached for the advisory to bite, and what stops it. The statement
  carries a `justification` from the **OpenVEX enum** (so a consumer can act on
  it) plus an `impact_statement` a person can read.
  `scripts/check-vex.py` refuses free text in the justification field, so a
  statement that skips the enum fails the build rather than shipping.
- **When it is written:** in the **same change** that dispositions the finding,
  never batched afterwards - the reasoning is only cheap while the triage is in
  hand, and an undocumented disposition is indistinguishable from an overlooked
  one.
- **Where it lives:** `security/vex/openvex.json`, at that fixed path. Product
  identifiers use the same purls the CycloneDX SBOM emits, so a consumer joins
  the two without a mapping table; the checker compares products against an SBOM
  when it is handed one, and validates the document's structure on every pull
  request. A document with **zero statements is the correct state** while
  nothing is triaged as not-exploitable.
- **When a statement is revisited or withdrawn:** when the dependency is
  upgraded past the advisory, or when the reachability judgement stops holding -
  a new call site into the component is the ordinary trigger. The statement is
  corrected or removed in the change that broke it, not left to be discovered by
  whoever next reads the document.

## SAST - static analysis

- **Merge gate:** CodeQL (with the `security-extended` query pack) and the
  repository-specific Opengrep invariant ruleset run on every pull request;
  **any Opengrep finding fails the check outright** (`--error`), and CodeQL
  alerts on the PR block merge until dispositioned. The .NET build runs with
  warnings-as-errors, which promotes analyzer findings to build failures.
- **Disposition of findings:** a finding is either **fixed before merge** or
  **explicitly accepted** with a written rationale (a code comment at the site
  or a note in the PR) - silent dismissal is not an option. False positives in
  the Opengrep ruleset are fixed in the ruleset itself, never waived ad hoc.
- **Accepted residuals** are documented where they live: the
  [Review Gate](https://github.com/Flowfin/jellyfin-plugin-sso/wiki/Review-Gate)
  wiki page records the known accepted residual(s) of the overall gate stack.
  A dependency advisory triaged as not-exploitable is not a residual of this
  kind - it is a published statement in `security/vex/openvex.json`, under
  _Publishing a not-exploitable disposition (VEX)_ above.

## Secrets management

- **No plaintext secrets in version control - enforced, not aspirational:**
  GitHub secret scanning with **push protection** blocks a credential push
  before it lands; there are no committed credentials, and the repository
  history is clean of them.
- **CI credentials are least-privilege:** workflows start from an explicit
  deny-all (`permissions: {}`) and grant per-job read-only scopes; publishing
  jobs use the ephemeral `GITHUB_TOKEN` with only the scopes the job needs.
  There are no long-lived cloud credentials in this repository; if a cloud
  integration is ever added, it uses **OIDC federation, not stored secrets**.
- **Runtime secrets** (the operator's OIDC client secret, SAML signing keys)
  never appear in the repository or CI at all - they live in the operator's
  plugin configuration, AES-256-GCM-encrypted at rest with a separate key file
  (see [SECURITY.md](../SECURITY.md)), are write-only in the admin API, and are
  redacted from configuration exports.
- **Rotation:** my GitHub credentials use the platform's strong-auth features;
  a leaked or suspected-leaked credential is rotated immediately and the
  incident is noted in the affected release notes if any artifact could have
  been touched.

## Scope

This policy covers the repository, its CI, and its release artifacts. Server
operators' deployment secrets are covered by their own operational practices -
the plugin's contribution is that it never logs, exports, or returns them.
