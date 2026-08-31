# Roadmap

This page defines how the plugin's readiness is communicated and where it stands
today. It is the single place that explains the maturity labels you see in the
README and in the plugin's configuration page.

## Where it stands

**Current stage: Beta** - the third rung of the ladder.

```
○ In-Development  →  ○ Alpha  →  ● Beta  →  ○ Release Candidate  →  ○ Full Release
                                 ▲ you are here
```

Beta means feature-complete and interface-stable: work is limited to bug fixes
and hardening, and no new breaking change lands without a documented migration
path. Wider testing on real but non-critical instances is encouraged; as with
any auth change, keep a config backup.

## The maturity ladder

The project moves through five stages. Each has a plain definition, who it is
for, and the explicit gates that must be met before it advances. The gates are
deliberately conservative: this is a login path, so readiness is proven, not
assumed.

### 1. In-Development

The core is being (re)built and hardened. Features are incomplete, interfaces
and configuration can change without notice, and known security gaps are still
being closed.

- **For whom:** developers, on throwaway instances only.
- **Gates to Alpha:**
  - the automated test net is established and green in CI;
  - security parity with the reference implementation is substantially reached
    (the P2 milestone), with no known exploitable finding left open;
  - a from-source install works end to end for both OpenID Connect and SAML.

### 2. Alpha

OpenID Connect and SAML sign-in work for the common providers, but the feature
surface is not yet complete and breaking changes are still possible.

- **For whom:** early adopters willing to test on non-critical instances and
  report back; still never on production.
- **Gates to Beta:**
  - feature parity with the reference implementation reached (the P4 milestone);
  - the CI and supply-chain hardening in place (the P5 / P5b milestones);
  - user-facing documentation complete for every shipped feature;
  - no open High or Critical security finding.

### 3. Beta - _current_

Feature-complete and interface-stable. Work is limited to bug fixes and
hardening; no new breaking change lands without a documented migration path.

- **For whom:** wider testing on real but non-critical instances is encouraged.
- **Gates to Release Candidate:**
  - a full end-to-end functional pass is green against a live Jellyfin server;
  - the test-coverage goal is met;
  - zero open security findings;
  - delivery metrics are tracked (the P6 milestone);
  - **user-facing polish** meets its definition of done - accurate catalog
    listing, README provider matrix / comparison / visual quick-start, wiki
    navigation, social-preview image, support on-ramps, consistent
    status/version references - tracked item by item in
    [#822](https://github.com/Flowfin/jellyfin-plugin-sso/issues/822).
- **How promotion is decided:** the gates above are tracked with linked
  evidence in the **P8 promotion epic**
  ([#716](https://github.com/Flowfin/jellyfin-plugin-sso/issues/716)) - each gate
  has a defined evidence artifact (a recorded live E2E run, a CI coverage report
  meeting the numeric goal, an empty open-security list, a refreshed
  `METRICS.md`, and the checked-off polish list in #822). The Beta→RC maturity
  flip in the README status line and the plugin config page happens **only when
  all boxes are checked with their evidence** - the promotion is an auditable
  record, never a judgement call.

### 4. Release Candidate

_This is the deliberate name for the stage between Beta and Full Release - a
frozen, production-ready candidate awaiting confirmation in the field, rather
than a "release beta"._

The build is frozen and treated as production-ready. Only a release-blocking
defect can pull a change in; everything else waits for the next cycle.

- **For whom:** cautious production trials on instances with a rollback plan.
- **Gates to Full Release:**
  - a candidate build survives a defined soak period with no release-blocking
    defect reported.

### 5. Full Release

Production-ready. Safe for real Jellyfin instances with real accounts, with the
stability and upgrade guarantees expected of a stable line.

- **For whom:** everyone.

## How the engineering work maps to the ladder

The work that carries the plugin up the ladder is tracked as phase milestones on
the [SSO Roadmap board](https://github.com/users/iderex/projects/1):

| Phase                        | Focus                                                   | Ladder stage it unlocks  |
| ---------------------------- | ------------------------------------------------------- | ------------------------ |
| **P2 - Security parity**     | Port the reference implementation's hardening           | In-Development → Alpha   |
| **P3 - Code quality**        | Thin the controller into tested, single-purpose helpers | (throughout)             |
| **P4 - Feature parity**      | Close the remaining feature gaps                        | Alpha → Beta             |
| **P5 - CI & supply chain**   | Reproducible builds, provenance, dependency hygiene     | Alpha → Beta             |
| **P5b - Review-gap program** | Independent second-perspective review on every change   | Alpha → Beta             |
| **P6 - Delivery metrics**    | Track delivery and stability                            | Beta → Release Candidate |

## Principles

- **Security before features.** This is a login path; the default posture is
  fail-closed, and security work outranks feature work.
- **Documentation describes what is implemented today**, never a planned feature.
  If a page disagrees with the code, the code wins - please open an issue.
- **Every change is issue-driven, reviewed, and documented** before it merges.

## Distribution

This is an **independent plugin repository**, installed by adding its own manifest under
**Plugins → Repositories** (see [Installation](https://github.com/Flowfin/jellyfin-plugin-sso/wiki/Installation)). Jellyfin's built-in official
catalog (`jellyfin/jellyfin-meta-plugins`) lists only plugins that live in the
[`jellyfin`](https://github.com/jellyfin) GitHub org, and there is currently no official SSO
plugin there - the LDAP plugin is the only official auth plugin. Official-catalog inclusion
would require adoption into the `jellyfin` org through that project's governance. **Decision
(2026-07): the project stays independent for now**, with that path understood and kept open.

### Ecosystem outreach

Where people looking for this plugin actually land, what was decided for each of
those places, and what has happened so far. A surface counts as posted only when
something was posted; a text that exists but has not been sent reads as drafted,
because those are different states and the difference is the whole point of
recording them.

| Surface                             | Decision                                                                                               | Status                                                                                                              |
| ----------------------------------- | ------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------- |
| `awesome-jellyfin` list ([#1086])   | Repoint the existing entry rather than add a second one beside it, as a pull request against that list | drafted, awaiting me                                                                                                |
| Upstream Jellyfin threads ([#1087]) | One factual note that a maintained continuation exists, and not on the open native-OIDC pull request   | drafted, awaiting me                                                                                                |
| Archived `9p4` repository ([#1088]) | Nothing is lodged there                                                                                | not actionable - the repository is archived, so it is read-only for issues, pull requests, comments and discussions |

Nothing in the table has been posted. How this plugin sits beside Jellyfin's
built-in auth, the official LDAP plugin and the archived `9p4` plugin is the
[Comparison](https://github.com/Flowfin/jellyfin-plugin-sso/wiki/Comparison) wiki
page, which is the positioning any of these surfaces would point at.

[#1086]: https://github.com/Flowfin/jellyfin-plugin-sso/issues/1086
[#1087]: https://github.com/Flowfin/jellyfin-plugin-sso/issues/1087
[#1088]: https://github.com/Flowfin/jellyfin-plugin-sso/issues/1088

## Upstream watch

Jellyfin upstream is building **native OIDC** into the server
([jellyfin/jellyfin#17271](https://github.com/jellyfin/jellyfin/pull/17271), landing 13.0
at the earliest - 12.0 is in feature freeze). The plugin's documented stance -
complementary, strictly broader (SAML, folder/Live-TV RBAC, linking, avatars, SSO-only),
and the only option on every current release line - lives on
[Native OIDC Coexistence](https://github.com/Flowfin/jellyfin-plugin-sso/wiki/Native-OIDC-Coexistence), together with the link-model
migration honesty.

## Future directions

The EU Digital Identity Wallet, defined by eIDAS 2.0 (Regulation (EU) 2024/1183)
and presented to a relying party over OpenID4VP and OpenID4VCI, is recorded here
as a possible future identity-provider direction. It is not planned, it is not
implemented, and nothing in the plugin speaks either protocol.

A deployment that wants wallet login before any of that can put a verifier
speaking OpenID4VP in front of this plugin and let the plugin consume it as an
ordinary OpenID Connect provider, which needs no plugin change. No recipe for
that arrangement is published here yet.

Whether a verifier is ever built into the plugin depends on conditions outside
the project: a relying-party registration route a self-hoster can actually use,
a maintained .NET verifier library, and wallet verification arriving in the
identity providers people already run. Issue
[#762](https://github.com/Flowfin/jellyfin-plugin-sso/issues/762) carries the
reading behind this entry.

## Following along

- The [SSO Roadmap board](https://github.com/users/iderex/projects/1) is the live
  source of truth for what is done and what is next.
- The [Home](https://github.com/Flowfin/jellyfin-plugin-sso/wiki/Home) page lists what the plugin does today.
- The [Security Model](https://github.com/Flowfin/jellyfin-plugin-sso/wiki/Security-Model) page explains how the login path fails closed.
