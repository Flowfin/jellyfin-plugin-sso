# Fuzzing the untrusted-input parse surface (#402)

This project is the coverage-guided fuzz harness prototype for the plugin's login-path parsers, and the
written evaluation behind [Scorecard alert #36 (Fuzzing)](https://github.com/Flowfin/jellyfin-plugin-sso/issues/402).
It is the concrete harness the weekly scheduled job (#174) runs.

It is **out of band**: not part of `SSO-Auth.sln`, so a normal `dotnet build` / `dotnet test` never
restores SharpFuzz or builds it. The _fuzzing_ is driven only by the scheduled Linux job, exactly as the
acceptance criteria require ("scheduled, non-blocking"). Since #1132 the gating `build` job does compile
the harness by path, so a module rename that breaks it reds the PR rather than the weekly run.

Since #1134 that job also **replays every committed seed** through its target in smoke mode, which asks a
different question from compiling: a plugin change can leave the harness building perfectly while making a
known-hostile input throw an exception the fail-closed filters do not name. The target list comes from the
corpus directories, so a new target is replayed by the fact of having a corpus. An empty corpus directory,
or no corpus at all, fails the step rather than passing quietly. The coverage-guided run stays non-gating.

## The attack surface we target

The login endpoints are anonymous and hand attacker-controlled bytes straight into parsers before any
signature or claim is trusted. Those byte-level entry points are the classic fuzzing sweet spot, and they
are what the harness drives (selected per run by the `SSO_FUZZ_TARGET` environment variable):

| Target (`SSO_FUZZ_TARGET`) | Entry point                                                                                                   | Untrusted input                                                                                      |
| -------------------------- | ------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------- |
| `saml` (default)           | `SamlResponseLoader.TryParse` → `SamlResponse` ctor + `IsValid` + every claim getter                          | The Base64 `SAMLResponse` form field (Base64 decode → hardened XML DOM load → signature/claim reads) |
| `discovery`                | `StrictJson.Inspect`, `PkceDiscovery.SupportsS256` and `OidcResponseIssuer.DiscoveryAdvertisesResponseIssuer` | The raw OpenID discovery JSON fetched at challenge                                                   |
| `idtoken`                  | `OidcResponseIssuer.IdTokenIssuer` (`new JsonWebToken(token)`)                                                | The raw id_token JWT string                                                                          |
| `jwks`                     | `OidcSignatureKeys.Convert` (after the library's `new JsonWebKeySet(json)`)                                   | The raw JWKS the challenge fetches from `jwks_uri`                                                   |
| `roles`                    | `OidcRoleExtractor.ExtractRoles`, driven at both terminal shapes from one input                               | The role-claim value from the id_token or the UserInfo response                                      |

The property under test is uniform: on **any** input the entry point must terminate with a fail-closed
result (`false` / `null` / a rejection) **or** one of the exceptions it explicitly maps - it must never
leak an unmapped exception (which on the real callback becomes an unauthenticated HTTP 500 / DoS) and
must never hang. A crash libFuzzer records is therefore a genuine finding: an exception type the
fail-closed filters do not catch, or a hang.

### What is deliberately out of scope

- **Signature forgery / "unexpected accept".** Coverage-guided fuzzing over random bytes cannot forge an
  XML-DSig or JWT signature that verifies against the pinned key, so it cannot reach an auth _bypass_; it
  finds _crashers_, not accepts. The accept-side invariants (a response is valid only with a correctly
  scoped, correctly signed assertion) are pinned by the `SamlResponse` / `OidcIdTokenValidator` unit
  tests and the FsCheck property suite instead.
- **The full `OidcIdTokenValidator.ValidateAsync`.** Its signature/issuer/audience/lifetime checks need a
  populated `OidcClientOptions` (discovery JWKS, client id, clock skew) and an `async` boundary, which do
  not fit libFuzzer's synchronous single-`ReadOnlySpan<byte>` contract cleanly. The **parse** half of the
  id_token surface (`IdTokenIssuer`) is fuzzed here; the **validation** half stays covered by
  `OidcIdTokenValidatorTests`. Wiring a `ValidateAsync` target with a fixed key set is the natural first
  expansion for #174.

## Why SharpFuzz, not ClusterFuzzLite (or OSS-Fuzz)

The acceptance criteria ask us to pick between ClusterFuzzLite and SharpFuzz, or document why neither
fits. They are not really alternatives - one is the .NET fuzzing _engine_, the other a CI _runner_:

- **OSS-Fuzz** has **no .NET support**, so the Scorecard-preferred managed-fuzzing path is unavailable to
  us. (This is also why #174 is framed as a _self-hosted_ weekly job.)
- **SharpFuzz** is the only mature coverage-guided fuzzer for .NET. It instruments the target IL and
  drives it under libFuzzer. **This is the engine we adopt**, and this project is built on it.
- **ClusterFuzzLite** is a CI _harness_ around libFuzzer that Scorecard recognises. It _can_ drive a
  SharpFuzz target, but only through a `.clusterfuzzlite/` Dockerfile + `build.sh` that reimplements the
  instrumentation build, plus its own workflow - a non-trivial, CI/supply-chain-touching addition that
  belongs in its own gated change, not this evaluation prototype.

**Decision:** adopt **SharpFuzz** as the engine now (this harness + seed corpus + the per-entry-point
targets). Run it from a **plain scheduled GitHub Actions Linux job** (#174) to start; treat wrapping it in
ClusterFuzzLite purely for the Scorecard badge as an optional, separately-gated follow-up. The security
value is the fuzzing itself, which the scheduled job delivers regardless of whether Scorecard credits it.

## Feasibility: local Windows vs CI Linux (honest)

- The **managed harness compiles cross-platform** - it builds cleanly on the maintainer's Windows box
  (validated in Debug and Release under `--warnaserror`), so it cannot silently bitrot when touched.
- **Actual fuzzing is Linux-only.** The `sharpfuzz` instrumentation CLI and the libFuzzer runtime are
  Linux-oriented; a coverage-guided run on Windows is impractical. So the _run_ lives in CI, never on the
  maintainer's machine. This is expected and is why #174 is a scheduled Linux job.
- The project is not in the solution, so nothing that works from the solution builds it. Since #1132 the
  gating `build` job compiles it by path on every PR, which is what keeps it from bitrotting; the weekly
  job is what keeps it _running_.

## Value assessment vs. the existing gate

The FsCheck property suite (`PropertyTests.cs`, #126) covers the **pure login-decision helpers**
(role→privilege mapping monotonicity, the OIDC "valid ⇒ username" invariant) - it does **not** touch the
**byte-level parse path**. The `SamlResponseParsingTests` already pin the known malformed-input classes
(non-Base64, malformed XML, prohibited DOCTYPE, null/empty, oversized, garbage certificate, malformed
signature element) as fail-closed. Fuzzing is **complementary**: it searches the same parse path for an
_un-enumerated_ crasher - an exception type or a hang the hand-written cases and the explicit
`catch` filters did not anticipate - which is precisely the residual risk unit and property tests cannot
exhaust. The marginal value is modest (the raw parsing is delegated to already-hardened platform/library
parsers - `System.Xml` with DTD prohibited, `Newtonsoft.Json`, `Microsoft.IdentityModel`), but real and
low-maintenance, and it is the surface #174 already committed to.

## The configuration that is fuzzed

The weekly job builds **Release with `-p:DefineConstants=DEBUG%3BTRACE`** (#1081), and that is the only
build in the repository which defines `DEBUG`. It matters because the post-conditions #1082 put on the
parse surface are `Debug.Assert`, which the compiler removes outside a `DEBUG` compile, so the plain
Release assembly the plugin ships carries none of them:

```sh
$ dotnet build SSO-Auth.Fuzz/SSO-Auth.Fuzz.csproj -c Release --warnaserror
$ tr -d '\000' < SSO-Auth.Fuzz/bin/Release/net9.0/SSO-Auth.dll | grep -ac "collapsed an absent NameID"
0
$ dotnet build SSO-Auth.Fuzz/SSO-Auth.Fuzz.csproj -c Release --warnaserror -p:DefineConstants=DEBUG%3BTRACE
$ tr -d '\000' < SSO-Auth.Fuzz/bin/Release/net9.0/SSO-Auth.dll | grep -ac "collapsed an absent NameID"
1
```

Three things about that spelling, none of them incidental.

It is a command-line property and not a line in a build file, because
`ParseSurfaceAssertions_NeverReachTheShippedBuild` refuses a `DefineConstants` in
`Directory.Build.props` or `SSO-Auth.csproj` outright, and keeping the constant out of both leaves that
refusal at full strength. Nothing that ships is built this way, and nothing that ships can inherit it: an
assertion left live in production auth code turns an input the login path is meant to reject into a
process abort.

`TRACE` is restated because the property replaces the default constant set instead of adding to it, and
Release defines `TRACE`. Without it the fuzzed build would differ from Release in a second, unrelated
way. `%3B` is MSBuild's escape for the separator, so the value survives whatever the shell would
otherwise do with a bare semicolon.

The configuration stays Release, so the assertions cost the fuzzer none of its optimized code:

```sh
$ dotnet msbuild SSO-Auth/SSO-Auth.csproj -p:Configuration=Release -p:DefineConstants=DEBUG%3BTRACE \
      -getProperty:DefineConstants -getProperty:Optimize
{ "Properties": { "DefineConstants": "DEBUG;TRACE", "Optimize": "true" } }
```

### An assertion failure is an ordinary crasher

A failed `Debug.Assert` prints its message and stack and terminates the process, so libFuzzer records
it the same way it records any other crash: a reproducer under `findings/<target>/`, archived by the
`sharpfuzz-crashers-<target>` artifact, and the "Report findings" step turns that leg red.

Triage is the same as for any other reproducer, and the rule against fixing it in the harness applies
unchanged: **do not delete or weaken the assertion to make the run green.** A failing post-condition
says the parser returned a shape the code around it already assumes it cannot return, so the reproducer
is minimised and filed, and the fix goes into the parser or into the post-condition's own statement of
the invariant, in a separate change.

## Running it (Linux)

```sh
# 1. Build the harness (Release, with the parse-surface assertions compiled in).
dotnet build SSO-Auth.Fuzz/SSO-Auth.Fuzz.csproj -c Release -p:DefineConstants=DEBUG%3BTRACE

# 2. Instrument the plugin assembly SharpFuzz will fuzz through.
dotnet tool install --global SharpFuzz.CommandLine
sharpfuzz SSO-Auth.Fuzz/bin/Release/net9.0/SSO-Auth.dll

# 3. Fuzz one target, seeded from its corpus (libFuzzer flags after --).
export SSO_FUZZ_TARGET=saml   # or: discovery | idtoken | jwks | roles
dotnet SSO-Auth.Fuzz/bin/Release/net9.0/SSO-Auth.Fuzz.dll \
    SSO-Auth.Fuzz/corpus/$SSO_FUZZ_TARGET -max_total_time=300
```

A non-zero exit with a written `crash-*` input is a finding. **Do not fix it in the harness.** Minimise
the reproducer, file it as its own security issue (GHSA path if it turns out to be exploitable rather than
a plain 500/DoS), and fix the parser in a separate change - the harness only surfaces findings.

### Smoke mode (any platform, no libFuzzer)

Because libFuzzer is Linux-only, set `SSO_FUZZ_SMOKE=1` to replay a corpus directory through the selected
target **once** and exit - no instrumentation, no native runtime. It proves the dispatch + parse wiring
runs and that every seed is handled fail-closed, so the harness can be validated on Windows and as a cheap
CI sanity check. This is how the prototype was validated at delivery, and how a new target is validated
before it lands: every target over its own corpus, exit 0. The count is not restated here because it
moved once already and the loop above derives it from the corpus directories.

```sh
export SSO_FUZZ_SMOKE=1 SSO_FUZZ_TARGET=saml   # or: discovery | idtoken | jwks | roles
dotnet SSO-Auth.Fuzz/bin/Release/net9.0/SSO-Auth.Fuzz.dll SSO-Auth.Fuzz/corpus/$SSO_FUZZ_TARGET
```

### Differential mode (any platform, no libFuzzer)

Both modes above only ever ask whether the target _survives_ an input. Neither can see a **wrong answer**,
and on the repeated-member walk that is the failure that matters: a walk quietly returning `Clean` for
every document never throws, so it passes libFuzzer and smoke alike while approving documents that mean
two things.

`SSO_FUZZ_DIFFERENTIAL=1` runs the walk that ships against a **second parser family** - Newtonsoft's
`JsonTextReader`, already in the dependency graph - over the committed corpus plus generated
discovery-shaped documents, and reports every case where the two answer differently about whether an
object scope names a member twice:

```sh
SSO_FUZZ_DIFFERENTIAL=1 SSO_FUZZ_CASES=50000 SSO_FUZZ_SEED=1188 \
    dotnet SSO-Auth.Fuzz/bin/Release/net9.0/SSO-Auth.Fuzz.dll SSO-Auth.Fuzz/corpus/discovery
```

Exit 0 is a clean, non-vacuous run; exit 1 is a divergence, which is a **finding** and is filed with the
document that produced it rather than patched inside the driver; exit 3 is a vacuous run - the two readers
never agreed in both directions, so a zero divergence count would have established nothing.

The generated documents are deliberately narrow: a seven-name member pool, two of whose entries spell an
earlier name with a `\u` escape, and a root that is an object nine times in ten. A wide pool spends the
run proving that documents without repeats have no repeats.

## The seed corpus

`corpus/<target>/` holds representative seeds so the fuzzer starts from meaningful coverage rather than
random noise: a well-formed and several malformed shapes per target (a minimal signed-shaped SAML
response, a DOCTYPE body, non-Base64; a full and a minimal discovery document plus a type-confused one; a
`none`-alg JWT and a non-JWT; a genuine two-key RSA key set). libFuzzer expands the corpus from these as
it explores.

One class is seeded deliberately rather than left to the mutator: a **repeated property name**, where a
document parses cleanly and the reader silently keeps one occurrence. The mutator is unlikely to invent
it, because it is not a malformation - `{"alg":"RS256","alg":"none"}` is well-formed JSON that reads back
as `none`, and which occurrence wins is a decision each reader makes without saying so. Three seeds carry
it (#1153): `discovery/repeated-issuer.json` repeats `issuer` beside a real
`code_challenge_methods_supported` array so the mutator has grammar on both sides of the repeat;
`idtoken/repeated-alg-header.jwt` repeats `alg` in the JWT header; `idtoken/repeated-aud-payload.jwt`
repeats `aud` in the payload, collapsing two audiences to one. `jwks/repeated-kid.json` (#1156) is the
same class on the key set: its second entry names `kid` twice, once as the first entry's name and once as
its own, so the set advertises two keys under one name until the last occurrence wins and it advertises
two under two. Measured against `jwks/two-rsa-keys.json`, both documents convert to the same two usable
keys under the same two ids, so the repeat leaves no trace downstream - which is the point. The seed is
grammar for the mutator, not a claim that the plugin misreads it.

`discovery/lone-surrogate-name.json` (#1188) is the other class the mutator will not invent: a member
name carrying an **unpaired surrogate escape**. Thirteen ASCII bytes that both parser families read
without complaint, and the input on which `System.Text.Json`'s `GetString` raises
`InvalidOperationException` rather than `JsonException` - so a walk catching only the latter takes the
throw on the anonymous discovery read. It is committed as a seed so the arm stays replayed by the smoke
gate rather than resting on a unit test alone.

`corpus/roles/` (#1158) carries the repeated-name class on the role claim, which is the one surface here
where a repeat could decide a privilege rather than a diagnostic. Every seed is the value of a
`resource_access` claim read under the path `resource_access.jellyfin.roles`, pinned in `Program.cs`
beside the driver so a seed and the path cannot drift apart: `array-terminal.json` and
`object-map-terminal.json` are the two terminal shapes the extractor supports,
`repeated-key-at-terminal.json` names `roles` twice in the object that holds it, and
`repeated-key-below-terminal.json` repeats a role name inside the object map one level below. What the
extractor should DO with a repeat is #1053's decision and is deliberately not encoded here; the target
asserts only that the walk terminates fail-closed or with an exception it maps.

## Scorecard alert #36 and #174

This prototype does not itself flip the Scorecard Fuzzing check - that check only credits a wired-in
ClusterFuzzLite/OSS-Fuzz integration, which we deliberately deferred above. So alert #36 is **re-dismissed
with this documented outcome**: SharpFuzz adopted as the engine, this harness + corpus landed, and the
recurring run tracked by #174 (weekly scheduled Linux job). Adopting ClusterFuzzLite later, if we want the
badge, is the remaining optional step.
