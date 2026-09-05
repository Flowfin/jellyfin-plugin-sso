# SSO-Auth.Bench: the OpenID login-latency harness

An in-process characterization of the OpenID login path: how long `OidChallenge` and `OidCallback`
take inside the plugin, serially and under concurrent callers. It is the measuring instrument for
[#1117](https://github.com/Flowfin/jellyfin-plugin-sso/issues/1117); capturing baseline numbers on a
controlled machine is a separate piece of work.

## Running it

```sh
dotnet run --project SSO-Auth.Bench -c Release
dotnet run --project SSO-Auth.Bench -c Release -- --iterations 2000 --warmup 200 --concurrency 16
```

| option           | default | meaning                                              |
| ---------------- | ------- | ---------------------------------------------------- |
| `--iterations`   | 500     | measured round-trips per scenario                    |
| `--warmup`       | 50      | round-trips each caller discards before measuring    |
| `--concurrency`  | 8       | callers driving the concurrent scenario at once      |
| `--link-import`  | off     | measure the account-link import instead (#1522)      |
| `--config-write` | off     | measure the configuration write and its undo (#1532) |

The project is **not** in `SSO-Auth.sln`, the same way `SSO-Auth.Fuzz` is not: `dotnet build`,
`dotnet test`, the coverage gate and the dependency scan all work from the solution and never
restore or build this. No CI job runs it either.

## The account-link import cost

`--link-import` measures a different subject, and is a separate run rather than a section of the
one above: how long ONE bulk administrative write holds the process-wide configuration lock, which
is the lock every login waits on. It drives the real `ImportLinks` through the same harness, at
100, 1000, 5000 and 10000 entries - the top of that range being roughly what the route's
one-mebibyte request-size limit admits. `--iterations` defaults to 20 here and `--warmup` to 3,
because a ten-thousand-entry import is not a thing to do five hundred times.

Two bounds it prints on every run. The harness persists through a mocked serializer, so the host's
own write to `SSO-Auth.xml` is outside the figures and every one of them is a floor; and the
username resolution happens outside the lock in `ImportLinks`, so it is real cost but not
lock-held time. The numbers taken with it live in
[docs/SERVER-MIGRATION.md](../docs/SERVER-MIGRATION.md), where an operator planning a migration
reads them.

## The configuration-write cost

`--config-write` measures the undo behind a configuration write against the write it is paid on
(#1532). Every write has taken a persisted-form snapshot of the whole configuration since #1521, so
a persist that throws can be rolled back out of the running server, and that snapshot is paid inside
the process-wide lock by writes on the LOGIN path as well as by an administrator saving a form. Two
rows per size: the snapshot alone, and the production `MutateConfiguration` with it. The no-snapshot
baseline is the difference, which is a reading of `ProviderConfigStore.Mutate` rather than an
estimate - it calls `Snapshot` once and nothing else reads the result - and there is deliberately no
switch in production that turns the undo off for a benchmark. The numbers and the decision they took
live at that method.

## What the two scenarios measure

**nominal**: one caller, serial challenge-then-callback round-trips. This is the latency a single
user waits through with nothing else happening.

**concurrent**: `--concurrency` callers running the same round-trip at once, each with its own
controller and its own HTTP context, reporting the same distribution plus the achieved
round-trips-per-second over the wall clock of the measured phase.

Both report p50/p95/p99 and max in milliseconds, by nearest rank, so every number printed is a
duration some iteration actually took. Percentiles rather than a mean, because the number that
matters on a login path is the tail.

Every round-trip is checked as it runs: the challenge must redirect to the IdP, and the callback
must answer with the signed-in page. A run whose logins started failing exits non-zero instead of
reporting the latency of a rejection.

## What it deliberately excludes

- **The network.** Discovery, JWKS and the token endpoint are served in-process from the test
  project's `OidcTokenFixture` through a stub HTTP handler. What is timed is the plugin's own work:
  state minting, PKCE, the token exchange's own parsing, and the id_token signature and claim
  validation. A real deployment adds the IdP round-trip on top.
- **Jellyfin.** The Jellyfin services are the same mocks the unit tests use, so session minting and
  user provisioning are not in these numbers. The measured legs stop at the callback; redeeming the
  state through `OidAuth` is not driven here.
- **The rate limiter.** `EnableRateLimit` is off in the default configuration, which is what the
  harness runs with, so nothing here is throttled and no number is a 429.
- **A pass/fail threshold.** This is a characterization. Latency is a property of the machine it
  was measured on, so there is no assertion to fail a build with, and it is wired into no check.

## Notes for anyone extending it

The harness reuses `SsoControllerHarness` and `OidcTokenFixture` from `SSO-Auth.Tests` through a
project reference and the `InternalsVisibleTo` in `SSO-Auth.Tests/AssemblyInfo.cs`, rather than
copying them, so it keeps measuring the login setup as it is now rather than as it was on the day a
copy was taken. The cost is that building this project builds the test project too.

That harness swaps the process-wide `SSOPlugin.Instance` in its constructor and clears the OpenID
state cache, which is why the test project confines harness-based classes to a non-parallel
collection. The bench works inside that: every caller is constructed before any of them runs, and
they are configured identically, so whichever construction won the swap describes them all. Adding
a scenario that needs a _differently_ configured provider means it cannot run concurrently with the
others.

In-flight authorize states are held until they expire or are redeemed, and the callback promotes a
state rather than consuming it, so a measured run leaves one state per round-trip behind. The
store's global cap is 100,000 entries, and a loopback client is exempt from the per-client share, so
an iteration count anywhere near that cap would start measuring the cap path instead of the login
path.
