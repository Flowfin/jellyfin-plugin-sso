# Server migration and rebuild

This page is for an operator moving this plugin's state from one Jellyfin
server to another, or rebuilding the same server from scratch. It covers the
order the steps have to run in, what each of the two backup files carries, and
what is deliberately not restored at all.

It is the operator counterpart to
[Account-management API](ACCOUNT-MANAGEMENT-API.md), which is written for
somebody calling the endpoints from a tool. The refusal rules of the link
restore live on that page and are not repeated here; this page carries the
order and the omissions, and links there for everything else.

Each claim below cites a file and a **name** inside it, a route template, a
method, a constant, or the literal string the plugin returns, so a reader can
check the claim by grepping for that name rather than trusting the sentence.

The names are cited instead of line numbers on purpose, which is the answer
[Account-management API](ACCOUNT-MANAGEMENT-API.md) took on #1424 and this page
takes on #1429. This page carried line numbers for one day after it landed, and
four of them already pointed at unrelated code: a citation that names the wrong
line is worse than none, because it teaches the reader to stop checking. A name
moves with the code it names; a number does not. So there is no number on this
page meant to be exact, because there are none, and a citation that stops
resolving is a defect worth reporting.

**Walked end to end, and the walk changed the plugin.** The procedure below was
followed against a scratch server rebuild - a fresh Jellyfin 10.11.11 on an empty
configuration directory, the accounts recreated, both files imported - and every
refusal quoted on this page was read back from that run rather than from the
source. It is tested rather than derived, and #1135 records the run.

**It did not pass the first time, and step 4 does not work on any build published
so far.** On every beta from `4.3.0-beta.43` to `4.3.0-beta.61` the link import
answers 204 and restores nothing: the posted document reaches the importer with
its entries dropped, so the step that completes a migration is a no-op that
reports completion, and none of the refusals below is reachable at all. A server
migrated on one of those builds has an empty link table and was never told. That
is #1517, whose fix landed on the 4.4 line in #1523 and is not yet in any
published build; when a release carrying it is out, running step 4 again with
the same file restores the links.

## The two files, and why there are two

A migration needs two downloads, not one, and neither is a substitute for the
other.

| File          | Endpoint                                                                          | What it is                                                                    |
| ------------- | --------------------------------------------------------------------------------- | ----------------------------------------------------------------------------- |
| Configuration | `GET /sso/Config/Export` (`ExportConfig` in `SSO-Auth/Api/Http/SSOController.cs`) | Every provider's settings, redacted: no secret and no link map                |
| Account links | `GET /sso/Config/Links/Export` (`ExportLinks`, same file)                         | One entry per account link, keyed by Jellyfin username rather than by user id |

Both are also reachable from the plugin's settings page, from the two blocks of
the transfer section in `SSO-Auth/Web/configPage.html`: the
`Export / Import Configuration` block inside the `sso-config-transfer` form for
the configuration pair, and the `Export / Import Account Links` block
(`config.link_transfer_title`) for the account-link pair.

The split is deliberate. The configuration export drops the canonical-link maps
under `[JsonIgnore]` - the attribute sits on `CanonicalLinks` and on
`CanonicalLinkIssuers` in `SSO-Auth/Config/PluginConfiguration.cs` - and is
documented as carrying no link map, so an administrator has to ask for the link
document separately rather than receiving identity data as a side effect of
exporting provider settings (`SSO-Auth/Config/LinkExportDocument.cs`, the
remarks on the class).

**The link file is personal data.** It pairs Jellyfin usernames with the
identity provider's subject identifier for each of them. It is not redacted, it
cannot be, and it should be stored and transported the way any other file naming
your users is. It is also not the per-subject export a single user would ask
for; the per-account read is `GET /sso/Links/Export/{jellyfinUserId}`
(`ExportUserLinks`), described under
[Export one account's links](ACCOUNT-MANAGEMENT-API.md#export-one-accounts-links).

## The order

Each step depends on state the one before it puts in place, and the refusal
rules of the link restore decide that order rather than a convention doing it.

1. **Bring the Jellyfin accounts back under the same usernames.** The link
   import resolves each entry's username against the user database and refuses
   the whole document when an account it names does not exist, as
   `no Jellyfin account is named ... on this instance` from
   `LinkImport.Resolve` (`SSO-Auth/Config/LinkImport.cs`). It never creates an
   account, so a backup file cannot bring a principal into existence.
2. **Import the configuration export** (`POST /sso/Config/Import`,
   `ImportConfig`). This is a merge, not a replace: a provider that exists only
   on the target is left alone, and a provider new to the target is added with
   an empty link map and a blank secret (`ConfigImport.MergeProviders`,
   `SSO-Auth/Config/ConfigImport.cs`).
3. **Re-enter every provider secret and save.** The export carries none, so a
   provider that arrived from it has a blank one and fails its logins closed
   until an administrator supplies it. On a provider the target already held, a
   blank incoming secret keeps the stored one rather than wiping it
   (`ServerManagedFields.Preserve`, called from `ConfigImport.MergeProviders`
   and stated in the summary on `ConfigImport`).
4. **Import the account links last** (`POST /sso/Config/Links/Import`,
   `ImportLinks`). The import refuses a protocol and provider pair this instance
   does not hold, as
   `no provider of that name is configured for that protocol on this instance`
   from `LinkImport.TryResolveProvider`, which is why it cannot run before
   step 2.

No step half-applies. Both imports resolve the whole document before they write
anything, and a single unrestorable entry throws with every refusal collected:
`LinkImport.Resolve` fills a `refusals` list and throws
`The link import was rejected and nothing was restored.` before
`LinkImport.Write` runs, and `ConfigImport.Apply` puts the whole incoming set
through `ProviderConfigValidator.Validate` before it reaches `MergeProviders`.
The controller runs each inside `MutateConfiguration`, which persists nothing
when the mutation throws - the remarks on `ImportConfig` and `ImportLinks` say
so - so a step run too early leaves the instance exactly as it was and is simply
re-run once the step before it is done.

The other failure is the write, and it is covered as far as this plugin
reaches. A valid import whose persist fails - a full disk, a read-only volume,
which is exactly what a freshly built target can hit - used to leave the
running instance carrying the whole import while nothing reached the XML, so
logins behaved as though it had succeeded until the next restart.
`MutateConfiguration` now rolls the change back out of the live configuration
before the `500` reaches you, so the running instance goes back to the stored
state. Retry the import once the disk or the mount is fixed.

**What that does not promise, stated rather than implied.** The write itself is
the Jellyfin plugin base class's, and it serializes straight over
`SSO-Auth.xml` with no temporary file and no rename, so a disk that fills
mid-write leaves a truncated file. The rollback puts the running instance back
on what was stored; it cannot repair the file. A truncated `SSO-Auth.xml` does
not load on the next start, and the base class replaces an unloadable one with
an empty configuration - so **take a copy of `SSO-Auth.xml` before a migration
step, and check it after a failed one, before restarting the server.** #1532
holds the change that would make the write itself atomic.

Re-running the link import after a partial migration is safe: re-importing a
mapping this instance already holds is not a repoint and succeeds, because the
refusal in `LinkImport.Resolve` fires only when the stored link resolves to a
different account.

## What is deliberately never restored

Each of these survives neither file, and each omission is a decision with a
reason rather than a gap.

| Not restored                                                                            | Where the decision is                                                 | Why                                                                                                                                                         |
| --------------------------------------------------------------------------------------- | --------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Provider secrets and SAML signing keys                                                  | `ConfigExport.cs`, the summary on the class                           | Withheld at the JSON boundary by `WriteOnlySecretConverter`, so the document carries no plaintext secret and no `ssoenc:` envelope                          |
| The at-rest data key `sso-secret.key`                                                   | `SSOPlugin`, where the `SecretStore` over `sso-secret.key` is built   | It lives in its own file beside the configuration and is never part of the configuration object at all                                                      |
| Rate-limit tuning (`EnableRateLimit`, `RateLimitMaxAttempts`, `RateLimitWindowSeconds`) | `ConfigImport.Apply`, the comment on the `MergeProviders` step        | Instance-local operational tuning, and a scalar has no blank-means-keep signal, so importing it would let a partial document silently disable a DoS control |
| The SSO-only globals (`DisablePasswordLogin`, `BreakGlassAdminUsername`)                | `ConfigImport.Apply`, the `SsoOnlyLoginGuard.AssertCanActivate` guard | Validated fail-closed on import but never applied; the mode is turned on through its own elevated, audited endpoints, which also run the per-user sweep     |
| `SsoOnlyRepointedUserIds`                                                               | `PluginConfiguration.SsoOnlyRepointedUserIds`                         | Bookkeeping about accounts this instance took a password door away from; it describes this user database, not the next one                                  |
| `LogoutSessions`                                                                        | `PluginConfiguration.LogoutSessions`                                  | Per-session single-logout state written at login and removed at logout; nothing on a rebuilt server has a session to log out                                |
| `CanonicalLinkDeadlines`                                                                | `PluginConfiguration.CanonicalLinkDeadlines`                          | The role-mapped access deadlines are not fields of the link backup document (`LinkExportDocument.cs`), so a time-limited link comes back without its expiry |
| `CanonicalLinkLastLogins`                                                               | `LinkExport.Build`, the comment on the entry it writes                | A login instant is an observation, not restorable state: writing it back would assert a login that never happened on the new server                         |
| A provider's `NewPath`                                                                  | `ConfigImport.MergeProviders`                                         | Runtime state recording which redirect-path spelling the last challenge used; meaningless across instances, so the target keeps its own                     |

Two of those are worth planning around rather than only knowing about.
**Re-enter the secrets** as step 3, or every provider that arrived from the file
fails closed. And **a link that carried an access deadline comes back without
one**, so a deployment using role-mapped access durations has to check those
accounts after the restore instead of assuming the expiry travelled.

One thing is dropped at export rather than at import: a link pointing at a
Jellyfin account that no longer exists is left out of the document entirely -
`LinkExport.Build` skips a row whose user id resolves to no username - so a
dangling link does not travel and the restore cannot differ from the file it
claims to apply.

## The failure modes an operator actually hits

All three produce `400`, restore nothing, and name the offending entries by
their index in the file that was posted rather than by canonical name. The full
refusal table, with a code line beside each row, is
[What is refused, and why](ACCOUNT-MANAGEMENT-API.md#what-is-refused-and-why);
these are the three a migration runs into.

- **A renamed user.** The entry names a username no account on this instance
  holds: `no Jellyfin account is named ... on this instance`. Rename the account
  back, or change that entry's `Username` field to the new name before
  importing. The canonical name is the identity; the username is only how the
  document finds the account.
- **A provider missing on the target.** The entry names a protocol and provider
  pair this instance does not hold:
  `no provider of that name is configured for that protocol on this instance`.
  Either step 2 was skipped, or the provider's name differs: provider names are
  matched exactly and ordinally, while the protocol is matched
  case-insensitively (`LinkImport.TryResolveProvider` and
  `LinkImport.TryGetConfig`).
- **An existing conflicting link.** This instance already links that canonical
  name to a different account -
  `this instance already links that identity to a different account; unlink it first` -
  or already binds that link to a different OpenID issuer -
  `this instance already binds that link to a different issuer; unlink it first`.
  Both refusals exist so a backup file cannot silently remap an
  identity-provider subject onto another account. Unlink the existing link
  first, then re-import.

An import that succeeds ANSWERS with the total and the per-provider counts, and
audits the same numbers with no canonical name in the line
(`SsoAudit.LinksImported`). Read the `Restored` field in the answer against the
number of entries in the file you applied: that comparison is the check on this
step, and until #1520 it could only be made in the server log, because the
endpoint answered `204` whatever the number was.

## How long the link import holds the server

The import resolves every username BEFORE it takes the configuration lock, and
then does the writes and the persist inside it. That lock is the one every login
waits on, so on a server with many thousands of linked accounts the question is
how long one import stops logins, and nothing said (#1522).

Nothing bounds the number of entries a document may carry except the
one-mebibyte request-size limit on the route, and a minimal entry is small, so
about ten thousand of them fit in one body. That is the ceiling, and it is what
the top row below measures.

Measured 2026-09-05, Release `net9.0` on .NET 10.0.11 x64, forty measured
imports per size with five discarded, one OpenID provider, every entry carrying
an issuer stamp so both maps are written:

```
dotnet run --project SSO-Auth.Bench -c Release -- --link-import --iterations 40 --warmup 5

scenario   stage            n    p50 ms    p95 ms    p99 ms    max ms
import     100 entries     40     0.835     0.943     2.883     2.883
import     1000 entries     40     3.852     6.683    29.502    29.502
import     5000 entries     40    15.481    22.199    22.652    22.652
import     10000 entries    40    43.901    76.230   100.581   100.581
```

**So a restore at the ceiling this route admits holds the lock for tens of
milliseconds, not seconds.** The cost is close to linear in the number of
entries. There is no entry cap on the route and this is why: a cap set where it
would bite would refuse a large real migration, which is the only shape that
reaches these sizes, and a cap set above the request-size limit would refuse
nothing.

**Two bounds on those numbers, and both make them a floor rather than a total.**
The harness persists through a mocked serializer, so the host's own write to
`SSO-Auth.xml` is not in them - which on a table this size is tens of
milliseconds again (#1532 measures the serialization alone at 33.6 ms for five
thousand links). And it runs on whatever box you run it on; the figures above
are one developer machine, not a claim about yours.

**A trap met while measuring this, because the next person will meet it too.**
The first run of this harness read 1871 ms at p50 for ten thousand entries -
forty times the number above - and the cost was the harness. Configuring the
mocked user manager with one return per username makes it match every call
against a list that grows with the size, so the instrument was quadratic and the
endpoint was not. One configured call answering every username removed it.

## Rolling back

A refused import leaves nothing to undo. Both resolve the whole document before
they write, and the walk confirmed it in both directions: after each of the four
refusals the target's own link export was identical to what it held before.

After a SUCCESSFUL one there is less of a way back than this page used to claim,
and the difference matters most on the mistake an operator actually makes -
importing the wrong file. Re-importing the correct one does not undo it. The link
import only adds and overwrites, never removes, so the wrong file's entries stay;
the correct document then hits `this instance already links that identity to a
different account; unlink it first`, and because the refusal is whole-document,
one leftover entry blocks the restore of every other link. Unlinking is one call
per canonical name and the refusal names at most ten entries at a time, by index.
There is no replace mode and no bulk unlink. #1519 holds that gap.

Re-importing the same file onto the state it produced IS safe, and the walk shows
it: a second run of a successful import succeeds and changes nothing, because a
mapping this instance already holds is not a repoint.
