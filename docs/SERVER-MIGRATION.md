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

**Not walked end to end yet.** Everything below is read out of the source files
cited beside each claim, at the commit this page landed on. The procedure has
not been followed against a scratch server rebuild, and the failure messages are
quoted from the code rather than from a run. Issue #1135 stays open for exactly
that, and until it is closed this page is derived rather than tested.

## The two files, and why there are two

A migration needs two downloads, not one, and neither is a substitute for the
other.

| File          | Endpoint                                                            | What it is                                                                   |
| ------------- | ------------------------------------------------------------------- | ---------------------------------------------------------------------------- |
| Configuration | `GET /sso/Config/Export` (`SSO-Auth/Api/Http/SSOController.cs:1396`) | Every provider's settings, redacted: no secret and no link map               |
| Account links | `GET /sso/Config/Links/Export` (`SSOController.cs:1470`)            | One entry per account link, keyed by Jellyfin username rather than by user id |

Both are also reachable from the plugin's settings page, from the two blocks of
the transfer section (`SSO-Auth/Web/configPage.html:185` for the configuration
pair, `:239` for the account-link pair).

The split is deliberate. The configuration export drops the canonical-link maps
under `[JsonIgnore]` (`SSO-Auth/Config/PluginConfiguration.cs:526`, `:747`) and
is documented as carrying no link map, so an administrator has to ask for the
link document separately rather than receiving identity data as a side effect of
exporting provider settings (`SSO-Auth/Config/LinkExportDocument.cs`, the
remarks on the class).

**The link file is personal data.** It pairs Jellyfin usernames with the
identity provider's subject identifier for each of them. It is not redacted, it
cannot be, and it should be stored and transported the way any other file naming
your users is. It is also not the per-subject export a single user would ask
for; the per-account read is `GET /sso/Links/Export/{jellyfinUserId}`
(`SSOController.cs:1523`), described under
[Export one account's links](ACCOUNT-MANAGEMENT-API.md#export-one-accounts-links).

## The order

Each step depends on state the one before it puts in place, and the refusal
rules of the link restore decide that order rather than a convention doing it.

1. **Bring the Jellyfin accounts back under the same usernames.** The link
   import resolves each entry's username against the user database and refuses
   the whole document when an account it names does not exist
   (`SSO-Auth/Config/LinkImport.cs:132`). It never creates an account, so a
   backup file cannot bring a principal into existence.
2. **Import the configuration export** (`POST /sso/Config/Import`,
   `SSOController.cs:1560`). This is a merge, not a replace: a provider that
   exists only on the target is left alone, and a provider new to the target is
   added with an empty link map and a blank secret
   (`SSO-Auth/Config/ConfigImport.cs:98`).
3. **Re-enter every provider secret and save.** The export carries none, so a
   provider that arrived from it has a blank one and fails its logins closed
   until an administrator supplies it. On a provider the target already held, a
   blank incoming secret keeps the stored one rather than wiping it
   (`ConfigImport.cs:18`).
4. **Import the account links last** (`POST /sso/Config/Links/Import`,
   `SSOController.cs:1674`). The import refuses a protocol and provider pair
   this instance does not hold (`LinkImport.cs:111`), which is why it cannot run
   before step 2.

No step half-applies. Both imports resolve the whole document before they write
anything, and a single unrestorable entry throws with every refusal collected
(`LinkImport.cs:83-84` and `:174-182`; `ConfigImport.cs:80` and `:91-92`). The
controller runs each inside `MutateConfiguration`, which persists nothing when
the mutation throws (`SSOController.cs:1596`, `:1714`), so a step run too early
leaves the instance exactly as it was and is simply re-run once the step before
it is done.

Re-running the link import after a partial migration is safe: re-importing a
mapping this instance already holds is not a repoint and succeeds
(`LinkImport.cs:147`).

## What is deliberately never restored

Each of these survives neither file, and each omission is a decision with a
reason rather than a gap.

| Not restored                                                                            | Where the decision is                       | Why                                                                                                                                                       |
| --------------------------------------------------------------------------------------- | ------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Provider secrets and SAML signing keys                                                  | `ConfigExport.cs`, the summary on the class | Withheld at the JSON boundary by `WriteOnlySecretConverter`, so the document carries no plaintext secret and no `ssoenc:` envelope                         |
| The at-rest data key `sso-secret.key`                                                   | `SSO-Auth/SSOPlugin.cs:66`                  | It lives in its own file beside the configuration and is never part of the configuration object at all                                                     |
| Rate-limit tuning (`EnableRateLimit`, `RateLimitMaxAttempts`, `RateLimitWindowSeconds`) | `ConfigImport.cs:85-90`                     | Instance-local operational tuning, and a scalar has no blank-means-keep signal, so importing it would let a partial document silently disable a DoS control |
| The SSO-only globals (`DisablePasswordLogin`, `BreakGlassAdminUsername`)                | `ConfigImport.cs:63-73`                     | Validated fail-closed on import but never applied; the mode is turned on through its own elevated, audited endpoints, which also run the per-user sweep    |
| `SsoOnlyRepointedUserIds`                                                               | `PluginConfiguration.cs:127`                | Bookkeeping about accounts this instance took a password door away from; it describes this user database, not the next one                                 |
| `LogoutSessions`                                                                        | `PluginConfiguration.cs:147`                | Per-session single-logout state written at login and removed at logout; nothing on a rebuilt server has a session to log out                               |
| `CanonicalLinkDeadlines`                                                                | `PluginConfiguration.cs:557`                | The role-mapped access deadlines are not fields of the link backup document (`LinkExportDocument.cs`), so a time-limited link comes back without its expiry |
| `CanonicalLinkLastLogins`                                                               | `SSO-Auth/Config/LinkExport.cs:111-116`     | A login instant is an observation, not restorable state: writing it back would assert a login that never happened on the new server                        |
| A provider's `NewPath`                                                                  | `ConfigImport.cs:131`                       | Runtime state recording which redirect-path spelling the last challenge used; meaningless across instances, so the target keeps its own                    |

Two of those are worth planning around rather than only knowing about.
**Re-enter the secrets** as step 3, or every provider that arrived from the file
fails closed. And **a link that carried an access deadline comes back without
one**, so a deployment using role-mapped access durations has to check those
accounts after the restore instead of assuming the expiry travelled.

One thing is dropped at export rather than at import: a link pointing at a
Jellyfin account that no longer exists is left out of the document entirely
(`LinkExport.cs:103-109`), so a dangling link does not travel and the restore
cannot differ from the file it claims to apply.

## The failure modes an operator actually hits

All three produce `400`, restore nothing, and name the offending entries by
their index in the file that was posted rather than by canonical name. The full
refusal table, with a code line beside each row, is
[What is refused, and why](ACCOUNT-MANAGEMENT-API.md#what-is-refused-and-why);
these are the three a migration runs into.

- **A renamed user.** The entry names a username no account on this instance
  holds (`LinkImport.cs:132`). Rename the account back, or change that entry's
  `Username` field to the new name before importing. The canonical name is the
  identity; the username is only how the document finds the account.
- **A provider missing on the target.** The entry names a protocol and provider
  pair this instance does not hold (`LinkImport.cs:111`). Either step 2 was
  skipped, or the provider's name differs: provider names are matched exactly
  and ordinally, while the protocol is matched case-insensitively
  (`LinkImport.cs:212-245`).
- **An existing conflicting link.** This instance already links that canonical
  name to a different account (`LinkImport.cs:149`), or already binds that link
  to a different OpenID issuer (`:166`). Both refusals exist so a backup file
  cannot silently remap an identity-provider subject onto another account.
  Unlink the existing link first, then re-import.

An import that succeeds is audited with the total and the per-provider counts,
and with no canonical name in the line
(`SSO-Auth/Api/Audit/SsoAudit.cs:306`). Those counts are what say whether what
came back matches the file that was applied.

## Rolling back

Both imports are atomic, so a refused one leaves nothing to undo. After a
successful one, the way back is the pair of files taken from the old server:
re-importing them reproduces the same state, because neither import writes
anything the documents do not name.
