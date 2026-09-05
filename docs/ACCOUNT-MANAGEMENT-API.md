# Account-management API

This page is for somebody building a provisioning tool against this plugin: an
invite flow like Wizarr or jfa-go, a request-manager side integration, or a
script that creates accounts in bulk. It covers one thing, how to create a
Jellyfin account that is SSO-linked from its first login, so that the capability
is discoverable without reading the controller source.

It does not cover the login, logout, provider-configuration or configuration
import/export endpoints. Those are driven by a browser or by an administrator on
the settings page, not by a provisioning tool. The one exception is the
account-link backup restore, which is here because it writes the same links every
other route on this page writes, and because a server migration is the other
occasion on which a caller holding only an administrator credential creates links
nobody signed in for. There is no generated OpenAPI document; this page is the
reference.

Everything below was read out of `SSO-Auth/Api/Http/SSOController.cs`, and out
of the `SSO-Auth/Config/` and `SSO-Auth/Api/Audit/` files it calls. Each claim
cites a file and a **name** inside it, a route template, a method, a constant,
or the literal string the plugin returns, so a reader can check the claim by
grepping for that name rather than trusting the sentence.

The names are cited instead of line numbers on purpose. This page carried line
numbers until #1424, and by then most of the ones pointing into the controller
and the audit file resolved to unrelated code: a citation that names the wrong
line is worse than none, because it teaches the reader to stop checking. A name
moves with the code it names; a number does not. So no number on this page is
meant to be exact, because there are none, and a citation that stops resolving
is a defect worth reporting.

## Base path and authentication

The controller is mounted at `/sso` under the Jellyfin server root
(`[Route("[controller]")]` on `SSOController`,
`SSO-Auth/Api/Http/SSOController.cs`). Route
matching is case-insensitive, so `/sso/Links/Roster` and `/SSO/links/roster`
reach the same endpoint.

Every endpoint on this page is elevation-gated with
`[Authorize(Policy = Policies.RequiresElevation)]` or, on the two per-user reads
and the unlink, with `[Authorize]` plus a caller check that lets a user act on
their own account and an administrator act on anybody's. There is no separate
credential for the plugin. A caller presents a Jellyfin administrator access
token, or an API key issued from the dashboard, in the header form Jellyfin
already uses:

```
Authorization: MediaBrowser Token="<token>"
```

An access token is minted the ordinary way, by posting to the server's
`/Users/AuthenticateByName`. That is a Jellyfin route rather than a plugin one,
and it is named here only because a provisioning tool needs it before it can call
anything else.

### What is rate-limited and what is not

The plugin's per-client limiter is opt-in and off unless an administrator turns
it on, and it keys on the connection's remote address only. Of the endpoints on
this page:

- the pre-provision write, the unlink and the link-backup restore share the
  `link` budget: `PreprovisionCanonicalLink`, `DeleteCanonicalLink` and
  `ImportLinks` each open with `RateLimitCheck(SsoRateLimitClass.Link)`
- the revoke has its own `unregister` budget: `Unregister`, with
  `RateLimitCheck(SsoRateLimitClass.Unregister)`
- the per-account link export has its own `export` budget: `ExportUserLinks`,
  with `RateLimitCheck(SsoRateLimitClass.Export)`
- the SSO-managed status read and the two per-user link listings are not
  rate-limited at all: `SsoManagedStatus`, `GetOidLinksByUser` and
  `GetSamlLinksByUser` contain no `RateLimitCheck` call

When the limiter refuses a request the response is `429` with a plain-text body
and a `Retry-After` header carrying whole seconds
(`LoginStatusMapper.ToActionResult`,
`SSO-Auth/Api/Session/LoginStatusMapper.cs`, the one place that header is set).
Treat that as the one status worth retrying. Nothing else on this page is safe
to retry blindly except the pre-provision write, which is idempotent for the
same mapping, and the link-backup restore, which refuses a repoint but
re-applies a mapping this instance already holds.

## The canonical name, and the mistake to avoid

Every link on both protocols is keyed on one string, called the canonical name in
the API. Writing the wrong value produces a link that looks correct in the roster
and never matches at login, and that is the single most likely integration error
on this surface.

For OpenID Connect the canonical name is the `sub` claim of the validated
`id_token`, and nothing else. A login whose `id_token` carries no `sub` is denied
rather than falling back to the username, because the username is mutable at the
identity provider (the `derived.Valid && string.IsNullOrWhiteSpace(derived.Subject)`
guard in `SSO-Auth/Api/Flows/OidcLoginService.cs`). So the
value to pre-provision is the identity provider's stable subject identifier, not
the email address, not the preferred username, and not whatever the provider's
admin console shows as a display name.

For SAML 2.0 the canonical name is the assertion's `NameID` (the
`samlResponse.GetNameID()` that becomes `providerUserId` in
`SSO-Auth/Api/Flows/SamlLoginService.cs`). If the identity provider is
configured to send a transient or unspecified `NameID` format, the value changes
between logins and no pre-provisioned link can survive. The identity provider has
to be configured for a persistent identifier before pre-provisioning means
anything.

Both values are opaque strings as far as the plugin is concerned. It does not
normalise case, trim, or canonicalise them beyond refusing an empty one.

## Pre-provision a link

```
POST /sso/Links/Preprovision/{mode}/{provider}/{jellyfinUserId}
Content-Type: application/json

"the-canonical-name"
```

`PreprovisionCanonicalLink`. `mode` is `oid` or `saml`, case-insensitive.
`provider` is the provider name as configured on the settings page.
`jellyfinUserId` is the GUID of an account that already exists. The body is a
bare JSON string, not an object.

This is the ordinary link write with the identity-provider round trip removed.
The self-service route redeems a live authorize state or a signed assertion, so
it structurally requires the person being linked to complete a flow at the
identity provider, which a tool holding only an administrator credential cannot
drive. This route writes the same link without that redemption, and differs in
exactly one behaviour, described under the conflict below.

Responses:

| Status | Meaning                                                                                                     |
| ------ | ----------------------------------------------------------------------------------------------------------- |
| 204    | The link was written, or the identical mapping already existed                                              |
| 400    | The canonical name was empty, `mode` is neither `oid` nor `saml`, or no provider of that name is configured |
| 404    | No Jellyfin account holds that user id                                                                      |
| 409    | That canonical name is already linked to a different Jellyfin account                                       |
| 429    | The `link` budget for this client is exhausted; see `Retry-After`                                           |

The 409 is the collision behaviour worth designing around. Repeating the same
mapping succeeds with 204, so a retry after a lost response is safe. Rebinding a
subject that is already linked elsewhere is refused and the stored link is left
exactly as it was: `CanonicalLinkService.TryCreateLink` returns
`CanonicalLinkWriteResult.ConflictingUser` from its `refuseRebind` guard without
touching the map, and `FlowResponses` renders that result as the 409. A tool
that wants to move a subject to another account has to delete the existing link
first, with the unlink below.

A provider that is configured but switched off reads as absent here, so the
response is the same `400` and the same "No matching provider found" body as a
provider name nobody has configured. Writing a link is a grant of future login
capability, and every grant path treats a disabled provider like a deleted one:
`TryCreateLink` calls `TryGetLinks` with `requireEnabled: true` and yields
`UnknownProvider` (`SSO-Auth/Api/Linking/CanonicalLinkService.cs`). Removal is
the opposite case and keeps working while a provider is disabled, because
disable-then-clean-up is the ordinary workflow: `TryRemoveLink` passes
`requireEnabled: false` to the same helper.

A `mode` that is neither `oid` nor `saml` is refused with `400` and the body
`The mode segment must be 'oid' or 'saml'.` The parse happens once at the
controller boundary and all three routes carrying a `{mode}` segment answer
identically (`RefuseUnknownMode`, returning the fixed `UnknownModeMessage`
constant; pinned across the three by
`EveryModeCarryingRoute_RefusesAnUnknownModeWithTheSameBody` in
`SSO-Auth.Tests/Http/SSOControllerLinkTests.cs`). The body is fixed text and
never repeats the token that was sent.

Until #1399 this input threw and the status was whatever the server's exception
middleware produced, which made it the one refusal on this surface a caller could
not depend on. It is decided here now.

A successful write is audited as a pre-provision, naming the administrator that
drove it (`SsoAudit.LinkPreprovisioned`, `SSO-Auth/Api/Audit/SsoAudit.cs`).

The link is written without the OpenID issuer binding, exactly like every other
administrator-made link. No `id_token` was redeemed here, so there is no issuer
to bind to, and the binding is taken on the identity's first real login instead.

## Read whether an account is SSO-managed

```
GET /sso/SSO-Managed/Status/{jellyfinUserId}
```

`SsoManagedStatus`. Returns `200` with two booleans, or `404` when no such
account exists.

```json
{ "PasswordLoginDisabled": true, "HasCanonicalLink": true }
```

The two facts are reported separately because they genuinely differ, and
collapsing them is the inference this endpoint exists to remove. An account can
hold a link while its authentication provider still routes password attempts to
the server's own provider, and an account can carry the SSO stamp with no link
left on it, having been unregistered, or provisioned and never linked. Only
`PasswordLoginDisabled` decides whether a password can be used, so that is the
one to read when deciding whether to show a password field or a reset link.

The `404` is deliberate rather than a report of two falses. "This account uses
passwords" and "this account does not exist" are different answers, and a caller
that cannot tell them apart would offer a password field for an account it is
about to fail to find.

## List the links an account holds

```
GET /sso/oid/links/{jellyfinUserId}
GET /sso/saml/links/{jellyfinUserId}
```

`GetOidLinksByUser` and `GetSamlLinksByUser`. One protocol each. Both return a
map of provider name to the list of canonical names linked to that account under
that provider, so an account with no links under a configured provider yields an
empty list rather than a missing key.

These two carry `[Authorize]` rather than the elevation policy, and the caller
check lets a user read their own links. An administrator reads anybody's.

## Export one account's links

```
GET /sso/Links/Export/{jellyfinUserId}
```

`ExportUserLinks`. Both protocols at once, in the same document shape the
whole-table export produces, or `404` when no such account exists. This is the
route to use when answering a data-subject access request for one person, since
it produces that subject's linkages without handing over everybody else's.

It carries its own rate-limit budget because it is the surface most likely to be
driven in a loop over the whole user list.

## Restore a link backup

```
POST /sso/Config/Links/Import
Content-Type: application/json

<the document GET /sso/Config/Links/Export produced>
```

`ImportLinks`. Restores an account-link backup onto this instance,
rebinding every link to the user id this server holds for that username today.
It is the half that completes a server migration: links are stored against
Jellyfin user ids, a rebuilt user database issues new ids, and only a
username-keyed document can be restored against it.

The document it accepts is exactly what `GET /sso/Config/Links/Export` returns
(`ExportLinks`). Post that file back unmodified; nothing has to be
rewritten between the two calls.

### The document shape

| Field                   | Meaning                                                                                                                            |
| ----------------------- | ---------------------------------------------------------------------------------------------------------------------------------- |
| `FormatVersion`         | The document format version, its own sequence (`LinkExportDocument.FormatVersion`). Version `1` today (`LinkExport.FormatVersion`) |
| `Links[]`               | One entry per canonical link, across every provider of both protocols (`LinkExportDocument.Links`)                                 |
| `Links[].Protocol`      | `OpenID` or `SAML` (`LinkExport.OpenIdProtocol` and `LinkExport.SamlProtocol`), matched case-insensitively on import               |
| `Links[].Provider`      | The provider name, matched exactly and ordinally                                                                                   |
| `Links[].CanonicalName` | The canonical name the link is keyed by, as described above                                                                        |
| `Links[].Username`      | The Jellyfin username the link resolves to; this is the field that makes the document portable                                     |
| `Links[].Issuer`        | The OpenID issuer this link is bound to, absent for SAML links and for OpenID links written before the binding existed             |

The two names are matched differently on purpose
(`LinkImport.TryResolveProvider`). The protocol is a two-value vocabulary the
plugin writes itself, so `openid` is accepted. The provider name is a key the
rest of the plugin looks up ordinally, so a case difference there names a
different provider and the entry is refused rather than restored onto a provider
no login would resolve.

```json
{
  "FormatVersion": 1,
  "Links": [
    {
      "Protocol": "OpenID",
      "Provider": "my-provider",
      "CanonicalName": "a1b2c3d4-0000-0000-0000-000000000000",
      "Username": "newcomer",
      "Issuer": "https://idp.example.invalid/realms/media"
    },
    {
      "Protocol": "SAML",
      "Provider": "my-saml-provider",
      "CanonicalName": "persistent-nameid-value",
      "Username": "someone-else",
      "Issuer": null
    }
  ]
}
```

### Nothing is written unless the whole document validates

Every entry is checked before a single link is written, and the first failure
rejects the whole document: `LinkImport.Resolve` collects every refusal and
throws before `LinkImport.Write` is reached, and `LinkImport.Apply` is what
`ImportLinks` hands to `MutateConfiguration`, which persists nothing when the
mutation throws and rolls the change back out of the running instance when the
write itself fails - a full disk, a read-only volume. So a rejected import
leaves the stored link table exactly as it was, and a running instance goes back
to what it had stored rather than carrying links that never reached the file.
The rollback reaches the running instance and not the file itself, whose write
is the plugin base class's and is not atomic (#1532). This is the property to know
before running it once: the instance either gets its complete link table back or
is left untouched, and there is no half-applied state that looks restored and is
not.

### What is refused, and why

Every refusal below produces `400` and restores nothing. The body names the
offending entries by their index in the document that was posted, up to ten of
them, followed by a count of the rest (`LinkImport.MaxReportedEntries`, and the
throw at the end of `LinkImport.Resolve`). It never echoes a canonical name:
that is the one field in the document identifying a real person at the identity
provider, so the index into the file the operator is holding is what locates the
entry instead (`LinkImport.Describe`).

Every row below except the first is a `Describe` call in `LinkImport.Resolve`,
and the middle column is the literal reason that call carries. That text is what
the `400` body repeats, so it is both the anchor to grep for and the string a
caller will actually read.

| What the document carries                                           | The reason in the body                                                                              | Why it is refused                                                                                                                         |
| ------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------- |
| A `FormatVersion` this plugin does not import                       | `Unsupported link export format version ...`, thrown by `LinkImport.Apply` before any entry is read | A shape it does not recognise is rejected rather than half-applied                                                                        |
| An empty entry                                                      | `the entry is empty`                                                                                | It names nothing to restore                                                                                                               |
| A protocol and provider pair this instance does not hold            | `no provider of that name is configured for that protocol on this instance`                         | The import never creates a provider, so there is no link map to write into                                                                |
| No canonical name                                                   | `the entry carries no canonical name, so it names no identity to restore`                           | It names no identity                                                                                                                      |
| No username                                                         | `the entry carries no username, so nothing can be resolved for it`                                  | Nothing can be resolved for it                                                                                                            |
| A username no account on this instance holds                        | `no Jellyfin account is named '<name>' on this instance`                                            | The import never creates a Jellyfin account, so a backup file cannot bring a new principal into existence                                 |
| Two entries mapping one identity to two accounts                    | `the document maps this identity to two different accounts`                                         | Otherwise the order of the document would silently decide which of the two won                                                            |
| A canonical name this instance already links to a different account | `this instance already links that identity to a different account; unlink it first`                 | The repoint refusal: a crafted backup file must not remap an identity-provider subject onto another account. Unlink first, then re-import |
| A link this instance already binds to a different issuer            | `this instance already binds that link to a different issuer; unlink it first`                      | A restore must not rewrite a security decision as a side effect. Unlink first                                                             |

### What succeeds, and is worth relying on

- Re-importing a mapping this instance already holds is not a repoint and
  succeeds: the repoint refusal in `LinkImport.Resolve` fires only when the held
  user id differs from the resolved one, so an import can be retried after a
  partial migration without unlinking anything first.
- A document with an empty `Links` list is applied and restores nothing rather
  than being refused (`LinkImport.Apply` resolves and writes it like any other).
  The answer then says `"Restored": 0`, which is what an operator who applied the
  wrong file reads without going to the server log for it.
- An entry carrying no `Issuer` overwrites no stored binding: the issuer check in
  `LinkImport.Resolve` is guarded on the entry's `Issuer` being non-blank, so a
  document taken before the binding existed restores against a bound link without
  relaxing it.
- An `Issuer` on a SAML entry is dropped rather than written, because that
  protocol has no issuer binding (the `link.Config is OidConfig` test in
  `LinkImport.Write`).

### What the answer carries

A success answers `200` with the count, per provider and in total
(`LinkImportResultDocument`). It used to answer `204 No Content`, which made a
restore that rebound every link and one that rebound none the same bytes on the
wire; the number existed only in the server log. That is how #1517 - an import
whose payload was silently dropped - stood from `4.3.0-beta.43` onward, and #1520
is the shape rather than the defect.

```json
{
  "Restored": 3,
  "Providers": [
    { "Protocol": "OpenID", "Provider": "my-provider", "Links": 2 },
    { "Protocol": "SAML", "Provider": "my-saml-provider", "Links": 1 }
  ]
}
```

`Restored` is the total and is the field to check against the backup that was
applied. It carries no canonical name, for the reason the refusal path does not:
that is the one field naming a real person at the identity provider.

### Responses

| Status | Meaning                                                                                                                                                  |
| ------ | -------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 200    | The document was applied; the body says how many links were rebound, in total and per provider, and `0` is a real answer                                 |
| 400    | The body bound to nothing: the host's model validation refuses it before the action runs, with a `ProblemDetails` this plugin neither chooses nor writes |
| 400    | The version is unsupported, or an entry is unrestorable; the body carries the refusal text above (the `catch (ArgumentException)` arm of `ImportLinks`)  |
| 429    | The `link` budget for this client is exhausted; see `Retry-After`                                                                                        |

The `400` for a body that did not bind is the host's and not this plugin's.
Measured against a running 10.11.11 with this plugin installed, `null`, an empty
body and `not json` each answered:

```
HTTP 400
{"type":"https://tools.ietf.org/html/rfc9110#section-15.5.1","title":"One or more validation errors occurred.","status":400,"errors":{"":["A non-empty request body is required."],"document":["The document field is required."]}}
```

This page quoted `The link import document is missing or is not valid JSON.` as
what such a caller reads. That sentence is real - it is the `document is null`
arm of `ImportLinks` - and no caller reaches it, because `[ApiController]` model
validation answers first. The arm stays as a backstop, since the plugin does not
own the pipeline that makes it unreachable, but it is not what anybody sees
(#1520).

The route carries a one-mebibyte request-size limit
(`[RequestSizeLimit(ConfigImportMaxBytes)]` on `ImportLinks`, where
`ConfigImportMaxBytes` is the controller's `1024 * 1024` constant). A larger
body is refused by the server before the action runs, so the plugin decides
neither the status nor the body in that case.

A successful import is audited with the same total and per-provider counts the
answer carries, and with no canonical name in the line (`SsoAudit.LinksImported`,
`SSO-Auth/Api/Audit/SsoAudit.cs`). The log is the durable copy; the answer is the
one an operator reads while they are still holding the file.

### The order this route belongs in

The refusal rules decide the order of a migration rather than a convention doing
it. The import resolves each username against the user database and refuses a
provider this instance does not hold, so the accounts have to exist under their
old usernames and the providers have to be configured before the import runs.
Restore the accounts first, configure the providers second, import the links
last.

## Remove one link

```
DELETE /sso/{mode}/Link/{provider}/{jellyfinUserId}/{canonicalName}
```

`DeleteCanonicalLink`. Removes exactly one mapping.

| Status | Meaning                                                                       |
| ------ | ----------------------------------------------------------------------------- |
| 200    | The link was removed                                                          |
| 400    | `mode` is neither `oid` nor `saml`, or no provider of that name is configured |
| 403    | The caller may not edit that user's links                                     |
| 404    | No link is registered for that canonical name                                 |
| 409    | The canonical name is registered, but to a different Jellyfin user id         |
| 429    | The `link` budget for this client is exhausted                                |

Removing a user's last link across both protocols also revokes their active
sessions, because a link removal only fails future logins closed and a token
minted earlier would otherwise stay valid until it expired (the `Result:
CanonicalLinkRemoveResult.Removed, UserRetainsAnyLink: false` guard in
`DeleteCanonicalLink`, which is what calls `RevokeUserTokens`). Removing a link
while the user still holds another one does not revoke, so unlinking one
provider does not log somebody out of a session they legitimately hold through
another.

## Revoke SSO for an account entirely

```
POST /sso/Unregister/{username}
Content-Type: application/json

"the-fallback-auth-provider-id"
```

`Unregister`. Note that this one is keyed on the username, not on the
user id, unlike everything else above. The body is a bare JSON string naming the
authentication provider the account is switched back to.

This removes the account's links on every provider of both protocols, persists
the provider switch, and revokes the account's active tokens. It is the heavy
option, and it is not the one to use for routine unlinking; use the DELETE above
for that.

Two things an integrator should know before offering this as a button.

A revoke is not durable against re-adoption. When the provider the person signs
in through has `AllowExistingAccountLink` enabled, a later SSO login can
re-adopt the same-named local account and the link comes back. With the
fail-closed default, where adoption is off, the revoke is durable (the
`AllowExistingAccountLink` note in `Unregister`).

A revoke of one's own account terminates one's own sessions too, including the
administrator session that issued the call.

## A worked example

Three calls, in order, creating an invite-born account that is linked before its
first login. The server address, the token, the provider name and the subject
below are all placeholders; substitute your own.

Create the Jellyfin account. This is a server route, not a plugin one:

```
curl -fsS -X POST "$SERVER/Users/New" \
  -H 'Content-Type: application/json' \
  -H "Authorization: MediaBrowser Token=\"$TOKEN\"" \
  -d '{"Name":"newcomer"}'
```

Take the `Id` from that response and pre-provision the link, using the identity
provider's stable subject for that person:

```
curl -fsS -X POST "$SERVER/sso/Links/Preprovision/oid/my-provider/$USER_ID" \
  -H 'Content-Type: application/json' \
  -H "Authorization: MediaBrowser Token=\"$TOKEN\"" \
  -d '"a1b2c3d4-0000-0000-0000-000000000000"'
```

A `204` means the link is in place. A `409` means that subject already belongs to
another account, and the tool should surface that rather than retrying.

Verify, and decide what the invite mail should say:

```
curl -fsS "$SERVER/sso/SSO-Managed/Status/$USER_ID" \
  -H "Authorization: MediaBrowser Token=\"$TOKEN\""
```

`HasCanonicalLink` is now true. `PasswordLoginDisabled` reflects whether the
account is stamped as SSO-managed, which pre-provisioning alone does not change,
so an account created this way can still hold a password until an administrator
turns SSO-only login on, or until the account is provisioned through an SSO
login.

## What this page does not settle

The account this example creates gets whatever policy the server gives a new
user. Seeding a policy at creation time is the provisioning template's job and is
configured on the settings page, not through this API.
