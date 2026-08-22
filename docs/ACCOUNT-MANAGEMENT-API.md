# Account-management API

This page is for somebody building a provisioning tool against this plugin: an
invite flow like Wizarr or jfa-go, a request-manager side integration, or a
script that creates accounts in bulk. It covers one thing, how to create a
Jellyfin account that is SSO-linked from its first login, so that the capability
is discoverable without reading the controller source.

It does not cover the login, logout, provider-configuration or config
import/export endpoints. Those are driven by a browser or by an administrator on
the settings page, not by a provisioning tool. There is no generated OpenAPI
document; this page is the reference.

Everything below was read out of `SSO-Auth/Api/Http/SSOController.cs` at the
commit this page landed on, and the line numbers are cited so a reader can check
a claim rather than trust it.

## Base path and authentication

The controller is mounted at `/sso` under the Jellyfin server root
(`[Route("[controller]")]`, `SSO-Auth/Api/Http/SSOController.cs:46`). Route
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

- the pre-provision write and the unlink share the `link` budget
  (`SSOController.cs:1722`, `:1890`)
- the revoke has its own `unregister` budget (`SSOController.cs:1574`)
- the per-account link export has its own `export` budget
  (`SSOController.cs:1427`)
- the SSO-managed status read and the two per-user link listings are not
  rate-limited at all (`SSOController.cs:1659`, `:1938`, `:1956`)

When the limiter refuses a request the response is `429` with a plain-text body
and a `Retry-After` header carrying whole seconds
(`SSO-Auth/Api/Session/LoginStatusMapper.cs:113`). Treat that as the one status
worth retrying. Nothing else on this page is safe to retry blindly except the
pre-provision write, which is idempotent for the same mapping.

## The canonical name, and the mistake to avoid

Every link on both protocols is keyed on one string, called the canonical name in
the API. Writing the wrong value produces a link that looks correct in the roster
and never matches at login, and that is the single most likely integration error
on this surface.

For OpenID Connect the canonical name is the `sub` claim of the validated
`id_token`, and nothing else. A login whose `id_token` carries no `sub` is denied
rather than falling back to the username, because the username is mutable at the
identity provider (`SSO-Auth/Api/Flows/OidcLoginService.cs:407-419`). So the
value to pre-provision is the identity provider's stable subject identifier, not
the email address, not the preferred username, and not whatever the provider's
admin console shows as a display name.

For SAML 2.0 the canonical name is the assertion's `NameID`
(`SSO-Auth/Api/Flows/SamlLoginService.cs:766`). If the identity provider is
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

`SSOController.cs:1714`. `mode` is `oid` or `saml`, case-insensitive. `provider`
is the provider name as configured on the settings page. `jellyfinUserId` is the
GUID of an account that already exists. The body is a bare JSON string, not an
object.

This is the ordinary link write with the identity-provider round trip removed.
The self-service route redeems a live authorize state or a signed assertion, so
it structurally requires the person being linked to complete a flow at the
identity provider, which a tool holding only an administrator credential cannot
drive. This route writes the same link without that redemption, and differs in
exactly one behaviour, described under the conflict below.

Responses:

| Status | Meaning                                                                 |
| ------ | ----------------------------------------------------------------------- |
| 204    | The link was written, or the identical mapping already existed          |
| 400    | The canonical name was empty, or no provider of that name is configured |
| 404    | No Jellyfin account holds that user id                                  |
| 409    | That canonical name is already linked to a different Jellyfin account   |
| 429    | The `link` budget for this client is exhausted; see `Retry-After`       |

The 409 is the collision behaviour worth designing around. Repeating the same
mapping succeeds with 204, so a retry after a lost response is safe. Rebinding a
subject that is already linked elsewhere is refused and the stored link is left
exactly as it was (`SSO-Auth/Api/Shared/FlowResponses.cs:97`,
`SSO-Auth/Api/Linking/CanonicalLinkService.cs:1185-1190`). A tool that wants to move a
subject to another account has to delete the existing link first, with the unlink
below.

A provider that is configured but switched off reads as absent here, so the
response is the same `400` and the same "No matching provider found" body as a
provider name nobody has configured. Writing a link is a grant of future login
capability, and every grant path treats a disabled provider like a deleted one
(`SSO-Auth/Api/Linking/CanonicalLinkService.cs:1180`,
`:1527-1530`). Removal is the opposite case and keeps working while a provider is
disabled, because disable-then-clean-up is the ordinary workflow
(`CanonicalLinkService.cs:1225-1228`).

A `mode` that is neither `oid` nor `saml` throws at the parse boundary
(`SSOController.cs:2022`, pinned by
`SSO-Auth.Tests/Http/SSOControllerLinkTests.cs:91`). What status the caller then
sees is decided by the server's exception middleware rather than by this plugin,
so do not depend on a particular one; send a valid mode.

A successful write is audited as a pre-provision, naming the administrator that
drove it (`SSO-Auth/Api/Audit/SsoAudit.cs:257`).

The link is written without the OpenID issuer binding, exactly like every other
administrator-made link. No `id_token` was redeemed here, so there is no issuer
to bind to, and the binding is taken on the identity's first real login instead.

## Read whether an account is SSO-managed

```
GET /sso/SSO-Managed/Status/{jellyfinUserId}
```

`SSOController.cs:1657`. Returns `200` with two booleans, or `404` when no such
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

`SSOController.cs:1954` and `:1936`. One protocol each. Both return a map of
provider name to the list of canonical names linked to that account under that
provider, so an account with no links under a configured provider yields an empty
list rather than a missing key.

These two carry `[Authorize]` rather than the elevation policy, and the caller
check lets a user read their own links. An administrator reads anybody's.

## Export one account's links

```
GET /sso/Links/Export/{jellyfinUserId}
```

`SSOController.cs:1420`. Both protocols at once, in the same document shape the
whole-table export produces, or `404` when no such account exists. This is the
route to use when answering a data-subject access request for one person, since
it produces that subject's linkages without handing over everybody else's.

It carries its own rate-limit budget because it is the surface most likely to be
driven in a loop over the whole user list.

## Remove one link

```
DELETE /sso/{mode}/Link/{provider}/{jellyfinUserId}/{canonicalName}
```

`SSOController.cs:1877`. Removes exactly one mapping.

| Status | Meaning                                                               |
| ------ | --------------------------------------------------------------------- |
| 200    | The link was removed                                                  |
| 400    | No provider of that name is configured                                |
| 403    | The caller may not edit that user's links                             |
| 404    | No link is registered for that canonical name                         |
| 409    | The canonical name is registered, but to a different Jellyfin user id |
| 429    | The `link` budget for this client is exhausted                        |

Removing a user's last link across both protocols also revokes their active
sessions, because a link removal only fails future logins closed and a token
minted earlier would otherwise stay valid until it expired
(`SSOController.cs:1911`). Removing a link while the user still holds another one
does not revoke, so unlinking one provider does not log somebody out of a session
they legitimately hold through another.

## Revoke SSO for an account entirely

```
POST /sso/Unregister/{username}
Content-Type: application/json

"the-fallback-auth-provider-id"
```

`SSOController.cs:1564`. Note that this one is keyed on the username, not on the
user id, unlike everything else above. The body is a bare JSON string naming the
authentication provider the account is switched back to.

This removes the account's links on every provider of both protocols, persists
the provider switch, and revokes the account's active tokens. It is the heavy
option, and it is not the one to use for routine unlinking; use the DELETE above
for that.

Two things an integrator should know before offering this as a button.

A revoke is not durable against re-adoption. When the provider the person signs
in through has `AllowExistingAccountLink` enabled, a later SSO login can re-adopt
the same-named local account and the link comes back. With the fail-closed
default, where adoption is off, the revoke is durable
(`SSOController.cs:1585-1590`).

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
