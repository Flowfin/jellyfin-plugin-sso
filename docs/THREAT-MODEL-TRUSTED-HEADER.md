# Threat model: the trusted-header path

This is a STRIDE pass over the pattern in which a reverse proxy authenticates a
visitor and tells the Jellyfin server who they are by setting a request header.
Authelia, Authentik and oauth2-proxy all offer it, usually under the name
forward auth. It exists so that a decision about adopting the pattern can cite a
model rather than a paragraph.

It is not a decision. It says what the plugin could enforce, what it could not,
and which of the remaining conditions belong to the deployment. Some of those
conditions are ones no code in this repository can check, and saying so is a
legitimate outcome of the pass rather than a gap in it.

The pass itself is still not a decision, and nothing below its final section has
been rewritten to read as one. The decision it was written for was taken on
2026-08-31 and is recorded at the end, so that a reader of this tree finds the
answer where the analysis is rather than only on the issue that asked for it.

The subject is the hop between the proxy and the plugin, not the proxy's own
configuration. How Authelia decides that a visitor is `alice` is Authelia's
problem. What this document is about is everything that happens after it writes
that name into a header.

Every claim about the current tree below was read at
`8764949194da338c49dffbef26548539f0662344` on `origin/main`, with the command
next to it.

## What the plugin does with headers today

Nothing that decides anything. There is no indexed header read anywhere in the
plugin source:

```
$ git grep -n 'Request.Headers\[' origin/main -- SSO-Auth/
$ echo $?
1
```

The typed accessors that are used read exactly one header, `Accept-Language`,
and only to choose which translation catalog renders a page:

```
$ git grep -c 'Headers.AcceptLanguage' origin/main -- SSO-Auth/
origin/main:SSO-Auth/Api/Flows/OidcLoginService.cs:1
origin/main:SSO-Auth/Api/Flows/SamlLoginService.cs:1
origin/main:SSO-Auth/Api/Http/SSOViewsController.cs:1
origin/main:SSO-Auth/Api/Shared/BrowserErrorPage.cs:1
```

Where the plugin needs to know who is calling, it reads the connection's remote
address and nothing else:

```
$ git grep -c 'RemoteIpAddress' origin/main -- SSO-Auth/
origin/main:SSO-Auth/Api/Flows/OidcLoginService.cs:1
origin/main:SSO-Auth/Api/Flows/SamlLoginService.cs:2
origin/main:SSO-Auth/Api/Http/SSOController.cs:1
```

The reason is recorded at the function those four call, and it is the same
reasoning this document is about, already applied once:

```
$ git show origin/main:SSO-Auth/Api/RateLimit/SsoRateLimiter.cs | sed -n '79,85p'
    /// </summary>
    /// <param name="remoteIp">The connection's remote address. Deliberately the ONLY input: the
    /// plugin never parses X-Forwarded-For itself. Jellyfin's own forwarded-headers middleware
    /// (enabled by the server's "Known proxies" networking setting) already resolves the real
    /// client into this address and strips the consumed header entries, so any X-Forwarded-For
    /// value visible here is client-supplied and spoofable - keying on it would let an attacker
    /// rotate keys to evade or pin a victim's address to lock them out.</param>
```

So the plugin's current position is that a header is client-supplied until
something outside the plugin says otherwise. Adopting the trusted-header pattern
means reversing that position for one named header, and the rest of this document
is about what that reversal costs.

## The trust boundary

There is one boundary and it sits at the Jellyfin server's listening socket.

On the far side is whatever wrote the request. The intended writer is the proxy,
which has authenticated the visitor and is asserting an identity it believes. Any
other writer is a caller who reached the socket by some other route and is
asserting an identity nobody checked.

The plugin sees both as the same thing. An HTTP request is bytes, and a header is
not a different kind of byte from a body. Nothing in the request distinguishes
the two writers, because the assertion carries no signature, no expiry, no
audience and no nonce. That is the whole of the difference between this pattern
and the two the plugin already implements, where an OpenID Connect `id_token` is
verified against the provider's published keys and a SAML assertion is verified
against the provider's certificate, both in process and both re-checkable
afterwards.

What the plugin can observe about the writer is one thing: the address the
connection came from. Everything below that is a plugin-side mitigation rests on
that one observation, and everything that is not turns into a condition on the
deployment.

## Spoofing

### S1. A request that never traverses the proxy

The caller reaches the server directly and sets the header themselves. They
become whoever they typed. This is the defining failure of the pattern and the
plugin cannot detect it from the request alone.

What the plugin can do: require the connection's remote address to be in a
configured list of proxy addresses, refuse the login otherwise, and refuse to
enable the feature at all while that list is empty. That turns a header anybody
can set into a header anybody who can source-spoof or co-locate can set, which is
a genuine narrowing and not a closure.

The condition that remains with the deployment: the server's listening socket is
not reachable except through the proxy. Nothing in this repository can verify
that, and a plugin that claims to have checked it would be lying.

### S2. The proxy appends instead of replacing

If the proxy adds its header without clearing a client-supplied one of the same
name, the server receives two values. Which one the plugin picks decides who logs
in, and picking the first or the last is a coin toss against a caller who knows
which one you pick.

What the plugin can do: refuse when the header occurs more than once, and refuse
when a single occurrence carries a value separator, rather than resolving the
ambiguity. Failing closed on an ambiguous identity is the same rule already
applied elsewhere in the login path.

### S3. A second way in

A container network where a co-located workload can reach the server, a
management listener, a second virtual host, a debug port. Any of these is a
caller with the proxy's network position and none of the proxy's authentication.
S1's peer-address check does not help when the extra ingress shares the proxy's
address space.

This one stays with the deployment. The plugin can name it in its documentation
and in its configuration help text, and that is all.

### S4. A pre-shared value between proxy and plugin

The proxy sets a second header carrying a secret the plugin also holds, so that a
caller who reaches the socket without it is refused.

What the plugin can do: hold that value under the same at-rest protection and the
same export redaction as the existing provider secrets, compare it in fixed time,
and refuse a login when it is absent or wrong.

What it does not fix: the value is a bearer credential sent in clear over the
proxy-to-server hop on every request. Anybody who can read one request can replay
it forever, it does not expire, and it appears in any packet capture or debug log
of that hop. It narrows S1 and S3 substantially. It does not convert the header
into an authenticated assertion.

## Tampering

### T1. Every attribute in the header set is unauthenticated

The pattern is usually offered with more than a name: a group list, a mail
address, sometimes an administrator flag. Each additional attribute is another
thing an attacker who wins S1 gets to choose, and the group list is the one that
matters, because that is what maps to permissions.

What the plugin can do: trust the identifier only, and resolve every permission
locally from configuration keyed on that identifier, never from the header. A
header that cannot say "administrator" cannot grant administrator however well it
is spoofed. This is a design constraint on the feature rather than a mitigation
added to it, and it is the single most valuable item on this list.

### T2. Header name confusion

Header names are matched by the server after its own normalisation, and proxies
differ in how they treat underscores, casing and non-token characters. A caller
who finds a spelling the proxy does not strip but the server does accept has
bypassed the proxy's sanitisation without touching the network path.

What the plugin can do: match the one configured name exactly, never a prefix and
never a family, and refuse anything else rather than falling back to a variant
spelling.

### T3. Mutation after the proxy

A second proxy, a service mesh sidecar or a load balancer between the
authenticating hop and the server can rewrite the header, and the plugin sees
only the last writer. This is S1 with more steps and it stays with the
deployment.

## Repudiation

### R1. There is no artefact to re-verify

After an OpenID Connect login the server held a signed token; after a SAML login
it held a signed assertion. Both can be re-checked later against the provider's
key material, which is what makes an incident review possible. A header login
leaves the plugin's own belief and nothing else. If the question afterwards is
whether a particular person actually signed in, the honest answer for the header
path is that the server cannot tell.

What the plugin can do: record the header path under its own protocol label in
the audit trail rather than folding it into the two existing ones, and record the
peer address the login was accepted from, which is the only piece of evidence
that exists. Today the success record carries the username, the protocol, the
provider and whether administrator rights were granted, and no address:

```
$ git show origin/main:SSO-Auth/Api/Audit/SsoAudit.cs | sed -n '35,41p'
        logger.LogInformation(
            "[SSO Audit] Login succeeded: {Username} via {Protocol} provider '{Provider}' (admin={IsAdmin}).",
            username?.ReplaceLineEndings(string.Empty),
            protocol,
            provider?.ReplaceLineEndings(string.Empty),
            isAdmin);
    }
```

### R2. Recording the address is itself a change

It is a new personal-data field in the audit trail, which pulls on retention and
on the privacy documentation. The trade is real and it should be made
deliberately: without the address the header path records less than the paths it
sits beside, and with it the plugin starts logging something it has so far chosen
not to.

## Information disclosure

### I1. Reflecting the header

An error page or a log line that echoes the header value or the header name
discloses internal topology, and one that echoes the S4 shared value discloses
the credential. The plugin's existing refusal surface answers with a fixed reason
code and no detail, and the header path has to hold that same line rather than
being helpfully verbose about why a header was rejected.

### I2. The shared value in configuration

If S4 is adopted, that value is a secret with the same handling as a provider
client secret: never logged, never returned by a read of the configuration, and
redacted from any export. The machinery for that already exists and reusing it is
a requirement rather than an option.

### I3. Username enumeration

A refusal that distinguishes "no such user" from "header rejected" tells an
unauthenticated caller which names exist. The single non-enumerating refusal the
plugin already uses is the right answer here too.

## Denial of service

### D1. The cost of an attempt collapses

Both existing paths make an attacker complete a round trip with an identity
provider before the plugin does any work. A header login is one request. If the
feature also provisions unknown users, one request creates an account, and a loop
creates as many as it likes.

What the plugin can do: put the header route in the existing rate-limit
classification rather than beside it, and gate provisioning on the header path
the same way the other paths gate it, with new accounts disabled pending approval
where that setting is on.

### D2. Throttling by address stops working when every request shares one address

The rate limiter keys on the connection's remote address, which in a proxied
deployment is the proxy for every visitor. Either the operator has configured
Jellyfin's known-proxies setting, in which case the middleware has already
resolved the real client into that address and the keying works, or they have
not, in which case one throttled abuser throttles everybody.

This is the sharpest finding in the pass, and it is a condition rather than a
mitigation. The plugin cannot fix it by reading a forwarded address, because
trusting a forwarded address is precisely the trust the pattern is trying to
establish and cannot verify. So the same unverifiable setting decides both
whether the header path is safe and whether the throttle in front of it works,
and a deployment that gets it wrong loses both at once.

## Elevation of privilege

### E1. The pattern is elevation whenever S1 holds

There is no separate mitigation to list here. Everything under Spoofing is this
threat's mitigation.

### E2. Administrator rights from a header

Mapping a header attribute to administrator makes the whole server one spoofed
request away. Administrator should not be reachable from the header path at all,
so that the worst outcome of a spoof is an ordinary account rather than the
server.

### E3. Interaction with SSO-only login

When password login is turned off, SSO is the only door. If the header path is
that SSO, then a header anybody can set is the only door, and the designated
break-glass administrator is the only thing between a spoof and total loss of
control. Adopting the header path and enabling SSO-only mode should not be
possible without the operator being told what the combination means.

## The conditions the plugin cannot verify

Collected in one place, because this is the list a decision needs. Each of these
has to hold for the pattern to be safe, and none of them is checkable from inside
the server process.

1. The server's listening socket is unreachable except through the authenticating
   proxy, from every network the server is attached to.
2. The proxy replaces the identity header on every route it serves, including
   error responses, redirects and protocol upgrades, rather than appending to a
   client-supplied one.
3. No second ingress reaches the server with the proxy's network position.
4. Jellyfin's known-proxies setting names the proxy, so that the address the
   plugin keys its throttle on is the visitor rather than the proxy.
5. Nothing between the proxy and the server rewrites the header.

A plugin-side implementation can narrow the first and the third with a
peer-address allowlist, narrow them further with a pre-shared value, and refuse
the ambiguity that the second one creates. It cannot confirm any of the five.

## What this leaves for the adoption decision

The pattern can be implemented here in a form that fails closed on everything the
plugin can see: off by default, refusing to enable without a proxy allowlist, one
exactly-named header, single occurrence only, identifier only with no roles and
no administrator flag, permissions resolved locally, its own audit protocol
label, the existing rate-limit classification, and the existing non-enumerating
refusal.

What it cannot do is make the pattern fail closed on the part that decides
whether it is safe. The five conditions above are properties of a deployment, the
plugin has no way to observe any of them, and a feature that is secure only while
an operator holds up their end is a different kind of feature from the two this
plugin ships today, both of which verify a signature and can say no on their own.

That difference is the decision, and this document does not take it. Declining on
the ground that the plugin cannot verify its own security precondition is a
defensible reading of the evidence here. So is adopting it with the constraints
above and a deployment contract stated in the documentation. What is not
defensible is adopting it without the constraints, because the version of this
pattern that reads a group list and honours an administrator flag turns one
spoofable header into the whole server.

## The decision this pass was written for

**DECLINED on 2026-08-31**, on #808, which is where the reasoning was written and
where the wording below is taken from rather than re-derived.

The ground is the finding of the section above, not a preference: no code in this
server process can observe any of the five conditions, and header trust fails
open, so the failure mode is a valid session for an attacker rather than an error
a log shows. A plugin that mints a session from a header it cannot prove came
from the proxy is trusting a claim it has no instrument to check. Adopting with a
deployment contract moves that risk into a document an operator is asked to
honour, and a document does not narrow an allowlist. The one adoption shape most
requesters actually want - reading the proxy-supplied group list and honouring an
administrator flag - is the one this pass rules out outright.

So the project will not ship an authentication path whose security precondition
it cannot verify. This document stays in the tree as the evidence behind that,
because a decline backed by a model is worth more to a future asker than a
decline backed by a preference.

What would change it is a mechanism by which the plugin can verify the peer it
received the header from. That is a new issue citing #808, not a reopening of it.

Nothing in this section widens what the pass established. The two readings it
called defensible were both defensible on the evidence; one of them was taken,
and the fact that the other remained available is not deleted by the taking.
