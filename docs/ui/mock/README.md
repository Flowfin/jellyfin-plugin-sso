# The 4.4 surface, as a clickable mock

Stage 0 of the 4.4 rebuild (#1526), under the plan in #1525. Five pages, one per
tab, plus the add-provider wizard and one opened provider editor. Nothing here
talks to a server, every control is disabled, and the figures on the cards are
invented, so what can be judged is the structure and nothing else.

## Opening it

From the tree, with no build step:

```
$ start docs/ui/mock/overview.html        # Windows
$ xdg-open docs/ui/mock/overview.html     # Linux
```

The five pages link to each other through the tab strip, so any of them is a
starting point.

Beside the real page on a test server, which is what the issue asks to walk. The
mock is static, so it drops into the server's own web root and is reachable in
the same browser as the plugin page:

```
$ docker cp docs/ui/mock jf-sso:/jellyfin/jellyfin-web/ssomock
$ start http://127.0.0.1:8096/web/ssomock/overview.html
```

Or from any file server, which needs nothing installed. The query has to be cut
off the path or `providers.html?protocol=SAML` looks for a file of that name:

```
$ node -e "const h=require('http'),f=require('fs'),p=require('path'); \
  h.createServer((q,s)=>{const u=q.url.split('?')[0]; \
  const n=p.join('docs/ui/mock',u==='/'?'overview.html':u); \
  f.readFile(n,(e,d)=>e?(s.writeHead(404),s.end()):(s.writeHead(200,{'content-type': \
  n.endsWith('.css')?'text/css':n.endsWith('.js')?'text/javascript':'text/html'}),s.end(d)))}) \
  .listen(8123,'127.0.0.1')"
$ start http://127.0.0.1:8123/
```

The SAML half of the provider editor is a link rather than a click:
`providers.html?protocol=SAML`.

## What is real and what is a stand-in

- **Real.** The tab strip is the markup the dashboard builds for its own section
  tabs, read off the running server rather than guessed - `<div is="emby-tabs"
class="tabs-viewmenubar">` around an `emby-tabs-slider` of
  `emby-tab-button` links. The controls carry the same `emby-*` classes the
  current configuration page uses.
- **Real.** The field list. Every control renders from `fields.js`, which
  `tools/ui-mock-fields.js` reconciles against the five built configuration
  pages under `SSO-Auth/Web/` - one page until #1527 built the rest - so a
  control that exists on a page and not in the mock fails that check.
- **A stand-in.** The colours and the type. Inside the dashboard the `emby-*`
  classes are already styled and the stand-in switches itself off; opened from
  the tree there is no dashboard stylesheet, so `mock.css` paints enough to make
  the structure legible. It is not the dashboard's palette and is not meant to
  become one.
- **Not the surface.** The protocol picker on the Providers page. A real editor
  opens the provider it was given; the picker is here so one screen can show both
  the OpenID and the SAML controls in their new homes.

## What it does not show

- No help text of the current page is copied. Each control is labelled by a
  readable form of its `id`, with the `id` beside it, because that is the key
  `FIELDS.md` reconciles on and a second copy of the help would drift against the
  first. Condensing the help is stage 2 (#1528) and is where that text moves.
- No i18n. One language per view is stage 3 (#1529).
- The self-service page at `/SSOViews/linking` is not mocked. It is part of 4.4
  and part of stage 3, and it is not one of the five tabs.

## Where the field table is

[`FIELDS.md`](FIELDS.md), with one row per control and the command that keeps its
count honest.
