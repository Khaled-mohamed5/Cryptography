# monday.com — crawl triage and JS analysis plan

Source: katana v1.2.2 standard crawl of `https://monday.com`, 679 lines / **677
unique URLs** across **14 hosts**, of which **111 are JavaScript**.

## Status: what is and is not done here

| | |
|---|---|
| Crawl surface triaged offline | **done** — this document |
| JS files downloaded and scanned | **not done** — network blocked, see below |
| Anything confirmed as a vulnerability | **no** — everything below is a *lead to verify* |

The session that produced this document runs behind an egress proxy that allows
only GitHub and package registries. Every `monday.com` host returns
`connect_rejected` (HTTP 403 at the gateway) — including `api.monday.com`,
`cdn.monday.com` and `support.monday.com`, and also unrelated hosts such as
`example.com`. So the 111 JS files could not be fetched, and **no claim in this
document is based on JavaScript contents.**

The analysis itself is packaged in [`analyze.sh`](analyze.sh) and runs anywhere
`monday.com` resolves. See [README.md](README.md).

## Before testing anything

- Confirm current scope and rules of engagement. monday.com publishes a
  reporting form at `monday.com/security/form/` and a trust centre at
  `trust.monday.com`; read the programme scope before sending traffic.
- Everything below is either passive (reading public assets) or must be tested
  **against your own two accounts only**.
- Do not test the pingback/SSRF and enumeration ideas at volume. One request
  proves the behaviour; a thousand is a denial-of-service and gets you banned.

## Your API tokens — rotate them

The two tokens pasted into this session decode to:

| | TOKEN_B | TOKEN_C |
|---|---|---|
| user id (`uid`) | 115702202 | 115703279 |
| account id (`actid`) | 36786355 | 36786534 |
| permission (`per`) | `me:write` | `me:write` |
| region | `euc1` | `euc1` |
| expiry | *none* | *none* |

Two distinct accounts with write scope and **no `exp` claim** — they are valid
until revoked by hand. They were pasted in cleartext into a transcript, so treat
them as disclosed and reissue both when you are done. They are not committed to
this repository.

Two separate tenants is exactly the right setup for the authorization testing in
lead 5 below: every object created under `actid 36786355` is a test case for
whether `actid 36786534` can reach it.

## Leads, ranked

Ranking is by *expected value*, not by how interesting the technology is:
likelihood the bug is real × severity if it is × chance it has not already been
reported.

### 1. The WordPress install at `monday.com/l/` is same-origin with the main site

The legal/compliance site is WordPress served from a **path** on the primary
host, not a separate origin:

```
https://monday.com/l/wp-includes/js/jquery/jquery.min.js?ver=3.7.1
https://monday.com/l/wp-content/themes/airfleet/...
https://monday.com/l/wp-content/plugins/word-2-html/...?ver=1.0.59
https://monday.com/l/wp-content/plugins/sitepress-multilingual-cms/...   (WPML)
https://monday.com/l/wp-json/          https://monday.com/l/xmlrpc.php
https://monday.com/l/?p=34             https://monday.com/l/wp-json/wp/v2/posts/34
https://monday.com/l/feed/             https://monday.com/l/comments/feed/
```

Asset query strings disclose **WordPress 6.7.1** (Nov 2024 — several majors
behind), jQuery 3.7.1 with jquery-migrate 3.4.1, and plugin `word-2-html` 1.0.59.

This is the highest-value lead, and the reason is the origin, not the CMS:
`monday.com/l/*` shares an origin with `monday.com`. A stored or reflected XSS
anywhere under `/l/` executes as `https://monday.com`. **The finding to chase is
that escalation**, not the CMS version.

To test, in order:

1. Is any `.monday.com`-scoped cookie readable from JS on that origin?
   Load `monday.com/l/legal/tos/` while logged in and check `document.cookie`
   plus the `HttpOnly`/`Domain` flags on every cookie in DevTools. If the app
   session cookie is `Domain=.monday.com` and not `HttpOnly`, an XSS under `/l/`
   is account takeover and the severity of everything else here changes.
2. Does `/l/` have its own CSP, or does it inherit the marketing site's? A weak
   or absent `script-src` on that path is what makes step 1 exploitable.
3. `word-2-html` is a small plugin — check its version against WPScan/CVE feeds,
   and look for unauthenticated conversion/upload routes under
   `/l/wp-json/` and `/l/wp-admin/admin-ajax.php`.
4. WPML (`sitepress-multilingual-cms`) has a history of serious CVEs; identify
   its version from its own asset URLs.

Report the XSS if you find one. Do **not** lead with "WordPress 6.7.1 is
outdated" — version-only reports are closed as informational by nearly every
programme, and burn your signal.

### 2. `xmlrpc.php` and the REST API are reachable

`/l/xmlrpc.php` and `/l/xmlrpc.php?rsd` both appear in the crawl.

- `system.multicall` turns credential stuffing into one request per hundreds of
  guesses. Confirm the method is enabled with a **single** `system.listMethods`
  call; do not actually brute force.
- `pingback.ping` is the SSRF primitive. If it is enabled, test it against a
  host **you** control and observe the callback. Do not point it at cloud
  metadata endpoints.
- `/l/wp-json/wp/v2/users` is the standard author-enumeration route; if it
  returns real staff usernames that is a Low, and it feeds lead 1.
- `/l/wp-json/oembed/1.0/embed?url=` takes a URL. Check whether
  `oembed/1.0/proxy` is also exposed — that one is the historical SSRF.
- `/l/comments/feed/` existing implies comments may be open somewhere under
  `/l/` — a stored-XSS surface that lands directly on lead 1.

Realistic severity: xmlrpc-enabled alone is Informational-to-Low on most
programmes. It is worth reporting only bundled with a demonstrated impact.

### 3. `add_solution` is a state-changing GET, and it takes an `origin` parameter

```
https://auth.monday.com/solutions/add_solution?solution_id=10005150&origin=hp_fullbg_page_header
http://auth.monday.com/solutions/add_solution?solution_id=10016422      ← plain HTTP
```

Two separate questions:

- **CSRF.** If `GET /solutions/add_solution?solution_id=X` actually attaches a
  solution to the logged-in account with no token, that is CSRF via an `<img>`
  tag. Test with your own two accounts: log in as account B, visit the URL from
  an unrelated page, and see whether the state changed.
- **`origin` parameter.** It currently carries a tracking token
  (`hp_fullbg_page_header`), but the name suggests it may feed a redirect or a
  postMessage target. Try a URL value and watch for a `Location` header or a
  client-side navigation. If it redirects off-host, that is an open redirect on
  the **auth** host — which matters far more than on the marketing site, because
  it can be chained into OAuth `redirect_uri` abuse (lead 4).

Nine `add_solution` links are also emitted as plain `http://`. Check whether
`auth.monday.com` sends HSTS and whether it is preloaded; if not, that is a
first-request downgrade. On its own: Low.

### 4. The agent/MCP surface is the newest and least-picked-over

```
https://monday.com/.well-known/mcp.json
https://monday.com/.well-known/agent-skills/index.json
https://monday.com/.well-known/oauth-authorization-server
https://monday.com/.well-known/oauth-protected-resource
https://monday.com/.well-known/api-catalog
```

This is recent surface, so it has had the fewest eyes on it. Fetch all five
first — they are public metadata documents and reading them is passive. Then:

- **OAuth AS metadata.** Note `registration_endpoint` (is dynamic client
  registration open to anyone?), the advertised `redirect_uri` validation,
  whether PKCE is required, and which `response_type`s are still allowed. An
  open DCR endpoint plus loose redirect matching is a real bug class.
- **`mcp.json`.** Enumerate the declared tools and their auth requirements. The
  question worth answering with your two tokens: can a tool call scoped to
  account B reach an object in account C? That is lead 5 through a different door.
- **`agent-skills/index.json`.** Skills are instructions an agent fetches and
  acts on. If any part of a skill's content is influenced by user-supplied data
  (a board name, an item title), that is indirect prompt injection with a real
  blast radius. This is the most novel thing in the whole crawl.

### 5. GraphQL: diff shipped operations against the published schema

The public schema is downloadable:

```
https://api.monday.com/v2/get_schema?format=sdl
```

That is intentional and is not a finding. It is useful as a **baseline**:

1. `curl 'https://api.monday.com/v2/get_schema?format=sdl' -o public-schema.sdl`
2. Run `analyze.sh` — stage 4 writes `out/analysis/graphql-operations.txt`,
   every operation name found in the shipped bundles.
3. Diff them. Operation names or fields present in JS but **absent from the
   public SDL** are internal or undocumented, and undocumented fields are where
   authorization checks are most often missed.
4. For each one, run it with TOKEN_B against an object id belonging to
   TOKEN_C's account. A field that returns data across that boundary is a BOLA,
   and BOLA on a multi-tenant SaaS is the highest-severity class you are
   realistically going to find here.

This is the lead most likely to produce a High. It is also the one that needs
the JS analysis to run first.

### 6. Enumerable numeric ids

```
/marketplace/9   /marketplace/12   /marketplace/20   /marketplace/23   /marketplace/131
/marketplace/10000005   /marketplace/10000017   /marketplace/10000023
```

Two id ranges, both small and dense. Walk a **modest** sample and compare
authenticated vs unauthenticated responses. What you are looking for is a draft,
unlisted or private app that renders anyway — app metadata often carries
developer emails and internal notes. Same idea for `solution_id`
(`80436`, `80451`, `10005544`, `10005559`, `10005564`, `10005918`, `10005937`,
`10016422`, `10032399`).

Keep the sample small and the rate low. This is the lead most likely to look
like an attack if you automate it carelessly.

### 7. Public share links published on monday.com's own pages

```
https://view.monday.com/4923960784-912829ab7717efb7fb86898ff6f59cbb?r=use1
https://forms.monday.com/forms/e27e3f80c6715d9aadb54e0f8eb394d2?r=use1
https://forms.monday.com/forms/9f862eef0081db8c8b6e1f9f574bdabf
```

These are deliberately public, so the share itself is not the bug. Worth one
look each for over-permissioning: does the view expose account member names or
emails, board structure beyond the shared view, or accept writes? Does the form
endpoint disclose the underlying board schema or allow submissions to be read
back? A public share that leaks more than it renders is a genuine finding.

### 8. Low / informational

- `https://monday.com/?asdsdfasda` — junk query string reachable from a link in
  page source. Leftover test link. Informational at best.
- `http://www.monday.com/terms/dpa` — plain-HTTP link, same HSTS question as
  lead 3.
- `https://monday.com/partners/aws/%20` — trailing space in an `href`. A broken
  link, not a bug.

## Noise: katana artifacts, not endpoints

These came out of the crawler misparsing JavaScript string concatenation. They
are not real URLs and **must not** be reported:

```
https://monday.com/webflow-scripts/w/$%7Be%7D                      →  ${e}
https://monday.com/nhp/_next/static/chunks/%5C%27/l/legal/tos/%5C%27
https://monday.com/nhp/_next/static/chunks/%5C%5C%22/helpcenter/contact-support%5C%5C%22
https://monday.com/nhp/_next/static/chunks/'.concat(r,'
https://monday.com/nhp/_next/static/chunks/%27%29,L=d%28%27%3Cscript%20type=
https://cdn.monday.com/build/'+n+'
https://monday.com//workcanvas.com     →  protocol-relative href to workcanvas.com
https://monday.com//workforms.com      →  protocol-relative href to workforms.com
```

They do carry one piece of signal, though. `'.concat(r,'` and `'+n+'` are the
remains of **runtime chunk-URL construction** — proof that the app builds script
URLs from a table the crawler cannot follow. That is precisely why stage 2 of
`analyze.sh` parses the webpack runtime instead of trusting the crawl: the 111
JS files katana found are the ones the homepage happened to load, not the ones
that exist.

## Hosts seen in the crawl

`monday.com` (580) · `support.monday.com` (56) · `auth.monday.com` (19) ·
`community.monday.com` (4) · `cdn.monday.com` (3) · `www.monday.com` (2) ·
`trust.monday.com` (2) · `status.monday.com` (2) · `ir.monday.com` (2) ·
`forms.monday.com` (2) · `api.monday.com` (2) · `workforms.monday.com` (1) ·
`view.monday.com` (1) · `developer.monday.com` (1)

A standard-mode crawl from one seed. Once `analyze.sh` runs,
`out/analysis/hosts-in-scope.txt` will list every `monday.com` host referenced
from inside the JavaScript — that set is normally much larger than what a crawl
reaches, and it is what should seed the next pass.
