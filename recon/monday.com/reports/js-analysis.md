# monday.com — JavaScript asset analysis

**Source:** katana v1.2.2 standard crawl of `https://monday.com` (840 output lines).
**Date:** 2026-09-06

---

## 0. Status: the fetch stage could not run here

This session's egress proxy allows **GitHub only**. Every monday.com host is refused
at the CONNECT stage by organization policy:

```
$ curl https://monday.com/nhp/_next/static/chunks/webpack-b03d4825341567da.js
curl: (56) CONNECT tunnel failed, response 403
    monday.com:443 — connect_rejected (organization policy)
```

`cdn.monday.com`, `api.monday.com`, `auth.monday.com` — all denied, as is the
open internet generally (`example.com` fails identically). Per the proxy's own
guidance, policy denials are reported rather than routed around.

So this report contains **everything derivable without downloading the files**:
a complete, deduplicated, prioritised inventory of the JS attack surface, plus
the technology and surface findings the URL corpus alone gives up. The actual
byte-level analysis runs with one command once you're somewhere with network —
see §4. `tools/jsrecon.py` is written and tested; only the download is missing.

Everything in §3 is **inferred from URLs, not verified against live responses.**
Treat it as leads to confirm, and confirm scope with whatever program or
engagement authorises this before hitting the target.

---

## 1. Inventory

| | count |
|---|---|
| Raw crawl lines | 840 |
| Unique URLs | 679 |
| **Unique JavaScript files** | **111** |
| Runtime-computed JS refs katana could not resolve | 8 |
| Hosts observed | 14 |

Three separate front-end stacks are serving this one domain:

| Stack | Path | JS files | What it is |
|---|---|---|---|
| **Next.js** | `/nhp/_next/…` | 93 | "nhp" = new home page. Build ID `f8386b8abfa0c30976f388dea89ed0363ecb1df0` |
| **Webflow** (self-hosted bundles) | `/webflow-scripts/…`, `/homepage-shared-scripts/…` | 5 | Marketing pages, A/B tests, feature toggles |
| **WordPress** | `/l/…` | 7 | Legal/compliance site, theme `airfleet` |
| **Auth app** | `cdn.monday.com/build/…` | 1 | Login bundle, separate build pipeline |

Cloudflare sits in front (`/cdn-cgi/…`).

### Hosts

```
monday.com (582)   support.monday.com (56)   auth.monday.com (19)
community.monday.com   cdn.monday.com   www.monday.com   trust.monday.com
status.monday.com   ir.monday.com   forms.monday.com   api.monday.com
workforms.monday.com   view.monday.com   developer.monday.com
```

Plus two sibling properties referenced from the footer: `workcanvas.com`, `workforms.com`.

---

## 2. Prioritised analysis order

Full list: `data/js-targets-prioritised.txt` (111 URLs, tiers 1→6).
The tiering is the point — 93 of the 111 files are Next.js chunks that are mostly
vendor code, and reading them in crawl order wastes the effort.

### Tier 1 — enumerate before analysing (`data/tier1-manifests.txt`)

The crawl found 111 JS files. That is **not the whole set** — it is what katana
happened to see referenced. These three files give you the real set:

| File | Why first |
|---|---|
| `_next/static/f8386…/_buildManifest.js` | Maps **every route** in the Next.js app to its chunk files, including routes not linked from any crawled page |
| `_next/static/f8386…/_ssgManifest.js` | The statically-generated route list |
| `chunks/webpack-b03d4825341567da.js` | The webpack runtime, carrying the chunk-id → content-hash table. Lets you construct every chunk URL, including chunks nothing links to |

Also: the build ID `f8386b8abfa0c30976f388dea89ed0363ecb1df0` unlocks the Next.js
data endpoints — `https://monday.com/nhp/_next/data/f8386b…/<route>.json`. Those
JSON payloads routinely carry more fields than the rendered page shows (draft
flags, internal IDs, unpublished copy). Enumerate them from `_buildManifest.js`
route list. This is often the highest-yield single step on a Next.js target.

### Tier 2 — highest signal per byte (`data/tier2-highvalue.txt`)

Hand-written application and config code, not vendor bundles:

| File | Why |
|---|---|
| `webflow-scripts/query-param-toggles/query-param-toggles.bundle.js` | A **client-side toggle system driven by URL parameters**. It necessarily names every toggle and its parameter. Prime source for unreleased features, and a parameter-injection / DOM-sink surface in its own right |
| `webflow-scripts/ab-tests/ab-tests.bundle.js` | Experiment definitions: variant names and target paths, frequently including pages not yet linked anywhere |
| `webflow-scripts/w/w.head.bundle.js` + `w.body.bundle.js` | Site-wide head/body scripts — analytics keys, consent logic, the full third-party vendor stack |
| `homepage-shared-scripts/main/body.bundle.js` | Same class, homepage-specific |
| `cdn.monday.com/build/login_monday-15ee379aee2e89225b5d.js` | **The authentication bundle.** Highest security relevance of anything here: auth/SSO flows, OAuth client IDs, captcha site keys, MFA logic, endpoint paths. Also contains a dynamic loader (see §3, F10) implying more `cdn.monday.com/build/*` chunks to enumerate |
| `chunks/pages/_app-88fd807ce3ccb80e.js` | Next.js global app shell — `NEXT_PUBLIC_*` config, API base URLs, analytics and flag bootstrap |
| `chunks/pages/generated-templates/dynamic-template-page-*.js` | A dynamic route; reveals the data-fetching endpoint shape for the templates section |
| `chunks/main-b51c87c8563d2d89.js` | Next.js client runtime |

### Tiers 3–6

- **Tier 3** — 21 named shared chunks `NNNN-<16hex>.js`. Shared component code; API clients usually live here.
- **Tier 4** — 67 lazy chunks `NNNN.<16hex>.js`. Route/feature-specific, loaded on demand.
- **Tier 5** — 8 WordPress + Cloudflare assets. Low code value, high fingerprint value (see F2).
- **Tier 6** — 3 framework/polyfill bundles (React, polyfills). Skip unless version-hunting.

### Fetch these in the same pass (`data/adjacent-endpoints.txt`)

Not JavaScript, but they expand the same surface and cost one request each:

```
https://api.monday.com/v2/get_schema?format=sdl     # full GraphQL SDL
https://monday.com/.well-known/oauth-authorization-server
https://monday.com/.well-known/oauth-protected-resource
https://monday.com/.well-known/mcp.json
https://monday.com/.well-known/agent-skills/index.json
https://monday.com/.well-known/api-catalog
https://monday.com/sitemap_index.xml
https://monday.com/l/wp-json/                        # WP REST root
https://monday.com/l/xmlrpc.php
```

---

## 3. Findings from the crawl corpus (unverified — URL-derived)

Ordered by follow-up value, not severity. None of these is a vulnerability as
stated; each is a lead with a stated next check.

### F1 — Next.js build ID is a git-commit-shaped value, and it unlocks the data API
`f8386b8abfa0c30976f388dea89ed0363ecb1df0` is 40 hex characters — the shape of a
git SHA, suggesting the deploy commit is used as the Next.js build ID. Minor
disclosure alone. The real value is that it is the key to
`/nhp/_next/data/<buildId>/<route>.json`.
**Next:** pull `_buildManifest.js`, enumerate routes, request each data JSON, diff
the JSON fields against what the rendered page displays.

### F2 — WordPress 6.7.1 on `/l/`, with plugin and theme versions exposed
WordPress stamps core assets with the core version, and these are core assets:

```
/l/wp-includes/js/comment-reply.min.js?ver=6.7.1
/l/wp-includes/css/dist/block-library/style.min.css?ver=6.7.1
/l/wp-includes/js/jquery/jquery.min.js?ver=3.7.1
/l/wp-includes/js/jquery/jquery-migrate.min.js?ver=3.4.1
```

→ **WordPress 6.7.1**, jQuery 3.7.1, jquery-migrate 3.4.1 (the 6.7.x defaults).
Plugins and theme, likewise versioned:

- `word-2-html` **v1.0.59** — a small third-party plugin, the kind worth a CVE/changelog check
- `sitepress-multilingual-cms` (WPML)
- theme `airfleet`

Exposed WordPress endpoints in the crawl: `xmlrpc.php` (and `?rsd`), `wp-json/`,
`wp-json/wp/v2/posts/34`, `?p=34`, `/feed/`, `/comments/feed/`, oembed.
**Next:** check `wp-json/wp/v2/users` for author enumeration; check whether
`xmlrpc.php` still accepts `system.multicall` and `pingback.ping`; check
`word-2-html` 1.0.59 against its changelog. Note this WP is path-mounted on the
main domain behind the same CDN — path-based routing to a distinct backend is a
classic spot for path-normalisation and cache-key confusion.

### F3 — Minify cache directory is publicly pathed
`/l/wp-content/cache/min/1/l/wp-content/…?ver=1785511551` — an Autoptimize-style
cache path. These directories are frequently listable and hold concatenated
JS/CSS revealing plugin internals not otherwise reachable.
**Next:** request `/l/wp-content/cache/min/1/` and `/l/wp-content/cache/` directly.

### F4 — GraphQL schema is published in full
`api.monday.com/v2/get_schema?format=sdl` returns the complete SDL — every query,
mutation, argument type and deprecated field, without needing introspection.
This is intentional and documented, and it is still the single richest input for
API testing here.
**Next:** pull the SDL, diff it against the public API docs. Fields present in the
schema but absent from the docs are where the interesting authorisation questions live.

### F5 — Agent/OAuth metadata surface (new, lightly tested)
```
/.well-known/mcp.json
/.well-known/agent-skills/index.json
/.well-known/oauth-protected-resource      (RFC 9728)
/.well-known/oauth-authorization-server    (RFC 8414)
/.well-known/api-catalog
```
An MCP server plus OAuth authorization-server metadata. The AS document names the
authorization, token and (if present) **dynamic client registration** endpoints
and the supported grants; the protected-resource document names the resource
server and required scopes.
**Next:** check whether dynamic client registration is open, how `redirect_uri` is
validated, and whether the MCP tool definitions in `mcp.json` expose privileged
actions. This surface is newer than the rest of the site and correspondingly
less trodden.

### F6 — Ten cleartext `http://` links in page markup
Nine to `http://auth.monday.com/solutions/add_solution?solution_id=…` and one to
`http://www.monday.com/terms/dpa`. They will redirect to HTTPS and HSTS preloading
covers most browsers, so this is informational — but the first request leaves the
client in cleartext, and it is a one-line fix.

### F7 — Protocol-relative link handling
`https://monday.com//workcanvas.com` and `https://monday.com//workforms.com` are
katana's normalisation of `href="//workcanvas.com"` — which in a browser resolves
to a **different host**, not a path.
**Next:** two things. (a) `workcanvas.com` and `workforms.com` are sibling
properties worth scoping. (b) `//`-prefixed paths are worth testing for
open-redirect and for path-normalisation differences between the Cloudflare edge
and the origin.

### F8 — Sloppy URL construction
`monday.com/partners/aws/%20` — a trailing encoded space in a generated link.
Cosmetic on its own; URL-normalisation mismatches between edge and origin are
where cache-poisoning primitives come from, so it is worth one probe.

### F9 — Region parameter and public share tokens
`view.monday.com/4923960784-912829ab7717efb7fb86898ff6f59cbb?r=use1` (public board
share) and two `forms.monday.com/forms/<32-hex>` links. Public by design. The
useful part is `r=use1` — a **data-region/cluster identifier** (US East 1),
implying sibling values (`euc1`, `apse2`, …) and region-specific endpoints.
**Next:** test whether the region parameter is validated server-side or merely routes.

### F10 — The 8 "malformed" URLs are evidence, not noise
Katana caught these because it parsed string-concatenation in the JS:

| Artifact | What it reveals |
|---|---|
| `webflow-scripts/w/${e}` | Template-literal script loader in the Webflow bundles |
| `_next/static/chunks/'.concat(r,'` | The webpack runtime chunk loader |
| `cdn.monday.com/build/'+n+'` | A dynamic chunk loader in the **login** bundle — more auth-app chunks exist |
| `chunks/%5C%27/l/legal/tos/%5C%27` | Hardcoded legal paths inside a chunk |
| `chunks/%5C%5C%22/helpcenter/contact-support%5C%5C%22` | Hardcoded support path |
| `chunks/%27%29,L=d%28%27%3Cscript%20type=` | A chunk building a `<script>` tag at runtime — worth reading for the injection sink |

Collectively: **the real JS inventory is larger than 111 files**, and the rest has
to be recovered from the runtime chunk maps (Tier 1), not from crawling.

### F11 — Cloudflare email obfuscation is on and reversible
`/cdn-cgi/scripts/5c5dd728/cloudflare-static/email-decode.min.js` plus
`/cdn-cgi/l/email-protection`. The scheme is a single-byte XOR keyed on the first
byte of the payload — trivially reversible, and that decoder script *is* the
algorithm. Not a vulnerability; relevant only for completeness of contact data
on the legal and support pages.

---

## 4. Running the analysis (`tools/jsrecon.py`)

Stdlib-only Python 3, no install. Passive: plain GETs, nothing else.

```bash
cd recon/monday.com

# Stage 1 — download (polite defaults: 4 workers, 250 ms delay, resumable)
python3 tools/jsrecon.py fetch \
    -i data/js-targets-prioritised.txt \
    -o out --maps

# Stage 2 — static analysis
python3 tools/jsrecon.py analyze \
    -i out -o reports/live --target-domain monday.com

# Tier 1 first if you want the full chunk list before committing to a full pull:
python3 tools/jsrecon.py fetch -i data/tier1-manifests.txt -o out
```

`--maps` chases source maps two ways — the `sourceMappingURL` comment and a bare
`.map` probe. A hit reconstructs original, unminified sources with file paths and
comments, which changes the whole exercise; always worth the extra requests.

**What `fetch` produces:** `out/files/` plus `out/manifest.jsonl` (status, bytes,
sha256, content-type, cache headers, detected source map per URL). Re-running skips
what it already has.

**What `analyze` produces:** `reports/live/report.md`, `findings.jsonl`, and one
`.txt` per category. Rules:

- **Secrets, high confidence** — AWS key IDs, Google API keys, GCP OAuth clients, Stripe, Slack tokens and webhooks, GitHub/GitLab PATs, npm, SendGrid, Twilio, Mailgun, Mailchimp, OpenAI, Anthropic, private-key blocks, JWTs, credentials embedded in URLs.
- **Vendor identifiers, review** — Sentry DSNs, Segment write keys, LaunchDarkly, Mixpanel, Amplitude, Algolia, Mapbox, reCAPTCHA, GA/GTM. Usually public by design; they map the vendor stack and occasionally carry write scope.
- **Generic `key = "…"` assignments** — Shannon-entropy filtered (default 3.2) with placeholder suppression.
- **Surface extraction** — endpoint paths, GraphQL operation names, absolute URLs, S3/GCS/Azure buckets, internal hostnames, IPs, emails, feature flags, `process.env` / `NEXT_PUBLIC_*` references, localStorage/sessionStorage keys, cookie names, DOM sinks (`innerHTML`, `document.write`, `eval`, `dangerouslySetInnerHTML`), `postMessage` handlers, and URL-parameter reads.

The last two categories are the DOM-XSS lead list: a `postMessage` listener or a
URL-param read that flows into a sink is the thing to trace by hand afterwards.

**Calibration.** The rules were tested both ways: against a fixture carrying known
planted secrets (all recovered, with placeholders like `YOUR_API_KEY_HERE`,
`${env.KEY}` and bare identifiers correctly suppressed), and against a real 70 KB
minified jQuery bundle (zero false positives across every rule).

---

## 5. Recommended next steps

1. **Re-crawl properly.** The katana run was `standard` mode on an outdated
   v1.2.2, so it never executed JS or parsed bundles. That is why the JS list is
   partial and why eight URLs came back as raw concatenation expressions:
   ```bash
   katana -u https://monday.com -jc -jsl -kf all -hl -d 5 -fs rdn -o katana-deep.txt
   ```
   `-jc` parses endpoints out of JS, `-jsl` adds jsluice extraction, `-hl` renders
   with a headless browser (necessary — the Next.js app hydrates client-side),
   `-kf all` pulls robots.txt and sitemaps.
2. **Tier 1, then decide.** `_buildManifest.js` + `webpack-*.js` tell you the true
   file count before you commit to a full download.
3. **Tier 2 by hand.** Nine files. `query-param-toggles.bundle.js`,
   `ab-tests.bundle.js` and the login bundle deserve reading, not just grepping —
   beautify them (`npx prettier --write`) first.
4. **The `_next/data/<buildId>/*.json` sweep** (F1) — highest expected yield.
5. **The `.well-known` OAuth/MCP surface** (F5) — newest, least trodden.
6. **Then the WordPress instance** (F2) — it is a different application on the
   same origin, and it is the most conventional part of the attack surface.
