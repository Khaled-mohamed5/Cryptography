# jsrecon — JS bundle analysis for authorized web app testing

Static analyzer for JavaScript assets collected during authorized security
testing. Stdlib-only Python 3, no install step.

## Usage

```bash
# 1. Download in-scope assets (scope guard is enforced, use it)
python3 jsrecon.py fetch -t targets_staging.txt -o ./js --allow-host staging.prevail.ai

# 2. Analyze
python3 jsrecon.py analyze -d ./js -o report.md --json findings.json --unpack-maps
```

`fetch` also follows `//# sourceMappingURL=` references and pulls any `.map`
files. `--unpack-maps` writes `sourcesContent` back out as original
pre-minification sources under `_unpacked/` — if maps are exposed, analyze
those instead of the minified bundles.

## What it looks for

| Category | Detail |
|---|---|
| Secrets | AWS, Stripe, Google, Slack, GitHub, Twilio, Sentry, AppSignal, Mapbox, JWTs, private keys, credentials-in-URL, plus an entropy-gated generic rule |
| DOM XSS sinks | `innerHTML`, `outerHTML`, `insertAdjacentHTML`, `document.write`, `srcdoc`, `createContextualFragment`, `setHTMLUnsafe`, jQuery HTML methods |
| Code execution | `eval`, `new Function`, string-form timers, dynamic `import()` |
| Redirect / nav | `location` assignment, `location.assign/replace`, `window.open`, `.src`/`.action` assignment |
| postMessage | listeners missing an origin check; `postMessage(..., "*")` |
| Prototype pollution | `__proto__`, `constructor.prototype`, prototype indexing |
| Recon | source maps, endpoints/paths, WebSocket URLs, internal hostnames, S3 buckets, dev comments, role/permission logic, feature flags, debug toggles |

### The part that matters: sink scoring

A flat grep for `innerHTML` across Turbo/Trix/ActionText returns hundreds of
vendor hits and buries the real ones. Instead, every sink match is scored by
**proximity to a controllable source** (`location.*`, `event.data`, `dataset`,
`URLSearchParams`, `getAttribute`, storage reads, `decodeURIComponent`, `atob`…)
within a ±260 char window:

- source nearby → **HIGH** (xss/code-exec) or **MEDIUM** (redirect)
- no source, file is known vendor code → **INFO**
- otherwise → **LOW**

`postMessage` listeners are scanned only up to the *next* listener, so a
neighbouring handler's origin check is never miscredited to an unguarded one.

Severity is a **triage ranking, not a verdict**. Every HIGH still needs manual
confirmation in the browser before it belongs in a report.

## Scope discipline

`targets_staging.txt` contains `staging.prevail.ai` assets only. Production
`prevail.ai`, `blog.prevail.ai` and `help.prevail.ai` appeared in the crawl but
are out of program scope and are excluded. `--allow-host` enforces this at fetch
time — a stray out-of-scope URL is dropped, not requested.

## Recon note from the crawl (no requests needed)

Comparing asset digests between the staging and production hosts in the crawl
output: **16 of 17 bundles share identical digests**, meaning staging and
production run the same build. Exactly one differs:

| Bundle | staging | production |
|---|---|---|
| `custom_elements_2025` | `cbdf736b` | `0cb732cb` |

So `custom_elements_2025` is the **only** bundle carrying staging-exclusive
code — the newest and least-exercised code in the app, and the one place where
staging-only behavior can live. It is Priority 1 in the targets file.

Two structural observations worth carrying into manual testing:

1. **Parallel bundle generations.** `application` / `application_2025` and
   `custom_elements` / `custom_elements_2025` both ship. A mid-redesign app
   frequently leaves the *older* code path reachable and unmaintained — check
   whether legacy handlers can still be reached.
2. **Stack fingerprint.** Rails + Hotwire (Turbo/Stimulus), Devise
   (`/users/sign_in|sign_up|password/new`), SAML SSO
   (`/users/saml/metadata?idp_entity_id=`), ActionText + Trix (rich text —
   historically a sanitizer-bypass surface), AppSignal. For a live-transcription
   video product, `remote_session_elements`, `speaker_tagging_*` and
   `gameplan_elements` are the custom, product-specific attack surface, and
   ActionCable/WebSocket authorization is the highest-value thing to check —
   per-channel authorization on `subscriptions.create` is a common gap.
