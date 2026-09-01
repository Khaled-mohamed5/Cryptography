# accsupport.att.com — AT&T Connected Communities Portal

## What it is

```
<title>AT&T | Connected Communities Portal</title>
<meta name="description" content="Keeping our communities connected">
<div id="root"></div>
<script defer src="/static/js/main.1e5c16f4.js"></script>
<link href="/static/css/main.18fcb7eb.css" rel="stylesheet">
```

A **Create React App single-page application**. `<div id="root">`, hashed bundle names under
`/static/`, and an empty HTML shell are the CRA build signature.

Also present: Akamai Bot Manager (the randomised `/2uLyLufa2t8Fqg6D3cBE_CBH9aQ/...` script and
stylesheet, plus `sec-overlay` / `sec-container`) and Akamai Boomerang/mPulse RUM.

## This retroactively explains the dirsearch results

A CRA SPA ships **two static assets and an API**. There is no server-side file tree.

- Catch-all 301 appending `/` → SPA route handling
- Zero 404s anywhere → every path is absorbed by the client-side router
- Nothing found in 11,460 requests → there was nothing on disk to find

Path brute-forcing cannot work against this architecture. Not "did not work this time" —
**cannot**, structurally. The application does not live in the filesystem.

## Do NOT report the mPulse key

```js
window.BOOMR_API_key = "WPDUB-APVCN-LTNDE-ZPC3E-YKMHC"
```

This looks like a leaked credential and is not one. Akamai Boomerang/mPulse API keys are
**public by design** — they identify the site to the RUM collector and appear in the page
source of every site using mPulse. They grant no access.

Reporting this is a guaranteed N/A. The same applies to the other Akamai telemetry in that
snippet:

| Value | What it is | Sensitive? |
|---|---|---|
| `ak.gh: 23.3.88.190` | Akamai edge ("ghost") server IP | No — published in every Akamai response |
| `ak.ai: 863940` | Akamai property ID | No |
| `ak.cp: 1416925` | Akamai CP code | No |
| `BOOMR_API_key` | mPulse site identifier | No — public by design |

**Rule: a value being present in client-side code does not make it a secret.** Frontend
bundles are public. The question is always *what does this credential actually authorise?*

## The real attack surface: the JS bundle

The entire application — every route, every API endpoint, every client-side check — is inside
`/static/js/main.1e5c16f4.js`. That single file is now the target.

```bash
curl -s https://accsupport.att.com/static/js/main.1e5c16f4.js -o main.js
wc -c main.js
```

### 1. API endpoints — the highest-value extraction

```bash
grep -oE '["'"'"']/(api|v[0-9]|rest|graphql|services?|gateway)[a-zA-Z0-9._/{}-]*' main.js \
  | tr -d '"'"'"'' | sort -u
```

Every endpoint the app calls. Then hit each one directly, outside the UI. Client-side
applications routinely enforce authorisation in the UI and not at the API — that gap is where
IDOR and broken access control live.

### 2. External hosts it talks to

```bash
grep -oE 'https?://[a-zA-Z0-9.-]+\.[a-z]{2,}[a-zA-Z0-9._/-]*' main.js | sort -u
```

Look for internal hostnames, staging environments, and cloud storage buckets.

### 3. Client-side routes

```bash
grep -oE 'path:["'"'"'][^"'"'"']*' main.js | sort -u
```

React Router definitions. Admin or internal routes that the navigation never links to are
worth visiting directly.

### 4. Source maps

```bash
tail -c 200 main.js | grep -o 'sourceMappingURL=.*'
curl -s -o /dev/null -w '%{http_code}\n' https://accsupport.att.com/static/js/main.1e5c16f4.js.map
```

A 200 means the original un-minified source is published — variable names, comments, file
structure. Low severity on its own, but it makes everything else far easier to read.

### 5. Candidate secrets — verify before believing

```bash
grep -oiE '(api[_-]?key|secret|token|password|bearer|auth)["'"'"']?\s*[:=]\s*["'"'"'][^"'"'"']{8,}' main.js
```

Most hits will be public identifiers like the mPulse key. For each one, answer: **what does
this credential authorise, and can I demonstrate that access?** No demonstrated access means
no report.

Genuinely reportable examples: an unrestricted Google Maps key that can be billed against, an
AWS access key, a Firebase config with world-writable database rules, an internal service
token that returns data when replayed.

## Rules of engagement

This portal likely handles connectivity assistance for community programs, which means real
applicant data may sit behind it.

- Test **only** against an account you create yourself
- Never enumerate another person's record, even to prove a point — verify IDOR by having two
  of your own accounts, or by observing an authorisation failure, not by reading someone's data
- If real personal data appears inadvertently, stop, do not save it, and declare it in the
  report as the policy requires
- Keep request volume low; Bot Manager is fingerprinting every request
