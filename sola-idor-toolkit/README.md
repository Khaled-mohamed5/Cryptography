# Sola Security — Authorization Testing Toolkit

Cross-account IDOR / BOLA / BFLA testing for the Sola Security bug bounty
program on HackerOne, built around the two provided test accounts.

> **Authorization:** this targets a public bug bounty program, against the
> hosts it lists as in scope, using credentials the program supplies for
> testing. Scope is enforced in code — see [Scope enforcement](#scope-enforcement).

## Why this exists as a script

Sola's API is GraphQL (`api.sola.security`) behind a Frontegg IdP
(`auth.sola.security`). That combination makes manual IDOR hunting
impractical: a GraphQL schema typically exposes dozens of root fields that
accept a caller-supplied object id, and **every one of them is a separate
authorization decision** that the server can get wrong independently. Clicking
through the UI exercises the handful the front end happens to call. This
exercises all of them.

## Setup

```bash
pip install -r requirements.txt

export SOLA_A_EMAIL='<account-1>@wearehackerone.com'
export SOLA_A_PASSWORD='...'
export SOLA_B_EMAIL='<account-2>@wearehackerone.com'
export SOLA_B_PASSWORD='...'
```

Credentials are read from the environment so they never land in git.

## Run

```bash
python3 run.py                    # read-only; safe against production
python3 run.py --rate 1.5         # go gentler
python3 run.py --one-way          # only A -> B
python3 run.py --allow-mutations  # also fire writes — read the warning first
```

Exit codes: `0` nothing found · `1` positive findings · `2` could not test.

Output lands in `findings/`:

| File | Contents |
|---|---|
| `REPORT.md` | Submission-ready write-up, one section per finding, with `curl` repro |
| `findings.json` | Machine-readable results |
| `evidence.json` | Full request/response transcript (tokens redacted) |

### When introspection is blocked (the common case)

Production APIs usually block introspection, and edge WAFs often block the
introspection *query* specifically — `__schema` is a well-known signature. The
toolkit tells these apart: an edge block reports `BLOCKED AT THE EDGE`, a real
refusal reports `introspection DISABLED by the server`. Only the second says
anything about the API.

Either way you don't need a schema. Record the app instead:

1. Open `app.sola.security`, log in as **A**, DevTools → **Network**, filter
   **Fetch/XHR**.
2. Click into **detail views** — open a policy, a report, a member. List pages
   alone carry no id arguments and produce nothing to test.
3. Right-click the request list → **Save all as HAR with content** → `a.har`.
4. Repeat as **B** → `b.har`.

```bash
python3 run.py --har-a a.har --har-b b.har --tag your-h1-handle
```

Captured operations are *better* than a schema here: they are real documents
the app itself issues, so they validate against the live schema by
construction, they carry the exact argument values the app sent (replayed
verbatim, with only the id under test swapped), and they already pass whatever
the WAF enforces. The HAR doubles as the harvest — every id in a capture
belongs to the account that recorded it.

This is also the seeding step you have to do anyway, so it costs nothing extra.

### Dealing with the WAF

Sola sits behind a WAF that blocks intermittently (`Task Failed successfully:
access denied`). The toolkit retries edge blocks with backoff and never retries
a genuine application denial — conflating the two would turn infrastructure
noise into phantom findings.

If blocking persists, the durable fix is to be allowlisted rather than to work
around it. Pass `--tag <your-h1-handle>` so every request carries
`X-Bug-Bounty`, making your traffic attributable, and ask the program to
allowlist you — the WAF message itself invites this ("contact support with a
full curl request"). Check the program's policy on VPNs and proxies before
relying on one; some programs require testing from an identifiable address.

### Before the first run

Seed **both** accounts with data through the UI — a policy, an integration, a
saved report, whatever the product offers. The engine replays identifiers that
each account genuinely owns, so empty accounts mean nothing to test. If both
accounts land in the *same* tenant, the run says so and reports on cross-*user*
isolation instead; to test the tenant boundary, put account B in its own
organisation.

## What it tests

**1. Cross-account object reads (BOLA).** For every root field taking an id,
replays account A's identifiers under account B's token.

**2. Tenant-header override.** Re-sends denied requests with the victim's
tenant in `frontegg-tenant-id` / `x-tenant-id`. Authority must come from the
signed `tenantId` claim; a backend that trusts the header instead grants full
cross-tenant access from a one-header change.

**3. IdP tenant switching.** Asks Frontegg to re-scope account B's token to
account A's tenant. Success means an authenticated user can mint a
validly-signed token for a foreign tenant.

**4. Cross-account mutations (BFLA).** Enumerated always, executed only under
`--allow-mutations`. Read access is frequently locked down while
`update*`/`delete*` on the same object is not.

**5. Introspection exposure** and **6. alias-batching limits** — each an
informational finding on its own, and both amplifiers for everything above.

### Not guessing at findings

The reason most IDOR scanners are noisy is that HTTP 200 means several
different things. Each probe therefore runs against controls:

| Probe | Purpose |
|---|---|
| A requests A's object | baseline — proves the query works, captures the authorised response |
| B requests A's object | the actual attack |
| B requests B's object | control — proves the resolver reads the id at all |

A finding is reported only when the attack returns data, the baseline
succeeded, **and** the attack response differs from the control. A resolver
that ignores its id argument and returns the caller's own object is classified
`IGNORES_ID` and dropped — that is the single most common false positive in
automated IDOR testing.

Verdicts: `CONFIRMED` (byte-identical copy of the owner's object) ·
`LIKELY` (unauthorised data, differing shape — often a field-level leak) ·
`DENIED` / `NOT_FOUND` (correct) · `IGNORES_ID` / `NO_BASELINE` (not findings).

## Safety design

These defaults exist because the target is a live production SaaS with real
customers.

- **Mutations off by default.** A cross-tenant `delete` proves a point by
  destroying someone's data. Read-side evidence already demonstrates a broken
  authorization model; write testing is opt-in and should target objects you
  own.
- **No id brute-forcing.** Every identifier tested is harvested from one of the
  two authorised accounts, so probes never touch a third party's objects.
  UUIDs aren't enumerable anyway.
- **Rate limited** to 3 req/s by default. Testing should not look like a load
  test.
- **Tokens redacted** from the saved transcript unless `--no-redact`.
- **Aborts** after 8 consecutive transport errors rather than hammering a
  service that is already unhappy.

### Scope enforcement

`solakit/http.py` refuses to send anywhere outside the program's published
scope, and fails closed:

- **In scope:** `www.sola.security`, `app.sola.security`, `api.sola.security`
- **Login only:** `auth.sola.security` — Frontegg is a third-party IdP and is
  out of scope; it is used only to obtain our own tokens, exactly as the real
  app does. No test traffic is directed at it.
- **Refused:** `docs.sola.security` (GitBook), `*.freshchat.com`

## Not covered here

This toolkit is about **authorization**. Worth testing by hand against the same
two accounts:

- **Invitation and role flows** — invite a user, then tamper with the role in
  the request (`member` → `admin`). Also try inviting yourself into A's org
  from B, and accepting an invite intended for another address.
- **Second-order IDOR** — object ids that arrive by email, webhook, or export
  link rather than through the API.
- **Object references in file/report downloads** — S3 presigned URLs, export
  endpoints, and anything under `app.sola.security` that takes an id in a path.
- **JWT handling** — `alg:none`, algorithm confusion, expired-token acceptance,
  and whether the API validates the token `aud`/`iss`. Note these are
  properties of *Sola's verification*, in scope, even though the issuer is not.
- **GraphQL resource exhaustion** — deeply nested or recursive queries. Check
  the program's DoS policy first; most programs exclude it.
- **Tenant-scoped search** — search endpoints often query a shared index and
  forget the tenant filter, leaking names or ids across tenants.

## Layout

```
run.py              orchestrator CLI
solakit/
  config.py         scope allowlist, accounts, safety defaults
  http.py           scope-enforcing rate-limited session + evidence capture
  auth.py           Frontegg login, JWT claims, tenant switching
  gql.py            GraphQL client, introspection, response classification
  recon.py          schema -> ranked IDOR candidates + runnable documents
  harvest.py        collect identifiers each account legitimately owns
  idor.py           cross-account engine with control tests
  harfile.py        HAR / captured traffic -> candidates (no schema needed)
  report.py         Markdown + JSON output
tests/
  mock_server.py    mock multi-tenant API (one vulnerable, one secure,
                    one id-ignoring resolver)
  test_engine.py    end-to-end assertions
  test_har.py       capture ingestion + edge-block detection
```

## Tests

```bash
python3 tests/test_engine.py   # schema path, engine classification, safety
python3 tests/test_har.py      # captured-traffic path, WAF/edge detection
```

Runs the full pipeline against the mock API offline and asserts the engine
flags the vulnerable resolver, clears the secure one, and does not report the
id-ignoring one.
