# Before you submit anything

## You currently have zero confirmed vulnerabilities

Everything in `bug-candidates.md`, `graphql-findings.md` and `idor-analysis.md` is a
**lead**: a shape in the schema or a URL pattern that *could* be a bug. Not one has been
tested against the live API. The single verified run so far returned `429` on every check.

This matters because of how triage works. A report that says *"the schema documents
`account_id` as 'needed for authentication', therefore there is an auth bypass"* gets
closed **Not Applicable** in minutes, because it contains no evidence that the resolver
actually trusts that argument. Ten of those in a row and your signal on the platform
drops far enough that your future reports get deprioritised or your account gets
restricted from submitting.

**A finding is a request and a response.** Until you have both, you have research notes.

## What is actually verifiable today

Two things, and both are weak. Submit them only if the program accepts hygiene issues —
check the policy first, because many explicitly exclude them.

**1. HSTS without `preload`** — you observed this directly:
```
strict-transport-security: max-age=31536000; includeSubDomains
```
No `preload` directive. Combined with the ten cleartext `http://auth.monday.com/...`
links in the homepage markup, a client that has never visited makes its first request to
the auth host in the clear. Informational-to-Low. Reproducible by anyone with `curl -I`.

**2. Internal mechanisms named in the public GraphQL SDL.** Anyone can fetch
`api.monday.com/v2/get_schema?format=sdl` unauthenticated, and it contains:
- `export_events` — "Requires a valid **X-Tool-Execution-Secret** header"
- `ActivityLogInternalQueries.logs` — "**skips authorization**, entity whitelisting"
- `InternalCallbackInput { service_name, path }` — "The name of the internal Monday
  service to call"

This is information disclosure about internal auth design. It is real and reproducible
with one unauthenticated request. It is also **low severity on its own** — it tells an
attacker where to look, it does not let them in. Most programs will mark it Informational.
File it as one report about the schema, not three.

Do not dress either of these up. Overclaiming severity is the fastest way to lose a
triager's attention for your next report.

## The two-account setup — do this before anything else

Every finding worth submitting from these reports is cross-tenant. You need:

1. **Account A** — your working account. Get a token: avatar → Developer → My Access Tokens.
2. **Account B** — a second free signup on a different email. Get its token too.
3. From B, collect: `account_id`, `user_id` (run `gqlprobe.py whoami` with B's token),
   a `board_id` and `item_id` from its URLs, an `asset_id` (upload a file), an
   `update_id` (post a comment).
4. Put a **recognisable secret** in B — an item named `CANARY-<random>`, a file called
   `canary.txt` with unique contents. That is what makes your proof unambiguous.

Then point A's token at B's identifiers:

```bash
export MONDAY_TOKEN='<A>'
python3 tools/gqlprobe.py idor --b-asset <B> --b-board <B> --b-account <B> \
                              --b-item <B> --b-update <B> --connection-id <N>
```

Anything that returns B's canary is a finding.

## What a report needs

Triagers close reports that make them do work. Give them everything:

**Title** — impact first, not mechanism.
> Bad: "IDOR in assets query"
> Good: "Any authenticated user can download arbitrary files from other accounts via `assets(ids:)`"

**Body:**

1. **Summary** — two sentences. What is broken, what an attacker gets.
2. **Steps to reproduce** — numbered, copy-pasteable, from a clean state. Include the full
   `curl`, the token you used (say *which account*, never paste the token), and the raw
   response.
3. **Proof** — the canary. `assets(ids: ["<B's asset>"])` returned `canary.txt`, and here
   is the file fetched from the returned `public_url`. Screenshot both accounts side by
   side so it is obvious they are different tenants.
4. **Impact** — concrete and bounded. "Asset IDs are sequential; an attacker enumerating
   them retrieves files uploaded by any customer." Do not write "full compromise" unless
   you have it.
5. **Remediation** — one line. "Authorise each requested ID against the caller's account."

**Rules:**
- One vulnerability per report. Do not batch.
- Never include a real token, cookie, or another user's PII in the report body. Redact,
  and say you have redacted.
- Test only on accounts you control. Never enumerate into real customer data — prove the
  bug with your own second account and *state* that the range is enumerable.
- If you find it and cannot reproduce it twice, do not submit it.

## Report skeleton

```markdown
## Summary
[One sentence: what is broken.] [One sentence: what an attacker gains.]

## Steps to reproduce
1. Create two monday.com accounts, A and B. Note B's account_id (<B_ACCOUNT>).
2. In account B, upload a file `canary.txt`; note its asset id (<B_ASSET>).
3. As account A, with A's API token:

   curl -s https://api.monday.com/v2 \
     -H "Authorization: <TOKEN_A — redacted>" \
     -H 'Content-Type: application/json' \
     -d '{"query":"{ assets(ids: [\"<B_ASSET>\"]) { id name public_url } }"}'

4. Response (account A's token, account B's file):

   {"data":{"assets":[{"id":"<B_ASSET>","name":"canary.txt",
    "public_url":"https://files.monday.com/..."}]}}

5. Fetching that public_url returns the contents of B's file:

   curl -s '<public_url>'   ->   CANARY-8f2a...

## Impact
Account A has no relationship with account B. [What the ID space looks like and why it
is enumerable. What kinds of data customers store there.]

## Remediation
Authorise every id in `assets(ids:)` against the requesting user's account before
resolving it.

## Notes
Testing was limited to two accounts I control. No third-party data was accessed.
```

## Order of work

1. Set up accounts A and B with canaries. (30 minutes, and it is the whole game.)
2. `gqlprobe.py idor` — the read-only sweep. `assets(ids:)` first.
3. `gqlprobe.py probe` — hidden fields; a cross-tenant hit there is high severity.
4. `gqlprobe.py crosstenant` — GQL-01 `dependency_column_config`.
5. `duplicate_item` by hand — the strongest write, and it copies rather than moves.
6. Only submit what returned a canary.

Scope: confirm the API and these hosts are in monday.com's program before sending
anything, and re-read their policy on rate limiting — you have already been limited once.
