# Authorization testing kit

Tooling and methodology for testing a multi-tenant SaaS application for broken access
control, IDOR, injection and business-logic flaws, under a bug bounty program.

| File | What it is |
|---|---|
| `TEST-PLAN.md` | The methodology. Ordered by expected value for an accounting SaaS target, not by OWASP category. Read this first. |
| `tools/authz_diff.py` | Two-account authorization differ. Harvests object IDs as tenant A, replays each as tenant B and as an anonymous client, classifies the result. |
| `tools/config.example.json` | Config template. Copy to `config.json` (gitignored) and fill in. |
| `tools/test_authz_diff.py` | Unit tests for the extraction and classification logic. No network. |
| `REPORT-TEMPLATE.md` | Submission template. |

## Who runs this

You do, under your own HackerOne account. The tool needs your session cookies and sends
traffic to a live production system, so it has to be executed by the person who accepted
the program terms and is accountable for that traffic.

## Setup

```bash
pip install requests
cp tools/config.example.json tools/config.json
```

Edit `tools/config.json`:

1. `target.base_url` — the asset you are authorized to test.
2. `target.marker_header` — your HackerOne username. The tool refuses to run until you
   change it, because the vendor needs to be able to attribute the traffic.
3. `harvest[]` — **replace the placeholder endpoints with real ones.** Open devtools,
   use the application normally as account A, and copy the request URLs the front end
   actually calls. Guessed endpoints burn your request budget on 404s.

Then export the cookies for your two test tenants — copy them from devtools, and note
that they expire, so re-export when a run comes back all-401:

```bash
export ACCT_A_COOKIE='...'
export ACCT_B_COOKIE='...'
```

## Running

```bash
cd tools

python3 authz_diff.py --config config.json --dry-run          # plan only, no traffic
python3 authz_diff.py --config config.json --out ../evidence/run1
python3 -m unittest test_authz_diff -v                        # verify the logic
```

Output is `run1.md` (summary) and `run1.jsonl` (full evidence, one finding per line).

## Reading the verdicts

| Verdict | Meaning |
|---|---|
| `CRITICAL` | An anonymous client got byte-identical content to the owner. Pre-auth data exposure. |
| `CONFIRMED` | Tenant B got byte-identical content to tenant A. Cross-tenant IDOR. |
| `INVESTIGATE` | 200 with different content, or an unexpected status. Could be B's own object at that ID, could be a partial leak. Check by hand. |
| `DENIED` | Correctly refused. |
| `SKIP` | The owner couldn't read it either, so there was no baseline to compare against. |

**An automated match is a lead, not a finding.** Reproduce every `CONFIRMED` and
`CRITICAL` manually in a browser before you submit. Triage teams close reports that turn
out to be a tool misreading a cached response or a shared-reference object that is
public by design.

## Safety behaviour

The defaults are deliberately conservative, because this runs against production systems
holding real customers' data:

- **GET/HEAD only.** Non-read methods require `--allow-writes`. `DELETE` is refused
  unconditionally — prove cross-tenant access with a read, and say in your report that
  you deliberately did not attempt to modify or destroy the victim tenant's records.
- **Hard request budget** (`safety.max_requests`, default 400), checked before every
  request. It stops and writes partial results rather than running away.
- **Client-side rate limit** (`safety.requests_per_second`, default 2). Slower than most
  program policies require. Check the policy — some cap it lower.
- **Attribution header** on every request.
- **No retries.** A failed request is recorded, not repeated. Retry storms look like a
  denial-of-service attempt from the vendor's side.
- **Credentials from environment variables only.** They are never written to the config,
  the evidence log, or stdout.

Before widening any of these, re-read the program's policy on automated scanning. The
fastest way to lose access to a private program is a scanner running at a rate nobody
authorized.
