# Authorization testing kit

Tooling and methodology for testing a multi-tenant SaaS application for broken access
control, IDOR, injection and business-logic flaws, under a bug bounty program.

| File | What it is |
|---|---|
| `TEST-PLAN.md` | The methodology. Ordered by expected value for an accounting SaaS target, not by OWASP category. Read this first. |
| `tools/har_to_config.py` | Turns a recorded browser session (HAR) into a ready config with the endpoints the app really calls. Start here — it replaces hand-copying URLs from devtools. |
| `tools/authz_diff.py` | Two-account authorization differ. Harvests object IDs as tenant A, replays each as tenant B and as an anonymous client, classifies the result. |
| `tools/config.example.json` | Config template, if you'd rather write it by hand. Copy to `config.json` (gitignored). |
| `tools/test_*.py` | 32 unit tests over the extraction, grouping and classification logic. No network. |
| `payloads/renderer-injection.md` | Server-side PDF/export injection — file read, SSRF, CSV formula injection. The highest-severity manual test on this kind of target. |
| `REPORT-TEMPLATE.md` | Submission template. |

## Who runs this

You do, under your own HackerOne account. The tool needs your session cookies and sends
traffic to a live production system, so it has to be executed by the person who accepted
the program terms and is accountable for that traffic.

## Workflow

```bash
pip install requests
cd tools
```

**1. Record a session as account A.** Log in, open devtools → Network, tick *Preserve log*,
then exercise the app: list invoices, open one, view its PDF, open a contact, download a
receipt. Every feature you touch becomes a test case. Right-click the request list →
*Save all as HAR with content*.

**2. Generate the config.**

```bash
python3 har_to_config.py session.har --host <api-host> --h1-username <you> -o config.json
```

Note the API host is often an `api.*` subdomain, not the one in the address bar. Review the
result and delete groups you don't care about — every group costs requests from your budget.
Any group marked `CHANGE-ME` is a detail endpoint whose collection wasn't in the recording;
give it a list URL or drop it.

**3. Export both tenants' cookies.** They expire, so re-export when a run comes back all-401.

```bash
export ACCT_A_COOKIE='...'
export ACCT_B_COOKIE='...'
```

**4. Run it.**

```bash
python3 authz_diff.py --config config.json --dry-run          # plan only, no traffic
python3 authz_diff.py --config config.json --out ../evidence/run1
python3 -m unittest discover -p 'test_*.py'                   # verify the logic
```

Output is `run1.md` (summary) and `run1.jsonl` (full evidence, one finding per line).

**5. Delete the HAR.** It contains your session cookies and every response body from that
browsing session. `*.har` is gitignored, but delete it anyway.

The differ covers IDOR mechanically. It does not cover the logic bugs in §4 of the test plan
or the renderer injection in `payloads/` — those are manual, and they're where the
higher-severity findings usually are.

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
