# AT&T bug bounty engagement — working record

Everything produced across the engagement: reusable tooling, per-target assessments, submitted
reports, and the reasoning behind each conclusion.

---

## Tools (reusable on any target)

| Path | Purpose |
|---|---|
| `tools/spa-recon.py` | Fetch a page, pull its JS bundles, probe each for a source map, extract API paths, routes, hosts and candidate secrets. Bounded and serialised — tens of requests, not thousands. |
| `tools/unmap.py` | Reconstruct original sources from an exposed `.js.map`. Path-traversal guarded. |
| `depconf-lab/` | Self-contained dependency confusion demonstration. Two local registries, one `.npmrc` line apart. Nothing published anywhere. |
| `poc/cors-agsdesktop.html` | Browser PoC for credentialed cross-origin reads. |

```bash
python3 tools/spa-recon.py https://host/
python3 tools/unmap.py main.js.map ./src
./depconf-lab/run-poc.sh
```

---

## Submitted

**#3986119 — Unclaimed npm scope `@att-bit`** → closed **Not Applicable**

- `REPORT-dependency-confusion.md` — the submission
- `REPLY-3986119.md` — the reply declining to publish to the scope

Two verifiable facts: AT&T production JS imports from `@att-bit`; that scope 404s on public npm.
Triage asked for a pingback from AT&T's build machine — obtainable only by claiming their
namespace and executing code on their infrastructure. Declined; report closed.

**Intelligence for next time: this program requires demonstrated exploitation for this class.**
Do not resubmit it here.

Worth periodically re-checking — if the scope becomes registered, AT&T acted on the report:

```bash
curl -s -o /dev/null -w '%{http_code}\n' https://registry.npmjs.org/@att-bit%2Fduc.components.modal
```

---

## Targets

### acenpw.att.com — WordPress on WP Engine behind Akamai
`00-assessment.md` · `01-testing-checklist.md` · `03-dirsearch-triage.md` · `04-full-findings.md`

Nothing exploitable. Subdomain takeover ruled out via the CNAME chain. ~11,000 scanned paths
produced zero findings — every "hit" was a canned response, proven by `body = 165 + 2 × len(path)`
matching 18/18 sampled paths exactly.

### accsupport.att.com — Connected Communities Portal (React SPA)
`05-accsupport-spa.md` · `06-leads.md` · `07-status.md`

Source map exposed → recovered the application source. Role switching turned out to be a
documented feature, not an escalation. Tickets are POST-only, so no read-back. Salesforce record
types unused by the client. **This is where the `@att-bit` scope was found.**

### agsdesktop.att.com — Omnissa/VMware Horizon gateway
`REPORT-cors-agsdesktop.md`

XXE closed: `disallow-doctype-decl=true` rejects the DTD outright; XInclude not processed.

CORS **is** misconfigured — arbitrary `Origin` reflected with `Access-Control-Allow-Credentials:
true`, confirmed by browser PoC. **Not exploitable**: the session cookie is `SameSite=Lax`, so it
never accompanies a cross-site fetch, and only unauthenticated error pages are readable. Not
filed — the report would have been disproven by a `Set-Cookie` header on the same endpoint.

### b2b*.att.com (×10) — webMethods Integration Server consoles
`08-targets.md` · `09-b2b-api.md`

Ten internet-facing admin consoles, byte-identical, one deployment. The Angular bundle exposed
the full admin API (server env, JDBC pools, thread dumps, sessions, a user-modification
endpoint). Authorisation **is** enforced — `/invoke/wm.server/ping` → 403,
`/admin/navigation/license` → 401. Tested with the least sensitive endpoints available; no
credentials attempted.

### bnc-businessmessaging.att.com — IPMS *(still open)*
`10-bnc-ipms.md`

**The best target found.** No Akamai, no Bot Manager — responses carry real signal. Decade-old
stack (jQuery 1.9.1, `ie-eight.js`). The bundle exposes the IPMS API: `addressbook`, `message`,
`AccountManagers` and `auth` each shipping **v1 and v2 side by side**, plus a second auth system,
cloud-transfer endpoints, and file/thumbnail paths.

Open leads: version skew (v1 missing a check v2 added), `cloudId` IDOR, SSRF via
`/transfers/cloud2ipms`. NetScaler cookie decodes to `ipms-rest-8080-int-chi` — Low, not worth a
solo report.

### Other
`08-targets.md` — `asecare.att.com` runs Yoast SEO 14.3 (2020), unchecked against WPScan for
*unauthenticated* entries. `acetng.att.com` never assessed.

---

## Method that worked

1. **Baseline before scanning.** One request to a path that cannot exist. If it returns `200`,
   every scanner hit on that host is noise.
2. **Uniform body size across unrelated paths = a canned response.** Sort by size first.
3. **`403` means protected, `404` means absent, `200` means content.** Only `200` warrants
   reading, and only after reading the body.
4. **Read the bundle, not the filesystem.** Three targets' entire API surface came from published
   JavaScript. ~35,000 brute-forced paths produced nothing.
5. **A status code is never a finding.** `install.php` returning `200` looked Critical and was
   benign; the CORS reflection looked exploitable until `SameSite=Lax` closed it.
6. **Test the boundary with the harmless endpoint.** If it holds there, it holds everywhere. If it
   fails, that is the finding — capture the minimum and stop.
