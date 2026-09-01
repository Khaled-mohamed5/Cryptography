# Complete findings — acenpw.att.com

Every response class observed across the dirsearch run and the manual follow-ups,
with what each one means and whether it is reportable.

**Bottom line: zero security vulnerabilities. Six observations, all informational,
none bountiable under this program's policy.**

---

## Part A — every response class, decoded

### 1. `302 → https://acetng.att.com/<same path>`  (the large majority)

A catch-all migration redirect. Unmatched paths are forwarded to a different AT&T host with
the path preserved.

**Not a finding.** dirsearch flags these only because 302 is not 404. Nothing was located.

**Not an open redirect** either — the destination is fixed. An open redirect requires the
attacker to *control* the destination, normally through a query parameter
(`?url=`, `?next=`, `?redirect=`). You cannot influence this one.

Two body sizes appear, and the split tracks file extension:

| Size | Extensions |
|---|---|
| 138B | `.zip .css .doc .exe .gif .ico .jpg .png .pdf .swf .xls .flv` |
| 417B | `.tgz .7z .gz .bz2 .rar .log .cert .class .chm` |

Most likely two different Akamai rules — browser-renderable static assets handled by one,
archives and logs by another. Cosmetic; no security relevance.

**Real value here:** the scan revealed `acetng.att.com`, a separate AT&T host. That is
legitimate recon worth pursuing as its own asset.

### 2. `403 — 827 bytes`  (hundreds of paths)

Akamai WAF block page. The body is *byte-identical* across `/wp-config.php`, `/.git/config`,
`/.env`, `/phpmyadmin/`, and hundreds of unrelated paths.

**Critical to understand: 403 means blocked, not exposed.** The WAF refused to serve the
request. `403 - /wp-config.php` is evidence the file is *protected*.

Misreading these as discoveries is the most common cause of an N/A closure on a first report.
Identical body size across unrelated paths is always a canned denial, never real content.

### 3. `403 — 166 bytes`

A second Akamai rule, almost exclusively on `.txt` paths. Same meaning: blocked.

### 4. `403 — 1 byte`

Seen on `/wp-content/uploads/`, `/wp-content/upgrade/`, `/wp-content/mu-plugins/`,
`/wp-includes/`.

This is the **WP Engine origin** denying directory access, distinct from Akamai's 827B page.
Directory indexing is off. Correct configuration.

### 5. `500 — 662 / 664 / 666 bytes`

On `.bak`, `.swp`, `.bac` paths: `/wp-config.php.bak`, `/config.php.swp`, `/htaccess.bak`.

Uniform sizes again — a canned error page, no content returned. **This is the one genuine
defect in the set**, discussed in Part B.

### 6. `404 — 332 bytes`

Genuine not-found. Only on `/cgi-bin/*`, `/crossdomain.xml`, `/nginx_status`. Notably these
escape the acetng redirect, so a separate Akamai rule covers them.

`/crossdomain.xml` and `/nginx_status` returning 404 is **good** — no Flash policy file, no
exposed nginx status page.

### 7. `301 — 45 / 47 / 48 bytes`

Trailing-slash normalisation on `/wp-admin`, `/wp-content`, `/wp-includes`. Standard.

### 8. `302 → /wp-login.php?redirect_to=…&reauth=1`

On `/admin-ajax.php` and every `/wp-content/uploads/*_backups/` path.

`reauth=1` is what WordPress emits from `auth_redirect()`. Unmatched paths in these locations
require authentication. **This is good posture** — the backup-plugin directories that
attackers routinely raid are gated behind login.

Note the routing split: `/wp-content/*` reaches the WordPress origin, while other unmatched
paths get the Akamai redirect to acetng.

### 9. `401 — 113 bytes` on `/wp-json/`

REST API requires authentication. This is why `/wp-json/wp/v2/users/` gave nothing —
**user enumeration is closed**, the most common WordPress information leak.

### 10. `400 — 1 byte` on `/wp-admin/admin-ajax.php`

WordPress returns `0` when called with no `action` parameter. Textbook normal behaviour.

### 11. `409 — 3 KB` on `/wp-admin/setup-config.php`

WordPress's "Configuration file already exists" response, emitted when `wp-config.php` is
present. Confirms a configured install. Benign.

### 12. `200 — 720 bytes` on `/wp-admin/install.php`  — VERIFIED BENIGN

Body confirmed as the **"Already Installed"** page. The installer refuses to run.

Had this rendered the setup wizard, it would have been Critical — anyone could set an admin
password and reach code execution via the theme/plugin editor. It does not.

### 13. `200 — 20 bytes` on `/wp-content/`, `/wp-cron.php`, `/wp-includes/rss-functions.php`

Stub responses. No directory listing, no content.

### 14. `200 — 0 bytes` on `/favicon.ico`

Empty favicon. Cosmetic.

### 15. `302 → farm-ingress-api.wpesvc.net` on `/.well-known/acme-challenge/*`

ACME challenge proxied to WP Engine's ingress for Let's Encrypt issuance. Normal, and the
reason the WP Engine fingerprint appeared in the original httpx output.

---

## Part B — the six real observations, ranked

None are bountiable. Ranked by how close each comes to mattering.

### B1. HTTP 500 instead of 403/404 on backup-file extensions

Requesting `/wp-config.php.bak` returns **500**, not 403 or 404.

A 500 means an unhandled server-side condition — something threw rather than being cleanly
rejected. Neighbouring paths return a clean 403, so the handling is inconsistent.

**Why it is a defect:** error paths should be deliberate. A 500 signals the request reached
code that did not expect it.

**Why it is not reportable:** no content is returned, no stack trace, no path disclosure —
just a 664-byte canned page. Without leaked information or a crash you can steer, there is no
security impact. AT&T excludes *"theoretical security issues with no realistic exploit
scenario"*.

**Only becomes reportable if** you can make it emit a stack trace, an internal path, or a
database error. Worth one look at the full body; do not submit the status code alone.

### B2. WordPress core on the 6.4 branch

`?ver=6.4.10` on core CSS assets. WordPress 6.4 shipped November 2023.

The `.10` matters — core security backports are being applied (WP Engine does this
automatically). An old branch that is patched is a *maintenance* posture question, not a
vulnerability.

**Check:** compare against the highest 6.4.x at https://wordpress.org/download/releases/.
Current → no core CVE. Behind → read that release's security notes, then mind the policy rule
that fixes newer than 30/60/90 days are ineligible.

### B3. Version disclosure via `?ver=`

WordPress appends its version to core asset URLs by default. It tells an attacker exactly
which CVEs to try.

**Not reportable.** Excluded as low impact with no exploit path. Every mature program closes
version disclosure as informative. Useful to *you* as a CVE search input, worthless as a
submission.

### B4. Hosting provider disclosure

The ACME redirect exposes `farm-ingress-api.wpesvc.net`, confirming WP Engine as origin.

**Not reportable.** Infrastructure fingerprinting with no exploit path.

### B5. `wp-cron.php` publicly accessible

Reachable by design in WordPress. Repeated requests can be used for resource-exhaustion
amplification.

**Not reportable.** AT&T explicitly excludes DoS. Do not test this — you would be attacking
availability, which violates the program terms.

### B6. Related subdomain exposed: `acetng.att.com`

The redirect target is a distinct AT&T host you had not enumerated.

**Not a vulnerability** — it is recon output. Its value is as a *new asset to assess*, subject
to the same scope rules.

---

## Part C — why nothing here pays

Cross-referencing every observation against the program's exclusions:

| Observation | Policy clause that excludes it |
|---|---|
| 500 error handling | "Theoretical security issues with no realistic exploit scenario" |
| Version disclosure | "Issues determined to be low impact" |
| Provider disclosure | "Issues determined to be low impact" |
| `wp-cron.php` | "Distributed Denial of Service attacks" |
| Subdomain discovery | Not a vulnerability class |
| `install.php` reachable | Benign response, no impact |

The asset is genuinely well defended: Akamai WAF plus Bot Manager in front, WP Engine managed
hosting with automatic core patching, REST API authenticated, directory indexing off, backup
directories behind login, config files blocked at the edge.

**Correct conclusion: submit nothing for this host.**

---

## Part D — how to read scanner output

Generalisable from this run:

1. **Uniform body size across unrelated paths = a canned response.** Hundreds of 827-byte
   403s is one block page, not hundreds of discoveries. Sort by size before reading anything.
2. **403 means protected; 404 means absent; 200 means content.** Only 200 warrants attention,
   and only after you read the body.
3. **A status code is never a finding.** Every conclusion in this document came from reading a
   *body*. `install.php` returning 200 looked Critical and was benign — one `curl` settled it.
4. **Redirects are only vulnerabilities when you control the destination.** Fixed target =
   routing. Attacker-controlled target = open redirect.
5. **Fingerprint before you brute-force.** Most of those 11,000 requests tested Typo3, Joomla,
   Bitrix, and cgi-bin paths against a known WordPress site. Identifying the stack first turns
   an 11,000-request scan into a few hundred targeted ones.
6. **Scanner "hits" are hypotheses, not results.** dirsearch reported several hundred; zero
   survived triage. That ratio is normal. The skill being paid for is the triage, not the scan.

---

## Part E — what has NOT been tested

The assessment so far is entirely reconnaissance. Path brute-forcing answers one question:
*does a file exist at this name?* It does not test application behaviour, which is where
most vulnerabilities live.

### Closed (do not revisit)

Subdomain takeover · open redirect · exposed config, backups, `.git` · directory listing ·
user enumeration · installer takeover · core version

### Untested — the actual attack surface

**E1. Application functionality — the largest gap**

Nobody has looked at what this site *does*. Start here:

```bash
# What is actually served?
curl -s https://acenpw.att.com/ | head -100

# Every link and form on the page
curl -s https://acenpw.att.com/ | grep -oE '(href|action)="[^"]*"' | sort -u

# API endpoints hidden in the JavaScript
curl -s https://acenpw.att.com/ | grep -oE 'src="[^"]*\.js"' | sort -u
# then fetch each and grep for: /api/, ajax, fetch(, XMLHttpRequest, endpoint
```

Then map every input: URL parameters, form fields, search boxes, headers, cookies. Each is a
candidate for injection, access-control failure, or IDOR. **This is what testing means.**

**E2. Plugin and theme CVEs**

```bash
curl -s https://acenpw.att.com/ | grep -oE 'wp-content/(plugins|themes)/[^/"?]+' | sort -u
```

Pull names from the live HTML rather than brute-forcing — quieter under Bot Manager and more
accurate. Then `readme.txt` → `Stable tag:` → WPScan database. Look for **unauthenticated**
SQLi, arbitrary file upload, or RCE.

**E3. `acetng.att.com`**

An entirely separate host, discovered but never assessed. Same scope rules apply.

**E4. Authenticated surface**

If registration or login exists, an authenticated session opens IDOR, privilege escalation,
and access-control testing — none of which is reachable unauthenticated.

### Expectation setting

This program has ~1,587 resolved reports and has been running since 2019. It is heavily
tested. Unauthenticated low-hanging fruit on a non-Focus, WAF-fronted, managed-hosting asset
is genuinely unlikely.

Finding nothing on a given host is the normal outcome, not a failure. The response is to
change target or change technique — not to lower the bar for what counts as a finding.
