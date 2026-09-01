# What to actually test on acenpw.att.com

Run these from **your own IP**, not cloud infrastructure. AT&T needs to attribute the
traffic to you. Keep request rates low — the policy forbids degrading availability, and
hammering an Akamai-fronted host will get you rate-limited or banned before it gets you a bounty.

Ordered by expected payout, not by ease.

## Tier 1 — genuinely worth a bounty

### 1. Vulnerable WordPress plugin (highest value path)
This is where real Criticals on WordPress assets come from.

```bash
# Version fingerprinting
curl -s https://acenpw.att.com/wp-content/plugins/<plugin>/readme.txt | head -20
curl -s "https://acenpw.att.com/?rest_route=/wp/v2/types" | jq .
```

Enumerate plugins, extract `Stable tag:` from each `readme.txt`, then match against the
WPScan vulnerability database. You are looking for **unauthenticated SQLi, file upload, or RCE**.

Policy constraint: *"0-day vulnerabilities less than 30/60/90 days from patch release are
ineligible."* The CVE must be past that window — which is fine, since an unpatched old CVE
is exactly what you want anyway.

### 2. Open redirect in that 302 — but only if you can chain it
Find what drives the redirect:

```bash
for p in redirect url next return dest destination continue r u goto; do
  curl -s -o /dev/null -w "$p -> %{redirect_url}\n" \
    "https://acenpw.att.com/?$p=https://example.com"
done
```

**Read this before reporting one:** an open redirect on its own will likely close as
Informative, because AT&T excludes issues "which require a social engineering component."
It becomes valuable only when **chained** — most notably if you can bounce an OAuth/SSO
flow on `signin.att.com` or `identity.att.com` (both Focus Assets) through this redirect to
leak a token or code. That chain is a real High/Critical. Demonstrate the token landing on
your host, on video.

### 3. Exposed sensitive files
```bash
/wp-content/debug.log
/.env
/wp-config.php.bak  /wp-config.php.save  /wp-config.php~
/.git/config
/wp-content/uploads/          # directory listing
```
Severity tracks what is actually inside. Credentials or internal data = strong report.
An empty directory listing = not a report.

## Tier 2 — real but usually closed as low impact

- User enumeration via `/wp-json/wp/v2/users` or `/?author=1`
- `xmlrpc.php` enabled (pingback SSRF, auth brute-force amplification)
- WordPress version disclosure via `/readme.html` or generator meta tag

AT&T explicitly excludes "issues determined to be low impact." Submit these only if you can
demonstrate concrete downstream impact, and expect $50 at best.

## Do not submit — explicitly excluded by policy

| Finding | Why excluded |
|---|---|
| Missing security headers, CSP, HSTS | Low impact / theoretical |
| Clickjacking on unauthenticated or static pages | Named exclusion |
| Missing SPF on domains with no MX | Named exclusion |
| Self-XSS (payload in headers or request body) | Named exclusion |
| POST-based reflected XSS | Named exclusion |
| Login/logout CSRF | Named exclusion |
| Content spoofing needing user action | Named exclusion |
| Banner grabbing / version disclosure alone | Theoretical, no exploit path |
| Anything requiring the victim to click an external link | Social engineering exclusion |

## Rules that will sink an otherwise good report

- **Critical and High findings require a video PoC.** Without one it is not triaged at all.
- Test **only against accounts you own**. Never touch another customer's data.
- If you stumble onto real customer or employee data, stop, do not save it, and declare it
  in the submission.
- Do not disclose anywhere else — not a blog, not a tweet, not a private group. Disclosure
  voids eligibility.
- Report must be new. Duplicates pay nothing, and you usually only learn it was a duplicate
  after the fix ships.
