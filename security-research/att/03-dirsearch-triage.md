# Triage of the dirsearch run against acenpw.att.com

~11,460 paths tested, several hundred "hits" reported. Almost none are findings.
Two systemic response patterns explain the bulk of the output.

## Pattern 1 — the catch-all 302 to acetng.att.com

```
/php.tgz         -> https://acetng.att.com/php.tgz
/backup.zip      -> https://acetng.att.com/backup.zip
/error.log       -> https://acetng.att.com/error.log
/wp-content/debug.log -> https://acetng.att.com/wp-content/debug.log
```

`acenpw.att.com` forwards unmatched paths to `acetng.att.com`, preserving the path.
This is a site-migration redirect. dirsearch lists every one as a hit because 302 is a
non-404, but **nothing was found** — the file does not exist, the request was just forwarded.

**This is not an open redirect.** The destination is hardcoded to a fixed AT&T host. An open
redirect needs the destination to be *attacker-controlled*, typically via a query parameter.
Here you cannot influence where it sends you. Rule it out.

## Pattern 2 — 403 means blocked, not exposed

```
403 - 827B - /wp-config.php
403 - 827B - /.git/config
403 - 827B - /.env
403 - 827B - /wp-json/wp/v2/users/
```

The uniform 827-byte and 166-byte bodies are Akamai WAF block pages. Identical size across
hundreds of unrelated paths is the signature of a single canned denial response.

`403 - /wp-config.php` means **Akamai refused to serve it**. It is the WAF working. Reading
these as "I found wp-config.php" inverts the meaning — this is the single most common way a
beginner report gets closed as N/A.

Same for the 500s on `.bak`/`.swp` paths: uniform 662–666 byte bodies, an origin error
handler, no content returned.

## What actually returned content

| Path | Result | Assessment |
|---|---|---|
| `/wp-admin/install.php` | **200, 720B** | **Only line worth verifying.** See below. |
| `/wp-admin/setup-config.php` | 409, 3KB | Benign. WordPress returns 409 "Configuration file already exists" when `wp-config.php` is present. Expected on a configured site. |
| `/wp-content/` | 200, 20B | Stub index. Directory listing disabled. |
| `/wp-cron.php` | 200, 20B | Normal WordPress behavior. |
| `/wp-json/` | 401, 113B | REST API requires auth. Good posture, not a finding. |
| `/wp-admin/admin-ajax.php` | 400, 1B | Normal — returns `0` with no `action` param. |
| `/wp-content/uploads/*_backups/` | 302 → `wp-login.php` | Backup dirs gated behind authentication. Good posture. |
| `/.well-known/acme-challenge/*` | 302 → `farm-ingress-api.wpesvc.net` | Confirms WP Engine origin. Normal ACME cert flow. |

Net result: **no exposed config, no exposed backup, no `.git`, no directory listing, no user
enumeration.** The asset is reasonably well defended.

## The one thing to verify: /wp-admin/install.php

`install.php` returning 200 has two possible meanings, and the status code alone cannot
distinguish them:

1. **"Already Installed" page** — WordPress is configured; the installer refuses to run.
   Benign, and the far more likely reading. The page is a short `wp_die()` with a stylesheet
   link, which is consistent with 720 bytes.
2. **The setup wizard renders** — WordPress has no database tables, and *anyone* can complete
   installation, set an admin password, and take over the site. From WP admin, plugin/theme
   editing gives code execution. That is a **Critical**.

Reading 2 is unlikely here: `setup-config.php` returned 409, which means `wp-config.php`
already exists, and the site is clearly serving a live WordPress. Also 720 bytes is far too
small for the setup wizard form, which runs several KB.

Verify with one request:

```bash
curl -s https://acenpw.att.com/wp-admin/install.php | head -40
```

- Contains **"You appear to have already installed WordPress"** → benign. Do not report.
  Reachability of `install.php` alone is closed as informative by every mature program.
- Renders a **form asking for Site Title / Username / Password** → stop testing immediately,
  do not complete the installation, screenshot and record video, and report as Critical.

## RESOLVED — install.php is benign

Body confirmed:

```html
<h1>Already Installed</h1>
<p>You appear to have already installed WordPress.
   To reinstall please clear your old database tables first.</p>
```

WordPress is configured and the installer refuses to run. **Not reportable.** This matches
the prediction from the 409 on `setup-config.php` and the 720-byte length. Do not submit
"install.php is publicly reachable" — every mature program closes that as informative.

## Two details worth extracting from that response

### WordPress core version 6.4.10 is disclosed

```
href='.../wp-includes/css/dashicons.min.css?ver=6.4.10'
```

Version disclosure alone is **not reportable** — low impact, no exploit path, excluded by
policy. Its value is as an input to the plugin/core CVE search.

The 6.4 branch is old, but the `.10` suffix means core security backports are being applied
(WP Engine does this automatically). What matters is whether 6.4.10 is the *current* 6.4.x
backport:

- Check https://wordpress.org/download/releases/ for the highest 6.4.x release.
- **6.4.10 is current** → no core CVE to report. Move to plugins.
- **A higher 6.4.x exists** → read that release's security notes for unpatched core issues.
  Note the policy rule: *"0-day vulnerabilities less than 30/60/90 days from patch release
  are ineligible for bounty"* — a fix released very recently does not qualify.

Do not report a version number as a finding. Report a *specific vulnerability* that the
version is provably subject to, with a working PoC.

### Akamai Bot Manager is actively fingerprinting you

```html
<link rel="stylesheet" href="/r2JzbL/8Zr_/_Lsx/QuVA/JVXMxF/pLOJS9/XllzAQ/Yj0LBhZ/DWCFZ">
<script src="/r2JzbL/8Zr_/_Lsx/QuVA/JVXMxF/pLOJS9/XllzAQ/VTQ5fQx/sNU4p" async defer></script>
<div id="sec-overlay" style="display:none;"><div id="sec-container"></div></div>
```

Randomised path segments plus `sec-overlay` / `sec-container` are the Akamai Bot Manager
signature. Your traffic is being actively profiled, not merely rate-limited. This makes the
scanning-volume point below concrete rather than theoretical.

## Scanning volume — a real risk to your program standing

Roughly 11,000 requests in nine minutes at 25 threads against AT&T production infrastructure.
The program policy states:

> Your testing activities must not negatively impact AT&T, or AT&T's Environment availability
> or performance.

The wall of uniform 403s shows Akamai was already blocking you. Aggressive automated scanning
against a defended production host risks being read as a policy violation, and can get you
removed from the program — which costs far more than any single finding on a non-Focus asset.

Turn `-t` down to 5–10, scope wordlists to the stack you have actually identified (WordPress
here, not Typo3/Joomla/Bitrix/cgi-bin), and prefer targeted requests over broad brute force.
