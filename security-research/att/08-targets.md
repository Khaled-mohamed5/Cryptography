# Prioritised targets from subdomain enumeration

Triage of the httpx sweep. Ranked by expected value.

---

## T1 — Ten exposed webMethods Integration Server admin consoles

```
b2b.att.com      144.160.29.90    200  6913  Integration Server Administrator
b2bag.att.com    144.160.29.89    200  6913  Integration Server Administrator
b2bage.att.com   144.160.219.82   200  6913  Integration Server Administrator
b2bao.att.com    144.160.219.88   200  6913  Integration Server Administrator
b2be.att.com     144.160.219.83   200  6913  Integration Server Administrator
b2bece.att.com   144.160.29.93    200  6913  Integration Server Administrator
b2bsa.att.com    144.160.219.85   200  6913  Integration Server Administrator
b2bsae.att.com   144.160.29.88    200  6913  Integration Server Administrator
b2bsd.att.com    144.160.29.87    200  6913  Integration Server Administrator
b2bsde.att.com   144.160.219.84   200  6913  Integration Server Administrator
```

"Integration Server Administrator" is the **Software AG webMethods Integration Server**
administrative console. Ten of them answer `200` on the public internet, on direct AT&T IP
space (144.160.0.0), with no Akamai in front and no WAF.

webMethods IS is B2B middleware — it moves partner transactions and business documents. An
administrative console for that tier should never be internet-facing.

### What to do

```bash
# Confirm exposure and capture the version banner
curl -s https://b2b.att.com/ | grep -iE "version|webmethods|software ?ag|<title>"
curl -s -I https://b2b.att.com/
```

Version matters: several webMethods IS releases carry published CVEs. A confirmed vulnerable
version on an exposed console is a strong report.

### Do NOT attempt to log in

Not with default credentials, not with anything. The program states:

> You may only exploit, investigate, or target vulnerabilities against your own accounts.

An administrative console is not your account. Succeeding would mean unauthorised access to
AT&T production middleware — beyond the program's authorisation regardless of intent.

**The exposure alone is the report.** "Ten webMethods Integration Server admin consoles are
publicly reachable, unauthenticated to the login page, on production B2B infrastructure" is
complete and defensible with zero login attempts. Let AT&T check the credentials internally.

---

## T2 — 394 KB "404" pages

```
clm-api-hotfix.att.com  404  394819 bytes
clm-api-qa.att.com      404  394819 bytes
docs.att.com            404  266389 bytes
```

A 404 is normally a few hundred bytes. **394 KB** means something is dumping content into the
error path — a stack trace, a config object, a bundled application, an internal route table.

```bash
curl -s https://clm-api-hotfix.att.com/ | head -c 3000
curl -s https://clm-api-hotfix.att.com/ | grep -oiE "(exception|stacktrace|at [a-z.]+\(|internal|password|secret|jdbc:)" | sort -u | head -30
```

Cheap to check, potentially real information disclosure.

---

## T3 — WordPress with pinned, dated plugin versions

```
asecare.att.com   WordPress, Yoast SEO 14.3, PHP, MySQL, jQuery Mobile
offers.att.com    WordPress, Elementor 4.2.4, Contact Form 7 6.1.7, AIOSEO pro 5.0.0.1
get.att.com       WordPress, AIOSEO pro 5.0.1.1, Site Kit 1.186.0
```

**Yoast SEO 14.3 dates to mid-2020.** Current is far ahead. This is the plugin-CVE path that
the earlier hosts never offered, and here the versions are already fingerprinted.

Match each against the WPScan database. Look for **unauthenticated** SQLi, arbitrary file
upload, or RCE — an authenticated-only issue is not usable here.

---

## T4 — Default install pages (unconfigured servers)

```
acssg-tsg.test.att.com   200  Apache2 Ubuntu Default Page   172.203.11.175 (Azure)
darp-jira.test.att.com   200  (1 byte)                      20.122.131.83  (Azure)
hrtd.att.com             200  GlassFish Server - Running    12.43.0.38
lex.att.com              200  Welcome to WildFly            184.26.12.242
```

Default pages mean nobody finished configuring the host. Low severity alone, but they sit
next to management interfaces: GlassFish admin on 4848, WildFly console on 9990, JIRA
unauthenticated endpoints. `darp-jira` is worth a look purely for the name.

---

## Corrections and scope traps

**`localhost.labs.att.com` resolved to 127.0.0.1.** That Apache page is **your own machine**,
not AT&T. httpx connected to your loopback. Not a finding — do not report it. (A public DNS
record pointing at 127.0.0.1 is at most a very low-severity note.)

**`plasma.att.com` is explicitly OUT OF SCOPE.** The program policy states it is temporarily
excluded and reports will be closed as Informative with no bounty. Skip it.

**You appear to be geo-blocked from the authentication tier.** Note the pattern:

```
signin.att.com              402
signin-pre.att.com          402
signin.stage.att.com        402
enterprise-clogin.att.com   402
clcontent.att.com           402
arizona/illinois/michigan/newyork/oregon/utah.att.com   403 "Just a moment..."
```

HTTP 402 across the entire auth estate, plus Cloudflare interstitials on the state sites, is
edge-level blocking of your source IP or region. **The Focus Assets may not be reachable from
where you are testing.** That reshapes strategy: T1–T4 are all reachable, so work those.

---

## Ordering

1. **T1** — capture the webMethods version banner. No login attempts.
2. **T2** — three curls, could be immediate information disclosure.
3. **T3** — Yoast 14.3 against WPScan first.
4. **T4** — only if the above are dry.
