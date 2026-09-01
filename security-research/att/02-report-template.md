# HackerOne report template — AT&T

Fill this in **only once you have a working PoC**. Everything in angle brackets is a blank
you must replace with something you actually observed.

---

**Title:** `<Vulnerability class> on acenpw.att.com allows <concrete attacker outcome>`

Good: `Unauthenticated SQL injection in <plugin> on acenpw.att.com allows database read`
Bad: `Vulnerability found in AT&T subdomain`

**Asset:** `acenpw.att.com` (falls under *Other Assets*, in scope, bounty eligible)

**Weakness:** `<CWE, e.g. CWE-89 SQL Injection>`

**Severity:** `<Low / Medium / High / Critical>` — with CVSS vector

---

## Summary

Two or three sentences. What is broken, where, and what an attacker gets from it. State the
impact in the first sentence, not the last.

## Steps to reproduce

Numbered, exact, copy-pasteable. A triager must reproduce this without asking you anything.

1. `<step>`
2. `<step>`
3. `<observed result>`

Include the full request and response:

```http
GET /<path> HTTP/1.1
Host: acenpw.att.com

```
```http
HTTP/1.1 <code>
<relevant response>
```

## Impact

The section that determines your payout. Be concrete and bounded:

- What data or functionality is exposed
- Who can trigger it — unauthenticated attacker? any logged-in user?
- What an attacker does with it in practice
- Any chain into a Focus Asset (`signin.att.com`, `identity.att.com`, `att.com/msapi`,
  `att.com/acctmgmt/`, `att.com/buy/`, `myattwg.att.com/olam/`, myATT apps) — say so
  explicitly and loudly, this is what raises severity

Do not inflate. Triagers downgrade overstated impact, and it costs you credibility on
every future report.

## Proof of concept

- **Video PoC is mandatory for High and Critical.** Screen recording, narrated or captioned,
  showing the full reproduction end to end.
- Screenshots for Medium and below.
- Redact any third-party data that appears.

## Remediation

One short paragraph. Optional, but it reads as competent and speeds triage.

---

## Pre-submit checklist

- [ ] I have a working PoC, not a hypothesis
- [ ] The finding is not on AT&T's exclusion list
- [ ] Video PoC attached (required if High/Critical)
- [ ] All testing was against accounts I own
- [ ] No customer or employee data accessed — or, if inadvertently accessed, declared above
- [ ] Not disclosed anywhere else
- [ ] Impact statement is specific and honest
- [ ] Steps reproduce cleanly from a fresh session

**Submit at:** https://hackerone.com/att
