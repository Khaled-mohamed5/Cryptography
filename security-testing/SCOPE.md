# Program rules — read before testing

Distilled from the sevDesk program policy (overview last updated 2025-07-10, scope
2025-02-12). **The policy on HackerOne is authoritative.** Re-check it before each session;
this file is a working summary, not a substitute.

---

## Blocking prerequisites

These are gates, not suggestions. Do them before sending any traffic.

- [ ] **Get your IP whitelisted.** The policy: *"Researchers must contact us to have their IP
      whitelisted before testing to avoid being blocked by our WAF."* Email
      **security@sevdesk.de** with the source IP you will test from and wait for
      confirmation. Testing before this both breaks the rules and simply will not work —
      the WAF blocks you.
- [ ] **Claim the program's test credentials** on HackerOne (the program page shows
      *1 asset with credentials, 0 claimed by you*).
- [ ] **Use your hacker alias for every account:** `oxel2rsh@wearehackerone.com`, and
      `oxel2rsh+<tag>@wearehackerone.com` for additional users. Trial accounts registered
      through the website are explicitly permitted.
- [ ] **Set the header the program asks for on every request:**
      `X-HackerOne-Research: oxel2rsh`. The tooling in `tools/` enforces this.

Because the WAF whitelist is tied to a specific source IP, all testing has to run from the
machine you registered. Traffic from anywhere else is blocked and unattributable.

---

## Out of scope — do not spend time here

| Excluded | Consequence for testing |
|---|---|
| **PDF generation & invoice custom layouts** | Embedding external resources via `<img>`, `<iframe>`, fonts and files, and making HTTP requests, is **intended behaviour**. SSRF and similar issues caused by external content loading through these features are explicitly excluded. |
| **Add-ons and any paid feature** | `https://my.sevdesk.de/admin/addons` is off limits, on both supplied credentials and self-created trials. Any feature behind payment is out of scope — this kills plan-limit and subscription-bypass testing. |
| **Third-party services** | Unless the issue directly impacts sevDesk users through sevDesk's own systems. |
| **Automated scanner output** | Reports without manual verification and demonstrated impact are rejected outright. |
| **Email enumeration** | Login and trial signup both reveal whether an email is registered. Intentional; trial accounts do not require email verification. |
| **Non-critical admin API access within your own client** | Authenticated users reaching admin-only API actions *inside their own tenant* with **no financial impact**. See the carve-outs below — they matter. |
| Core Ineligible Findings | HackerOne's standard exclusion list. |

### The carve-outs that keep things in scope

The same-tenant admin-API exclusion explicitly **does not apply** to:

1. **Cross-client access** — anything crossing a tenant boundary.
2. **Unauthenticated access** — without any token or `cft`.
3. **Stored XSS.**
4. **Impersonation attacks.**

Those four are the program telling you where it will pay. Everything in this kit should be
aimed at them.

Note also the "no financial impact" qualifier on the exclusion: a same-tenant admin action
that *does* have financial impact is not excluded by its terms.

---

## How severity is scored

The policy gives explicit CVSS guidance, and it drives the payout:

| Attack needs | Privileges Required | Effect |
|---|---|---|
| A user in the **same** client/tenant | **High** | Suppressed score |
| A user from a **different** client/tenant | **None** | Much higher score |

So the same underlying bug is worth several times more when demonstrated across tenants.
When you find something, always check whether it reproduces cross-tenant before writing it
up — and demonstrate it that way if it does.

| Severity | Bounty | Share of resolved reports |
|---|---|---|
| Low | $150 | 28.57% |
| Medium | $500 | 42.86% |
| High | $1,500 | 0% |
| Critical | $3,000 | 28.57% |

Nothing has ever been paid at High, and the split is barbell-shaped — lows and criticals.
Reads as: marginal findings get graded down to low, and only clear, high-impact ones clear
the bar. Depth beats volume here.

---

## Conduct rules

- One vulnerability per report, unless a chain is needed to show impact.
- Detailed, reproducible steps — the policy states unreproducible reports are not rewarded.
- Only interact with accounts you own or have explicit permission for.
- No social engineering (phishing, vishing, smishing).
- Good-faith effort to avoid privacy violations, data destruction, and service degradation.
- Ask the program before submitting on unscoped subdomains.
- Private program: **do not discuss it publicly**, including resolved issues.

---

## Competitive picture

71 reports received in 90 days, 7 resolved in total, 11 hackers thanked, $5,000 paid
lifetime. Response efficiency 62%.

High report volume against a single asset that has been open since Feb 2025 means the
obvious surface is picked over. Duplicates are the main risk to your time — the shallow
IDOR checks on primary objects have almost certainly been submitted already. The value is
in the endpoint variants and the logic bugs that require actually understanding the
accounting domain.

---

## Stack (from the scope page)

`Kotlin | Spring Boot | JavaScript/TypeScript | Angular.js | React | HTML5 | CSS3 | REST |
Docker | SQL | NoSQL | PostgreSQL | AWS | Helm | Terraform`

What that implies:

- **Angular.js** (AngularJS 1.x, not modern Angular) — client-side template injection is a
  live vector on this stack, and stored XSS is explicitly in scope. See §3 of the test plan.
- **Spring Boot** — check for exposed actuator endpoints, and test mass assignment: Jackson
  binds JSON fields to objects, so try submitting fields the UI never sends (`id`,
  `sevClient`, `role`, `create`, `objectName`).
- **PostgreSQL behind an ORM** — direct SQLi is unlikely in the JPA paths; the credible
  surface is anywhere a filter, sort or query-builder parameter is string-assembled.
- **NoSQL alongside SQL** — operator injection (`{"$ne": null}`) is worth testing in JSON
  bodies.
