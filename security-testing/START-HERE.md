# Start here — full checklist

Work top to bottom. Do not skip stage 1.

---

## Stage 1 — Permission (do this first, wait for the reply)

- [ ] Find your public IP: visit `whatismyipaddress.com`
- [ ] Email **security@sevdesk.de**:

  > Subject: IP whitelisting request — HackerOne researcher oxel2rsh
  >
  > Hello,
  >
  > I am oxel2rsh on your HackerOne program and would like to begin testing
  > https://my.sevdesk.de. Per your test plan, please whitelist my testing IP:
  >
  > `YOUR.IP.HERE`
  >
  > I will register test accounts under oxel2rsh@wearehackerone.com and send the
  > X-HackerOne-Research: oxel2rsh header on all requests.
  >
  > Thank you,
  > oxel2rsh

- [ ] **Wait for their confirmation.** Their WAF blocks you until this is done. Nothing
      below will work.
- [ ] On HackerOne, click **Show credentials** and claim the program's test credentials
      (currently 0 claimed by you).

---

## Stage 2 — Accounts

- [ ] Account A: sign up at sevdesk.de as `oxel2rsh+test1@wearehackerone.com`
- [ ] Account B: sign up as `oxel2rsh+test2@wearehackerone.com`
- [ ] **Verify they are separate companies (tenants), not two users in one.**
      Create an invoice in A. Log in as B. If B can see A's invoice through the normal UI,
      they are the same tenant — start over. Every later result depends on this.
- [ ] Fill account A with data: 2 contacts, 2 invoices (one draft, one finalised), 1 offer,
      1 receipt with a file attached, 1 bank account. The tool cannot test objects that do
      not exist.

---

## Stage 3 — Automated cross-tenant check

- [ ] Log in as account A. Press **F12** → **Network** tab → tick **Preserve log**.
- [ ] Click through the app: invoice list, open an invoice, view its PDF, open a contact,
      download a receipt. Every feature you touch becomes a test case.
- [ ] Right-click the request list → **Save all as HAR with content** → `session.har`
- [ ] Check which host the requests go to. If they go to `api.sevdesk.de` rather than
      `my.sevdesk.de`, use that in the next command or everything gets filtered out.

```bash
cd security-testing/tools
pip install requests

python3 har_to_config.py session.har --host my.sevdesk.de --h1-username oxel2rsh -o config.json
```

- [ ] Open `config.json`. Delete any group you do not care about — each one costs requests.
      Any group marked `CHANGE-ME` needs a list URL or should be deleted.
- [ ] Get both cookies: **F12 → Application → Cookies**, copy the whole cookie string.

```bash
export ACCT_A_COOKIE='paste test1 cookie here'
export ACCT_B_COOKIE='paste test2 cookie here'

python3 authz_diff.py --config config.json --dry-run      # check the plan, sends nothing
python3 authz_diff.py --config config.json --out ../evidence/run1
```

- [ ] Read `evidence/run1.md`.
- [ ] **Reproduce every `CONFIRMED` and `CRITICAL` by hand in a browser.** The policy
      rejects reports based on unverified tool output. A tool match is a lead, not a finding.
- [ ] Delete `session.har` when finished — it contains your session cookies.

---

## Stage 4 — Manual testing (where the real money is)

The tool covers one bug class. These are by hand. Full detail in `TEST-PLAN.md`.

**Stored XSS — explicitly in scope**
- [ ] Put `{{7*7}}` in a contact name, company name, invoice line description, tag name.
      Save, then view the page. If `49` appears, that is AngularJS template injection.
- [ ] Escalate: `{{constructor.constructor('alert(1)')()}}`
- [ ] Check whether the payload reaches a user in the *other* tenant. That changes CVSS
      Privileges Required from High to None.

**Cross-client access — explicitly in scope**
- [ ] On create/update requests, add fields the UI never sends: `sevClient`, `id`, `role`,
      `objectName`. Try setting `sevClient` to account B's tenant ID. Writing an object
      into another tenant is a cross-client finding.
- [ ] Try `?embed=` with objects belonging to the other tenant.

**Business logic — in scope, and least picked over**
- [ ] Finalise an invoice, then modify its amount or date via the API instead of the UI.
      German accounting records must be immutable (GoBD). If it changes, that is a real
      integrity bug.
- [ ] Force a duplicate invoice number. Force a gap. Set a negative number.
- [ ] Negative quantity, negative price, discount over 100%, tax rate the UI does not offer.
- [ ] Send line items and a total that disagree — is the total recomputed server-side?

**Do NOT test (out of scope — wasted reports)**
- [ ] ~~PDF renderer SSRF / iframe / file:// injection~~ — documented intended behaviour
- [ ] ~~Add-ons, plan limits, trial extension, anything paid~~
- [ ] ~~Email enumeration~~
- [ ] ~~Admin API access inside your own tenant with no financial impact~~

---

## Stage 5 — Report

- [ ] One issue per report.
- [ ] Use `REPORT-TEMPLATE.md`.
- [ ] Always state whether it works cross-tenant — it multiplies the payout.
- [ ] Say what you did NOT do: "confirmed with GET, did not attempt modification or deletion
      of the other tenant's data."
- [ ] Include full reproduction steps. The policy rejects reports that cannot be reproduced.

---

## Reality check

71 reports in 90 days, 7 resolved ever, $5,000 paid lifetime, 0% ever paid at High severity.
The easy findings on this asset are gone. Duplicates are your main risk.

Your best odds are Stage 4 business logic — it requires understanding how German accounting
actually works, which is why most people skip it.
