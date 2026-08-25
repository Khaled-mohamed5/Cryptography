# sevDesk — Authorization & Application Logic Test Plan

Target asset: `https://my.sevdesk.de` (HackerOne private program, critical max severity).

sevDesk is a German cloud accounting platform. That shapes where the bugs are. It is
multi-tenant (`SevClient`), it has a documented REST API (`/api/v1/...`) with an object
model that the web UI itself consumes, it renders user-controlled content into PDFs and
outbound email, it exports to third-party tax software (DATEV), and it is subject to
**GoBD** — the German regulation requiring booked accounting records to be immutable and
sequentially numbered. That last point matters more than it looks: on most SaaS, editing
your own finalized record is a shrug. Here it is a compliance-relevant integrity bug, and
programs in this space tend to pay for it.

Work the classes in this order. It is descending order of expected value for this
particular target, not the order they appear in OWASP.

---

## 0. Before you send a single request

- [ ] Read the program policy in full. Note the rate-limit rule, the automated-scanning
      rule, and whether self-registered accounts are permitted (some programs require you
      to claim their issued test credentials — the program page shows
      "1 asset with credentials, 0 claimed by you").
- [ ] Set an identifying header on **every** request so the vendor's SOC can attribute your
      traffic and not page someone at 03:00: `X-Bug-Bounty: <your-h1-username>`.
      The harness in `tools/` does this for you.
- [ ] **Register both test accounts under your HackerOne alias**, not a personal address:
      `<your-h1-username>@wearehackerone.com`, which forwards to your real inbox. Several
      programs require this and will close reports filed from unattributable accounts;
      beyond the rule, it makes the accounts self-identifying as researcher accounts, so
      the vendor's team can tell your tenant apart from a real customer's at a glance. Use
      sub-addressing (`+a`, `+b`) if you need the two registrations to differ.
- [ ] Register account **A** and account **B** as two separate tenants. Confirm they are
      separate `SevClient`s, not two users inside one tenant — cross-tenant is the finding
      that pays; cross-user-inside-one-tenant is usually intended behaviour.
- [ ] Inside tenant A, create a **second, lower-privileged user** (employee role) and, if the
      product offers it, a **tax advisor** grant. These are your privilege-escalation subjects.
- [ ] Populate A with real-looking objects: 2 contacts, 2 invoices (one draft, one booked),
      1 offer, 1 receipt/voucher with an uploaded file, 1 bank account, 1 inventory part.
      You cannot test authorization on objects that do not exist.
- [ ] Never test destructive operations on anything but your own objects. `DELETE` against a
      cross-tenant ID proves the bug by destroying someone's accounting record — prove it
      with `GET` instead and say in the report that you did not attempt the write.

---

## 1. IDOR / cross-tenant object access — highest value here

The API is object-oriented with predictable integer IDs and the UI calls it directly, so
every object type is a candidate. The pattern is always the same: create the object as A,
note its ID, request it as B, and as nobody.

### Object types to enumerate
`Contact`, `ContactAddress`, `CommunicationWay`, `Invoice`, `InvoicePos`, `Order` (offers),
`OrderPos`, `Voucher`, `VoucherPos`, `CreditNote`, `CheckAccount`,
`CheckAccountTransaction`, `Part` (inventory), `SevUser`, `Tag`, `Report`, `Export`,
`DocumentFolder` / uploaded receipt files.

### The mistakes that actually get made
Do not just test `GET /api/v1/Invoice/{id}`. That is the one endpoint the developers
remembered to protect. Test the *other representations of the same object*, which is
where the check gets skipped:

| Surface | Why it breaks |
|---|---|
| `GET /api/v1/Invoice/{id}/getPdf` | PDF renderer often takes a different code path with its own (missing) check |
| `sendViaEmail` / `sendByWithRender` | Mailer resolves the object before authorizing it |
| `?embed=contact,contactPerson,sevClient` | **The single highest-yield parameter on this API.** The parent may be authorized while the *embedded* child is fetched by raw ID with no check. Try embedding across tenants. |
| `?sevQuery[...]` filters | Filter may run before the tenant scope is applied |
| Bulk / batch endpoints | Per-item authorization frequently omitted in the loop |
| File download by document ID | Static-ish handler, commonly unprotected |
| Public "view invoice online" share links | Check token entropy — if it is the object ID, a hash of it, or sequential, that is a pre-auth leak of every invoice on the platform |
| Report / `Export` generation by ID | Export jobs often trusted because "you must have had access to create it" |

### Classification
- B receives **byte-identical content** to A → confirmed cross-tenant IDOR. Critical.
- B receives **200 with different content** → probably B's own object; do not report yet, verify.
- Unauthenticated receives 200 → pre-auth data exposure. Higher severity than the authed case.
- `403`/`404` → correctly denied. A `404` that differs in timing or body from a genuinely
  nonexistent ID is a minor enumeration oracle — low, usually informational, but note it.

`tools/authz_diff.py` automates exactly this loop, GET-only, rate-limited.

---

## 2. Broken access control — role and privilege boundaries

Distinct from IDOR: here the object is inside your tenant but your *role* should not reach
the operation.

- [ ] **API token vs. UI session.** Generate an API token as the low-privileged employee user.
      Then call admin-only operations with it. A very common failure: role checks are
      enforced in the web front end / session middleware and skipped entirely for token auth.
      This alone is worth the whole session if it lands.
- [ ] **Vertical escalation via the invite flow.** Invite a user and tamper with the role field
      in the request (`role`, `sevUserRole`, `permissions[]`, a nested object). Then accept the
      invite and check the effective role. Also try re-sending an invite with an elevated role,
      and editing your *own* user record to raise your role.
- [ ] **Tax advisor scope.** The advisor grant is a deliberate cross-tenant bridge, which makes
      it the most interesting authorization surface in the product. Once A grants advisor access
      to B: can B write where it should only read? Can B reach objects outside the booking data
      (bank credentials, users, subscription/billing)? Does revoking the grant actually kill B's
      existing sessions and API tokens, or does the revocation only hide the UI entry point?
- [ ] **Function-level auth on every mutating verb.** For each object type, as the employee role:
      `POST` create, `PUT` update, `DELETE`. Do not assume the UI hiding a button means the
      endpoint is protected.
- [ ] **Session lifecycle.** After a password change, are old sessions invalidated? After 2FA is
      enabled, are pre-2FA sessions? After a user is removed from a tenant, do their tokens die?
- [ ] **Account-takeover chain.** Can email or password be changed without re-entering the current
      password? Combine with any stored XSS from §3 and you have a full ATO — write it up as the
      chain, not as two separate lows.

---

## 3. XSS and injection into rendered output

Reflected XSS on a SaaS dashboard is usually low. On this target the interesting sinks are
**stored** and they are **not the browser**.

- [ ] **Stored XSS in tenant data rendered to other users.** Contact name, company name, invoice
      line-item description, invoice header/footer free text, custom field values, tag names,
      uploaded receipt filename, bank transaction memo. Payload fires for the *other users in the
      tenant* and, via the advisor grant, potentially across tenants — say so in the impact
      section, it raises severity.
- [ ] **HTML injection into the PDF renderer — check this properly.** Invoices are user-templated
      HTML converted to PDF server-side. If a headless browser or `wkhtmltopdf` renders your
      input, then injected markup runs *on the server*, not in a victim's browser:
      - `<iframe src="file:///etc/passwd">` → local file read
      - `<img src="http://169.254.169.254/latest/meta-data/iam/security-credentials/">` → cloud
        metadata SSRF → credential theft
      - `<link rel=stylesheet href="http://your-collab/">` → blind SSRF confirmation
      Generate the PDF and *open it* — a file-read shows up as text in the rendered document.
      This is the single highest-severity thing on this list. It is a critical, not a medium.
- [ ] **SSRF via logo / template asset URL.** Anywhere the product accepts a URL for a company
      logo or template resource, point it at internal ranges and at your collaborator.
- [ ] **HTML injection into outbound email.** Invoices are emailed to customers from sevDesk's
      infrastructure. Injection there is a phishing primitive sent from a trusted domain with
      the vendor's SPF/DKIM. Also test header injection via the recipient/subject fields.
- [ ] **CSV / formula injection into DATEV and CSV exports.** Put `=cmd|'/c calc'!A1`,
      `@SUM(1+1)*cmd|...`, `+`/`-`/`=` prefixed values into any exported field. The victim here is
      the *tax advisor* opening the export in Excel. Programs sometimes rate this informational —
      argue impact via the advisor workflow, which is a first-class product feature, not a stretch.
- [ ] **SVG upload.** If receipt upload accepts SVG and serves it from the app origin rather than a
      sandboxed domain, that is stored XSS on the main origin.
- [ ] **Filename and path handling on receipt upload.** `../` traversal, null bytes, double
      extensions, `.html`/`.svg` content-type confusion.

---

## 4. Business logic — where an accounting product is uniquely exposed

This is the class most hunters skip and where this target is most likely to yield something
original.

- [ ] **GoBD immutability.** Book/finalize an invoice, then try to modify it via the API rather
      than the UI: change the amount, the date, the line items, the recipient. If a booked invoice
      is mutable, that is an accounting-integrity bug with a regulatory angle — lead the report
      with GoBD, not with "I edited a field".
- [ ] **Invoice number sequence.** Force a duplicate number. Force a gap. Set a number lower than
      an existing one. Set a non-numeric or negative number. Sequential gapless numbering is a
      legal requirement, so breaking it is a real finding rather than a cosmetic one.
- [ ] **Arithmetic manipulation.** Negative quantity, negative unit price, negative discount,
      discount > 100%, quantity `1e308`, quantity `0.1 + 0.2` rounding abuse, tax rate set to a
      value the UI does not offer (`-19`, `999`). Check whether the stored total is recomputed
      server-side or trusted from the client — send a request where the line items and the
      submitted total disagree.
- [ ] **Currency.** Change currency after totals are computed. Mix currencies across line items.
      Check whether the exchange rate is client-supplied.
- [ ] **Subscription and plan limits.** Whatever the plan caps — invoice count, user seats, bank
      connections, storage — hit the cap in the UI, then create one more directly via the API.
      Limits enforced only in the front end are a classic and are usually accepted as a medium.
- [ ] **Trial abuse.** Can the trial be extended by resetting a field, re-registering with a `+`
      alias, or changing the tenant creation date?
- [ ] **State-machine skipping.** Draft → sent → paid → cancelled. Try each illegal transition
      directly: mark paid without sending, un-cancel a cancelled invoice, pay a draft, reopen a
      closed accounting period, book into a locked fiscal year.
- [ ] **Bank reconciliation.** Can a transaction be matched to an invoice belonging to another
      tenant? Can a transaction amount be edited after import so the books balance falsely?
- [ ] **Race conditions.** Send the same "mark as paid", "book invoice", or "assign invoice number"
      request concurrently (20+ parallel). Duplicate invoice numbers or double-booking from a race
      is a strong finding. Use a single burst, then stop — do not sustain it.

---

## 5. SQL injection

Lowest expected yield on a mature API of this kind, but the query-builder parameters are the
credible surface because they are string-assembled far more often than the ORM paths are.

Candidate parameters: `sevQuery[...]`, `orderBy`, `sort`, `order`, `embed`, `depth`, `limit`,
`offset`, `filter`, `search`, and any report/export date-range or grouping parameter.

Probe order:
1. Error-based first — a single `'` and a `\`. Look for a 500 or a driver error string.
2. Boolean differential — `orderBy=id` vs `orderBy=(select 1)` vs `orderBy=1,1`.
3. Time-based **last, and carefully**. Use a 5-second sleep, not 30. One confirmation, then stop.
   Do not run `sqlmap` against production unless the policy explicitly allows automated tooling —
   its default tamper/threading profile is exactly what gets a researcher banned.

Also check NoSQL/ORM operator injection in JSON bodies (`{"id": {"$ne": null}}`,
`{"id": {"gt": 0}}`) — on a query-builder API that is often the more realistic variant.

---

## 6. Report quality

For this program specifically:

- **Impact in tenant terms.** "I read invoice 88213 belonging to a different company, including
  their customer's name, address and bank details" beats "IDOR found". Name the GDPR exposure
  explicitly — it is a German target and personal financial data is Article 9-adjacent.
- **Two accounts, both yours, both named.** State the IDs of both test tenants so triage can
  reproduce without guessing.
- **Say what you did not do.** "I confirmed read access with GET and deliberately did not attempt
  DELETE or modification against the victim tenant." This materially improves how triage receives
  a cross-tenant report.
- **Chain the lows.** Stored XSS + no re-auth on email change = account takeover. Filed separately,
  they are two mediums that may both get closed as informational.
- **One issue per report.** Do not bundle.

Template: `REPORT-TEMPLATE.md`.
