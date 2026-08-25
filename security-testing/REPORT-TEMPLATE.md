# Report template

One issue per report. Chain related lows into a single report only when the chain is the
impact (e.g. stored XSS + no re-auth on email change = account takeover).

---

## Title

`<Vulnerability class> in <specific feature> allows <specific impact>`

Good: `IDOR in invoice PDF endpoint allows any authenticated user to read invoices of
other tenants`
Bad: `IDOR vulnerability found`

## Summary

Two or three sentences. What the flaw is, where it is, and what an attacker gets. Written
so a triager who has never seen your report can decide severity from this paragraph alone.

## Test accounts

State both, so triage can reproduce without guessing:

- **Tenant A (attacker):** `<h1username>@wearehackerone.com` — tenant/client ID `______`
- **Tenant B (victim):** `<h1username>+b@wearehackerone.com` — tenant/client ID `______`

Both accounts are mine, registered for this program.

## Steps to reproduce

Numbered, literal, and complete. Assume the reader has your two accounts and nothing else.

1. Log in as tenant A.
2. Create an invoice. Note its ID (`______`).
3. Log out; log in as tenant B.
4. Send:
   ```http
   GET /api/v1/Invoice/<A's invoice id>/getPdf HTTP/1.1
   Host: <target>
   Cookie: <tenant B's session>
   ```
5. Observe: tenant B receives tenant A's invoice PDF.

Include the full request and the relevant part of the response. Redact your own session
token. Redact any third party's personal data — describe what fields were exposed rather
than pasting a real customer's address.

## Impact

The part that decides your bounty. Write it in the vendor's terms, not the scanner's.

- What data or capability crosses the boundary — name the actual fields (customer names,
  addresses, bank details, tax IDs, revenue figures).
- Who can do it — any registered user? Unauthenticated? Requires an existing relationship?
- Scale — one record, or every record on the platform? Are IDs sequential, so enumeration
  is trivial?
- For a German/EU target: state the GDPR exposure explicitly. Financial records of
  identifiable natural persons are personal data, and a cross-tenant read is a reportable
  breach for the vendor.
- For an accounting product: if the bug affects record integrity or invoice numbering, say
  **GoBD** and explain the compliance consequence. That reframes "I edited a field" as an
  auditability failure, which is what it actually is.

## Scope of testing performed

State this explicitly — it materially improves how a cross-tenant report is received:

> I confirmed read access using `GET` only. I deliberately did not attempt to modify or
> delete any record belonging to the victim tenant, and I did not access any tenant other
> than the two test accounts listed above. Total requests sent: `___`, rate-limited to
> `___`/second. All requests carried the header `X-HackerOne-Research: <h1username>`.

## Suggested remediation

Brief and concrete. For IDOR: enforce the tenant scope in the data-access layer rather
than per-controller, so new endpoints inherit the check instead of each one having to
remember it. Name the specific endpoint variants that were missing it — the PDF renderer,
the `embed` expansion — since those are the ones that got skipped the first time.

## Supporting material

Screenshots, HTTP logs, a short video. Keep the evidence files out of version control —
`evidence/` is gitignored for that reason.
