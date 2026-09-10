# Meridian Operations Portal — Data Import

The Catalog → Data Import screen and the endpoint behind it. An operator pastes
a supplier catalog XML feed, and the parsed product records come back for
review.

Importing is a **preview** step: the endpoint parses and validates a document
and returns what it found. Nothing is written to the catalog.

## Running it

```bash
cd portal
python3 -m pip install -r requirements.txt
python3 app.py            # http://127.0.0.1:5000/catalog/import
```

`app.py` runs Flask's development server. Behind a real deployment, serve
`app:app` with a WSGI server and keep the body-size limit enforced at the proxy
as well.

## Tests

```bash
cd portal
python3 -m pytest tests -q
```

The suite covers the parser and the endpoint, including the rejection cases
listed below.

## The endpoint

`POST /api/catalog/import`, body is the XML document, content type
`application/xml` (`text/xml` and `application/*+xml` are also accepted).

```xml
<catalog>
  <product>
    <name>Sample Product</name>
    <sku>SKU-1</sku>
    <note>imported</note>
  </product>
</catalog>
```

```json
{
  "status": "ok",
  "note": "Preview only -- no records were written to the catalog.",
  "received_bytes": 124,
  "imported": 1,
  "skipped": 0,
  "records": [
    {"name": "Sample Product", "sku": "SKU-1", "note": "imported", "position": 1}
  ],
  "problems": []
}
```

`status` is `ok`, or `partial` when some records were skipped. A document that
cannot be accepted at all returns `4xx` with
`{"status": "rejected", "error": "..."}`.

| Status | Meaning |
| --- | --- |
| 200 | Parsed. `records` holds what was accepted, `problems` what was skipped. |
| 400 | The document was rejected — malformed, wrong shape, or using a refused XML construct. |
| 413 | The body exceeds the size limit. |
| 415 | The content type is not XML. |

## Handling of supplier documents

A supplier feed is input from outside the organisation, so it is parsed as
hostile input. Parsing goes through `defusedxml` with `forbid_dtd`,
`forbid_entities` and `forbid_external` all set, which rejects a document
carrying:

- an entity that reads a local file (`file:///etc/passwd`) or reaches a network
  address — XML external entity (XXE) disclosure and SSRF;
- a nested entity chain that expands to exhaust memory — "billion laughs" and
  quadratic blowup;
- a reference to an external DTD or any other external document;
- any document type declaration at all, including a bare `<!DOCTYPE catalog>`.

Note that `defusedxml`'s defaults leave `forbid_dtd` **off**; the call in
`catalog_import.py` sets it explicitly.

Alongside parsing:

- The body is capped at 1 MiB, enforced both by Flask's `MAX_CONTENT_LENGTH`
  (before the body is read) and by the parser (for callers that do not come
  through Flask).
- A document may hold at most 500 records, and a single field at most 512
  characters.
- Rejection messages describe the document, never the server's environment; the
  contents of a file an entity tried to reach can never appear in a response.
- Records reach the browser as JSON string values, written to the page through
  `textContent`. Responses carry `X-Content-Type-Options: nosniff` so the JSON
  cannot be content-sniffed into markup, plus `X-Frame-Options: DENY`,
  `Referrer-Policy: no-referrer`, and a `Content-Security-Policy` of
  `default-src 'self'` with no `unsafe-inline` — which is why the page's script
  and styles live in `static/` rather than inline.

Records that are individually invalid do not sink the document: they are left
out and reported under `problems`, so a mostly-good feed still previews.
Skipped records are those missing `<name>` or `<sku>`, repeating an earlier SKU
(compared case-insensitively), or carrying an over-long field.

## Layout

```
portal/
├── app.py               routes, response headers, request limits
├── catalog_import.py    document parsing and validation
├── templates/           base shell, the import page, placeholders
├── static/              stylesheet, page script, favicon
└── tests/               parser and endpoint tests
```

Only Data Import is built out. The other sidebar entries resolve to a
placeholder page so the shell navigates coherently.
