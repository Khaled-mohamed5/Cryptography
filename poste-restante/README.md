# POSTE RESTANTE — a blind dead-drop board

Leave a message under a cover name, dress the envelope in your own CSS, and
never meet the courier who picks it up. No accounts, no email, no password:
a drop belongs to whoever holds the cookie that left it.

```
python3 app.py                 # http://127.0.0.1:8080
python3 -m unittest discover -s tests -t tests
```

Python 3.9+ and nothing else — no pip install, no framework, no build step.
The station keeps its SQLite database and signing key in `data/`, created on
first run.

## The station

| Route | What happens |
| --- | --- |
| `GET /` | The counter: compose a drop, and the ledger of drops this handle left |
| `POST /post` | Sanitize and file a drop, then redirect to it |
| `GET /d/<id>` | Pickup view: the envelope, its manifest, and the flag form |
| `GET /d/<id>/envelope` | The envelope itself — what the sandboxed frame loads |
| `POST /d/<id>/flag` | One report per courier; `SEAL_THRESHOLD` of them withhold the drop |

A **handle** is an opaque 16-hex-character id in an HMAC-signed, `HttpOnly`,
`SameSite=Lax` cookie. It is the whole identity system. It decides which drops
appear in your ledger, which drops you can still read after they are sealed,
and it is the CSRF token's basis. It is never shown, never asked for, and maps
to nothing else.

**Pickups** count distinct handles that opened a drop, excluding its author:
re-reading is not re-collecting, and previewing your own drop is not a pickup.

## What the station will not carry

Every drop is written by a stranger and read by a stranger, and the station
vouches for neither. Two independent layers stand between them, and neither is
trusted to be complete on its own.

**Sanitizing, on the way in** (`sanitize.py`, exercised by
`tests/test_sanitize.py`):

- Markup is reduced to an allowlist of text tags. Event handlers, `<script>`,
  `<style>`, `<form>` and framing tags are dropped with their contents;
  unknown tags are unwrapped so stray markup degrades to plain text.
- `href` accepts only `http`, `https`, `mailto` and fragments, after control
  characters and exotic whitespace are stripped — `java\nscript:` is a live
  scheme in a browser, so it is not a live scheme here. Surviving links get
  `rel="nofollow noopener noreferrer ugc"`.
- **Nothing may name a remote URL.** No `<img>`, no `<video>`, no `url()`, no
  `@import`, no `@font-face`. A drop that can fetch is a drop that reports
  every reader's IP back to whoever left it, and a *blind* dead drop cannot do
  that.
- CSS is parsed, not regex-scrubbed: properties come from an allowlist, every
  `name(` in a value must be a known-safe function, and `@media`, `@supports`
  and `@keyframes` are the only at-rules that survive. `expression()`,
  `behavior`, `-moz-binding` and backslash escapes are rejected outright.
- Sanitized CSS is emitted inside a `<style>` element — a raw-text context that
  ends at `</style`. No `<` survives sanitizing, enforced as a property of the
  output rather than of three separate regexes staying correct.

**The sandbox, on the way out** (`app.py`):

- The envelope renders in an iframe with `sandbox="allow-popups
  allow-popups-to-escape-sandbox"`. No `allow-scripts`, so nothing in it can
  execute; no `allow-same-origin`, so it holds an opaque origin and cannot
  reach the station's cookies or DOM.
- Its `Content-Security-Policy` is `default-src 'none'` with styles as the only
  exception: even if a URL slipped past the sanitizer, the browser refuses the
  request.
- Station pages get their own strict policy and no inline styles at all, so
  `style-src` can stay `'self'` without `'unsafe-inline'`. A regression test
  keeps it that way.

**Abuse.** Any courier can flag a drop, once. `SEAL_THRESHOLD` (3) independent
reports seal it: strangers get a placeholder and the envelope endpoint returns
`410 Gone`. The author can still read what they wrote. Reports are stored with
their reason for a human to review:

```sh
sqlite3 data/station.db \
  "SELECT d.id, d.title, COUNT(f.reporter) AS reports, GROUP_CONCAT(f.reason, ' | ')
   FROM drops d JOIN flags f ON f.drop_id = d.id GROUP BY d.id ORDER BY reports DESC;"
```

**Rate limits.** 20 posts per five minutes per client address, 30 drops per
hour per handle, and hard caps on title (80), message (20 000) and cipher
(8 000) characters.

**Logs.** Request logs carry no client addresses. An anonymous board that keeps
an access log keyed by IP is not an anonymous board.

## Running it somewhere real

```sh
python3 app.py --host 0.0.0.0 --port 8080 \
    --data-dir /var/lib/poste-restante \
    --secure-cookies --trust-proxy
```

- `--secure-cookies` adds `Secure` to the handle cookie; required behind HTTPS.
- `--trust-proxy` reads the client address from `X-Forwarded-For`. Only set
  this when a proxy you control actually sets that header — otherwise every
  client can forge its own rate-limit bucket.
- `POSTE_RESTANTE_SECRET` supplies the signing key instead of `data/secret.key`
  (share it across processes, or every handle stops verifying).

Rotating the secret invalidates every cookie: the drops remain, but no one can
prove they own them any more.

## Known limits

- The envelope frame has a fixed height with a drag handle. Nothing inside it
  can run scripts, so nothing inside it can report its own height — that is the
  trade, and it is the right way round.
- Rate-limit buckets live in memory, so they reset on restart and are per
  process.
- A client that discards cookies gets a fresh handle per request and inflates a
  drop's pickup count.
- There is no delete. A drop stays until a courier removes it from the database.
