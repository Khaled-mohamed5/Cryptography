# Sample analysis — Burp Suite DOM Invader injected script

## Identification

The obfuscated script is the content script that **Burp Suite's DOM Invader**
injects into every page of its embedded browser. The decisive evidence is
mechanical, not circumstantial — decoding the string array yields:

| encoded entry | plaintext |
|---|---|
| `qNvYCerptuLUDMfKzxi` | `BurpDOMInvader` |
| `ChjVDg90ExbLihbVBgX1DgLVBJO` | `prototype pollution:` |
| `y29UC3rYDwn0B3iUChjVDg90ExbLlNbYB3bLCNr5pxzHBhvL` | `constructor.prototype.property=value` |

and the script reads its configuration from `window.localStorage`, registers a
`window.BurpDOMInvader` object, and reports findings by dispatching a
`CustomEvent` on `document` — the standard extension ⇄ page bridge.

It is **defensive tooling**: a DOM-XSS / web-message / prototype-pollution
scanner that instruments a page it is deliberately loaded into.

See [`decoded-strings.txt`](dom-invader/decoded-strings.txt) for 113
machine-verified plaintext recoveries (re-checkable with
`node dom-invader/verify-strings.js`) and [`sinks.json`](dom-invader/sinks.json)
for the sink table.

## Obfuscation parameters

Produced by **javascript-obfuscator (obfuscator.io)**, high preset. Concrete
values recovered from this sample:

| Component | Value |
|---|---|
| String-array function | `a4_0x2128` |
| Decoder function | `a4_0x5998` |
| Index offset | `0x136` (subtracted inside the decoder) |
| Encoding | base64 over `abc…xyzABC…XYZ0-9+/=` → UTF-8 bytes → `decodeURIComponent` |
| Self-defending rotation | `push(shift())` until a `parseInt` checksum equals `0xa6a0f` |
| Alias in the main IIFE | `_0x395d81(a, b) → a4_0x5998(b - 0x2e5, a)`, i.e. array index `b - 0x41b` |
| Alias in the rotation IIFE | `_0x13351f(a, b) → a4_0x5998(b + 0x1a9, a)`, i.e. array index `b + 0x73` |
| Dispatcher object | `_0x4977b3` (~1,500 constant + operator-proxy entries) |
| Control-flow flattening | `'0|1|2|…'.split('|')` driving `switch (order[i++])` |
| Stack-trace budget | `Error.stackTraceLimit = 0x14` |

Two details make naive static decoding fail, and are why
[`deobfuscate.js`](deobfuscate.js) executes the prelude in a sandbox instead:

1. **The array is rotated at load time.** The rotation count is only discoverable
   by running the checksum loop, so the mapping index → string is not readable
   from the source text.
2. **Alias wrappers take a decoy argument and differ per scope.** In
   `_0x395d81(0xec4, 0x14e3)` the *first* argument is ignored; the offset also
   differs between wrappers, and the same wrapper name is reused in sibling
   scopes with different offsets — so aliases must be resolved by binding
   identity, not by name.

## What the script does

### Configuration

Reads a JSON blob from `localStorage`, bails out if absent or disabled, and
takes its feature flags from it: `canary`, `spoofOrigin`, `guessStrings`,
`duplicateValues`, `filterStack`, `crossDomainLeaks`, `prototypePollution`,
`injectPrototypePollutionJson`, and an optional user `messageCallback`.

### Source → sink taint tracking

A **canary** string is injected into attacker-controllable sources and the
script watches for it arriving at a dangerous sink.

* **Sources** (`location.href/hash/search/pathname/protocol/host/hostname`,
  `document.referrer/cookie/baseURI/documentURI`, `window.name`,
  `localStorage`/`sessionStorage`, `URLSearchParams`, plus `postMessage` data).
* **Sinks** — 127 entries mapping to 86 severity ranks in
  [`sinks.json`](dom-invader/sinks.json), grouped into three families:
  * JS-execution: `eval`, `Function`, `setTimeout/Interval`, `script.*`,
    `document.write*`, `jQuery.globalEval`, event-handler attributes;
  * HTML injection: `innerHTML`, `outerHTML`, `insertAdjacentHTML`,
    `iframe.srcdoc`, the jQuery manipulation family;
  * URL/attribute: `location.*`, `iframe.src`, `form.action`, `*.formaction`,
    `anchor.href`, `xhr.open`, `fetch`, `websocket`.

Sink rank drives severity: reaching `eval` (rank 2) outranks reaching
`location.search` (rank 83). Ranking helpers walk a **4-level severity ladder**
and a **3-level confidence ladder**, which lines up with Burp's
High/Medium/Low/Information and Certain/Firm/Tentative scales.

### Encoding analysis

The most interesting routine builds, per canary, a regex family that recognises
the canary followed by each of `\`, `<`, `>`, `'`, `"`, `:` in **every encoding a
browser might have applied** — raw, backslash-escaped, `\xNN`, `\uNNNN`,
octal, `%NN`, `&#NN;`, `&#xNN;`, and the full set of HTML named character
references. That last requirement is why the file carries a ~2,000-entry
code-point → entity-name table (twice).

The result is a per-character verdict: a sink is only reported as
**vulnerable** when the characters that actually matter for that sink family
survived unencoded — quotes/angle brackets for HTML sinks, additionally a
backslash for JS sinks, and a colon for URL sinks. This is what keeps the
false-positive rate down, and it is the part most worth reading in the
deobfuscated output.

### Web-message (postMessage) testing

`addEventListener` and `onmessage` are wrapped so that for each listener the
script can:

* record the origin, the stack of the registering listener, and the frame path
  (`top->frame[0]->frame[2]`);
* re-deliver a mutated copy of the message with the canary appended or
  prepended, as a raw string and as JSON, to see whether the payload reaches a
  sink;
* detect **missing origin checks** by exposing `origin` through a getter and
  observing whether the listener reads it — and whether it reads it *first*;
* harvest string comparisons out of the listener's own source
  (`case 'foo':`, `x === "bar"`) and replay them as guessed message types, so
  listeners that switch on a message `type` can still be reached;
* flag **cross-domain leaks** when data from a different origin reaches a sink.

Origin spoofing rewrites the reported origin to a look-alike host so a listener
doing a sloppy `indexOf`-style origin check is caught.

### Prototype pollution

Eight source templates are tried, each in both a hash and a query-string
variant, covering `__proto__.x`, `__proto__[x]`, `constructor.prototype.x`,
`constructor.prototype[x]` and the filter-bypass spellings
`__pro__proto__to__` and `constrconstructoructor` (which survive a naive
non-recursive `replace()` sanitiser). A `Proxy` on the polluted object records
which property names a gadget actually reads.

### Event replay

To reach code behind user interaction, the script dispatches synthetic
`click`/`mouseover`/`mousedown`/`mouseup` and `keydown`/`keypress`/`keyup`
events across every element with a matching handler, plus a `hashchange`, while
suppressing the default action so the page cannot navigate away.

## Reproducing the deobfuscation

```bash
cd deobfuscation
npm install
node deobfuscate.js path/to/dom-invader.obfuscated.js -o dom-invader.clean.js
```

**Note on provenance.** The obfuscated sample was supplied inline in the request
rather than committed to this repository, so the tool has not been run against
it *here*; the artefacts above (`sinks.json`, `decoded-strings.txt`) were
extracted from it directly and every string mapping is machine-verified. Drop
the original file into `dom-invader/` and the command above reproduces the full
clean source. The tool's correctness is covered end-to-end by `npm test`, which
round-trips a fixture built with this same obfuscation scheme and asserts the
deobfuscated output behaves identically to the obfuscated original.
