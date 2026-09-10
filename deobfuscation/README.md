# JavaScript Deobfuscator

An AST-based deobfuscator for code produced by
[javascript-obfuscator](https://github.com/javascript-obfuscator/javascript-obfuscator)
(obfuscator.io) with the "high obfuscation" preset — string-array encoding,
self-defending checksums, dispatcher objects, opaque predicates and
control-flow flattening.

It was written to unpack the Burp Suite **DOM Invader** injected content script;
see [`ANALYSIS.md`](ANALYSIS.md) for that sample's parameters and structure.

## Usage

```bash
cd deobfuscation
npm install                                   # @babel/parser, traverse, generator, types
node deobfuscate.js input.js -o output.js     # or omit -o to write to stdout
node deobfuscate.js input.js --no-rename      # keep the original _0x… identifiers
```

## How it works

The obfuscator layers six transforms; the tool reverses them in the opposite order.

### 1. String-array encoding

Every string literal is replaced by a numeric lookup into a shared array:

```js
function a4_0x2128() { const arr = ['jMXLCZS', …]; a4_0x2128 = () => arr; return arr; }
function a4_0x5998(i, k) { … arr[i - 0x136] … base64-decode … }
(function (fn, target) { … rotate arr until a checksum equals target … })(a4_0x2128, 0xa6a0f);
```

Entries are base64 over a **rotated alphabet** (`abc…xyzABC…XYZ0-9+/=`, lowercase
first), decoded to UTF-8 bytes and then run through `decodeURIComponent`. Callers
never touch the decoder directly — they go through per-scope alias wrappers whose
offsets differ, and one of the two arguments is a decoy:

```js
function _0x395d81(a, b) { return a4_0x5998(b - 0x2e5, a); }   // real index: b - 0x41b
```

Re-implementing that statically is brittle (the rotation count is only knowable by
running the checksum loop), so the tool instead **lifts the array function, the
decoder and the rotation IIFE into a `node:vm` sandbox and executes them**. Alias
wrappers are compiled into the same sandbox, keyed by Babel *binding identity* so
that the same name reused in sibling scopes with different offsets stays distinct.
Every call with literal arguments is then evaluated for real and replaced with the
resulting string.

### 2. Dispatcher / proxy objects

Constants and tiny operator wrappers are hoisted into a per-function lookup table:

```js
const _0x4977b3 = {
  'omuUi': function (a, b) { return a === b; },
  'PdZQG': 'string',
  'fPTPC': function (f, a, b, c, d) { return f(a, b, c, d); },
};
if (_0x4977b3['omuUi'](typeof x, _0x4977b3['PdZQG'])) …
```

Constants are inlined; operator and call proxies are unwrapped by substituting the
call arguments into the one-line `return` body. Substitution is refused when a
parameter is used more than once (it would duplicate side effects) or dropped
entirely while its argument is non-trivial (it would lose them).

### 3. Literal normalisation

`!![]`→`true`, `![]`→`false`, `typeof 'x'`→`'string'`, `void 0`→`undefined`,
`o['prop']`→`o.prop`, plus constant folding of arithmetic, comparison and
string concatenation. Hex numeric literals are normalised to decimal.

### 4. Opaque predicates

Steps 1–3 turn the injected guards into constants (`if ('rqSjo' === 'buHHO')`),
so the dead branch can be deleted outright, along with any statements left
stranded after a `return`/`continue`/`break`/`throw`.

### 5. Control-flow flattening

```js
const order = '2|0|3|1'.split('|');
let i = 0;
while (true) { switch (order[i++]) { case '0': A; continue; … } break; }
```

is rewritten back to the straight-line sequence in the order the array dictates.

### 5b. Dead code elimination

Bindings left unreferenced by the passes above are dropped when their initialiser
is provably side-effect free (a conservative allowlist: literals, object/array
literals of literals, and a handful of pure `String`/`Array` methods).

### 6. Identifier renaming

`_0x4977b3` and friends are renamed scope-correctly via Babel's `scope.rename` to
`fn1` / `arg1` / `v1`. Pass `--no-rename` to keep the originals.

Passes 2–5b feed each other (inlining exposes constants, folding exposes dead
branches, deleting branches exposes dead bindings), so the driver runs them to a
fixed point — re-parsing between rounds to keep scope information accurate — for
at most 12 rounds.

## Tests

```bash
npm test
```

`test/make-fixture.js` generates `test/fixture-obfuscated.js` using the *same*
scheme as the real sample: a pre-rotated string array restored by a checksum IIFE,
the verbatim decoder, an alias wrapper, a dispatcher object with operator and call
proxies, an opaque predicate and a flattened switch. `test/run-tests.js` then
checks that the deobfuscated output

* **produces the identical return value** to the obfuscated original,
* contains the recovered plaintext strings,
* has no decoder scaffolding, dispatcher references, opaque predicates,
  flattening artefacts or `_0x…` identifiers left,
* and still parses.

## Limitations

* Only calls whose arguments are **literals** can be decoded. Obfuscators that
  compute indices at runtime need dynamic tracing instead.
* The decoder prelude is executed. Run untrusted samples in a throwaway
  container — the `vm` sandbox is an isolation *convenience*, not a security
  boundary.
* Renaming recovers *structure*, not intent: `v1`/`fn1` are placeholders. Original
  identifier names are destroyed by the obfuscator and cannot be recovered.
