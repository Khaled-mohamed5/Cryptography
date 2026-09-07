# JS recon toolkit

Static analysis pipeline for JavaScript bundles, built for the monday.com crawl
in [`urls.txt`](urls.txt) but target-agnostic.

Triage of the crawl itself is in [FINDINGS.md](FINDINGS.md). **Read the scope
section there before pointing this at anything.**

## Why not just grep the crawl output

A crawler records the scripts a page happened to load. A Next.js app loads the
rest lazily, from an id→contenthash table inside the webpack runtime. That table
names every chunk in the build, including the ones no crawled page references —
admin surfaces, feature-flagged code, half-shipped integrations. Those are the
chunks worth reading, and they are exactly the ones a crawl misses.

katana found 111 JS files. Stage 2 exists to find the rest.

## Run it

```bash
./analyze.sh                  # fetch → chunks → maps → scan
./analyze.sh fetch scan       # only the named stages
TARGETS=my-urls.txt ./analyze.sh
JOBS=2 ./analyze.sh           # be gentler (default 4)
```

Everything lands in `out/` (git-ignored):

```
out/js/                     downloaded bundles, including enumerated chunks
out/maps/                   retrieved .map files
out/sources/                original source recovered from those maps
out/chunks-all.txt          every chunk URL derivable from the runtime
out/chunks-new.txt          the subset the crawl never saw
out/analysis/findings.json  secret + sink candidates, with file, offset, context
out/analysis/*.txt          urls, api paths, graphql operations, hosts
```

Re-running skips files already on disk, so an interrupted run resumes.

## Stages

**1. fetch** — pulls `js-targets.txt` (the 111 JS URLs from the crawl) at
concurrency 4, flattening each URL to a unique filename and recording
`out/url-index.tsv` so relative source-map references resolve correctly later.

**2. chunks** — `lib/chunks.py` parses the webpack runtime and `_buildManifest.js`
for the chunk hash map, rebuilds every chunk URL, subtracts what is already
downloaded, and fetches the remainder.

**3. maps** — `lib/sourcemaps.py` reads each bundle's `//# sourceMappingURL`
comment *and* blindly probes `<bundle>.js.map`. Any map that comes back is
unpacked into `out/sources/` as an original file tree. A production build
serving `sourcesContent` is worth reporting on its own; it also makes stage 4
far more accurate, because comments and dead code survive in the original.

**4. scan** — `lib/scan.py` over both the minified bundles and any recovered
sources:

- **secrets** — 22 rules. Structurally-anchored ones (`AKIA…`, `xoxb-…`,
  `sk_live_…`, `ghp_…`, PEM blocks, JWTs) report as-is; loose name-based ones
  (`apiKey: "…"`) must additionally clear a noise filter and Shannon entropy
  ≥ 3.2, which is what keeps minified identifiers out of the results.
- **sinks** — `innerHTML`, `document.write`, `eval`, `new Function`,
  `dangerouslySetInnerHTML`, `srcdoc`, jQuery HTML sinks, wildcard
  `postMessage`, and `message` listeners with no origin check within 1200
  characters. A sink is promoted to high when a taint source (`location.hash`,
  `event.data`, `URLSearchParams`, …) appears in the same window.
- **inventory** — absolute URLs, API paths, GraphQL operation names, and
  hostnames split into in-scope and third-party.

Findings are candidates with file, byte offset and surrounding context. Confirm
each by hand; nothing here is evidence on its own.

## Validation

The pipeline was exercised end-to-end against a local fixture mimicking a
Next.js build (webpack runtime + manifest + lazily-loaded chunks + a source map),
and the scanner separately against real minified libraries.

| check | result |
|---|---|
| chunks recovered that the "crawl" never saw | 6 of 6, including one holding a planted key |
| source map discovered and unpacked | 2 original sources recovered |
| planted secrets found in bundles | 5 of 5 |
| planted secret found only in recovered source | 1 of 1 |
| planted DOM-XSS / postMessage sinks found | 4 of 4, all correctly marked tainted |
| **false-positive secrets on 141 KB of real minified jQuery + axios** | **0** |

Sinks did fire on the real libraries (6 × `innerHTML` in jQuery, a `postMessage`
pair in axios). Those are correct detections of genuine patterns and the reason
sinks are ranked for review rather than reported as findings.

Fixing the false-negative that this testing exposed is worth recording: the
noise filter was compiled case-insensitively, so its "lowercase identifier"
branch matched *any* all-alphabetic string — silently discarding AWS key ids.
Structural rules now bypass noise and entropy filtering entirely.

## Conduct

Passive by default: plain `GET`s for public static assets, no authentication, no
parameter fuzzing, no writes, concurrency 4. It reads what a browser would
already have loaded.

That still means traffic to someone else's origin. Keep `JOBS` low, run it once
rather than on a loop, and confirm the target is in scope for the programme you
intend to report to.
