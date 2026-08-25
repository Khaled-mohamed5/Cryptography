# js-recon — JS analysis pipeline for the Bentley Motors program

Offline-capable toolkit for pulling and analysing every JavaScript asset found by a
katana crawl. Built for an authorised Intigriti private-program engagement.

## Why this runs on your machine, not in the agent sandbox

The container this was written in has an egress policy that returns `403` on
`CONNECT www.bentleymotors.com:443`, so it cannot fetch the target. That is the right
outcome anyway: an invite-only program should be tested from your own authorised session
and IP, not from shared infrastructure.

## Layout

```
urls/katana-raw.txt   277 URLs from the crawl, deduped
urls/js-urls.txt      77 unique JS assets (derived)
urls/hosts.txt        host inventory with URL counts
scope.txt             hosts 04- is allowed to touch — edit to match the RoE
01-fetch.sh           download every JS asset            -> out/raw/<host>/
02-sourcemaps.py      find + unpack source maps          -> out/sourcemaps/<host>/<bundle>/
03-analyze.py         static analysis                    -> out/report.md, out/findings.json
04-verify-endpoints.sh  OPTIONAL, ACTIVE: probe extracted endpoints
run-all.sh            1 → 2 → 3
FINDINGS.md           prioritised triage of the crawl itself — read this first
```

## Run

```bash
./run-all.sh                     # fetch, sourcemaps, analyse
$EDITOR out/report.md

# optional, active, scope-gated, rate limited:
./04-verify-endpoints.sh https://www.bentleymotors.com
```

Tunables (env): `RECON_UA`, `RECON_DELAY` (default `0.25`s), `RECON_JOBS` (default `4`).
Keep the delay non-zero. Getting rate-limited or setting off a WAF on a BETA private
program is a fast way to lose access.

## What `03-analyze.py` looks for

| Pass | Finds |
|---|---|
| `secrets` | 25 key formats (AWS, GCP, Slack, Stripe, JWT, private keys, basic-auth URLs…) plus a filtered generic `key: "value"` heuristic |
| `endpoints` | LinkFinder-style path/URL extraction, deduped, with the files each came from |
| `sinks` | 18 DOM-XSS sinks, each correlated against taint **sources** within 700 characters — the `tainted` set is what you read first |
| `postmessage` | every `message` listener, flagged when no origin check appears in *its own* handler body |
| `dynload` | `createElement('script'\|'iframe'\|…)` where `.src` is assigned a variable |
| `libs` | dependency fingerprints with the known-vulnerable ranges spelled out |
| `internals` | internal hostnames, RFC1918 addresses, S3/blob buckets, AEM paths, `@bentleymotors.com` addresses, debug flags, TODO/FIXME |

All context windows are byte-offset based, so minified single-line bundles are handled
correctly.

## Notes on accuracy

- Source-map recovery is tried twice per file: the declared `//# sourceMappingURL`, then a
  blind `<url>.map`. A map carrying `sourcesContent` gives you the original unminified
  source, which is worth more than every other pass combined.
- The sink/source correlation is proximity-based, not a real taint engine. Treat the
  `tainted` list as a ranked reading order, not as proof — confirm each one by hand.
- The generic secret rule filters placeholders (`YOUR_API_KEY`, `${…}`, `{{…}}`, `changeme`,
  low-entropy values), but still expect false positives. Verify before submitting.
