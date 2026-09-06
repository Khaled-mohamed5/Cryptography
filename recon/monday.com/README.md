# monday.com JS recon

Analysis of the JavaScript attack surface discovered by a katana crawl of
`https://monday.com`. Passive: public assets, plain GETs, no active testing.

```
data/     crawl corpus and derived target lists
tools/    jsrecon.py — fetch + static-analysis toolkit (stdlib Python 3)
reports/  js-analysis.md — the report
```

Start at [`reports/js-analysis.md`](reports/js-analysis.md).

## Data files

| File | Contents |
|---|---|
| `katana-raw.txt` | The original 840-line crawl output |
| `all-urls-unique.txt` | 679 unique URLs |
| `js-urls.txt` | 111 unique JavaScript files |
| `js-targets-prioritised.txt` | The same 111, ordered by analysis value (tiers 1→6) |
| `tier1-manifests.txt` | Next.js build/chunk manifests — fetch these first |
| `tier2-highvalue.txt` | 9 hand-written app/config bundles |
| `tier3-shared-chunks.txt` | 21 named shared chunks |
| `tier4-lazy-chunks.txt` | 67 lazy-loaded chunks |
| `tier5-wordpress-vendor.txt` | 8 WordPress/Cloudflare assets |
| `tier6-vendor-framework.txt` | 3 framework/polyfill bundles |
| `js-malformed.txt` | 8 runtime-computed refs katana could not resolve |
| `adjacent-endpoints.txt` | Non-JS endpoints worth pulling in the same pass |
| `hosts.txt` | Host frequency table |

## Usage

```bash
python3 tools/jsrecon.py fetch   -i data/js-targets-prioritised.txt -o out --maps
python3 tools/jsrecon.py analyze -i out -o reports/live --target-domain monday.com
```

Fetch is resumable and rate-limited (4 workers, 250 ms delay by default).
Analyse writes `report.md`, `findings.jsonl`, and one `.txt` per extracted category.
