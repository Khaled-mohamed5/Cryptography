# monday.com JS recon

Analysis of the JavaScript attack surface discovered by a katana crawl of
`https://monday.com`. Passive: public assets, plain GETs, no active testing.

```
data/     crawl corpus and derived target lists
tools/    jsrecon.py — fetch + static-analysis toolkit (stdlib Python 3)
reports/  js-analysis.md — the report
```

Start at [`reports/bug-candidates.md`](reports/bug-candidates.md) — 20 bug
candidates, itemised, each with the command that confirms or kills it.
[`reports/js-analysis.md`](reports/js-analysis.md) has the surface inventory
behind them.

**Nothing is verified.** The environment that produced this cannot reach
monday.com (egress proxy: `x-deny-reason: host_not_allowed`), so no request was
ever sent to the target. Run `tools/verify.sh` to turn the candidates into
findings.

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
# check the 20 bug candidates (passive, rate-limited, bounded samples)
bash tools/verify.sh              # all
bash tools/verify.sh 01 06 09     # selected

# download and statically analyse the JS
python3 tools/jsrecon.py fetch   -i data/js-targets-prioritised.txt -o out --maps
python3 tools/jsrecon.py analyze -i out -o reports/live --target-domain monday.com
```

Fetch is resumable and rate-limited (4 workers, 250 ms delay by default).
Analyse writes `report.md`, `findings.jsonl`, and one `.txt` per extracted category.
