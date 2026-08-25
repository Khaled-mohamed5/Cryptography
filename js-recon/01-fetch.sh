#!/usr/bin/env bash
# Download every JS asset from urls/js-urls.txt into out/raw/, preserving host+path.
set -uo pipefail
cd "$(dirname "$0")"

UA="${RECON_UA:-Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0 Safari/537.36 (bugbounty)}"
DELAY="${RECON_DELAY:-0.25}"     # seconds between requests, be polite
JOBS="${RECON_JOBS:-4}"          # parallel workers
LIST="${1:-urls/js-urls.txt}"
OUT="out/raw"

mkdir -p "$OUT" out/meta
: > out/meta/fetch.log
: > out/meta/fetch-index.tsv

fetch_one() {
  local url="$1"
  local host path fname dir
  host="$(printf '%s' "$url" | sed -E 's#^https?://([^/]+).*#\1#')"
  path="$(printf '%s' "$url" | sed -E 's#^https?://[^/]+##')"
  fname="$(printf '%s' "$path" | sed -E 's#[?&=:]#_#g; s#^/##; s#/#__#g')"
  [ -z "$fname" ] && fname="index.js"
  fname="${fname:0:180}"
  dir="$OUT/$host"
  mkdir -p "$dir"

  local code
  code=$(curl -sS -L --compressed --max-time 45 \
      -A "$UA" \
      -H 'Accept: */*' \
      -H 'Accept-Language: en-GB,en;q=0.9' \
      -D "out/meta/${host}__${fname}.headers" \
      -o "$dir/$fname" \
      -w '%{http_code}' \
      "$url" 2>>out/meta/fetch.log)

  local size=0
  [ -f "$dir/$fname" ] && size=$(stat -c%s "$dir/$fname" 2>/dev/null || echo 0)
  printf '%s\t%s\t%s\t%s\n' "$code" "$size" "$url" "$dir/$fname" >> out/meta/fetch-index.tsv
  if [ "$code" != "200" ] || [ "$size" -lt 32 ]; then
    printf '  [!] %-3s %s (%sB)\n' "$code" "$url" "$size"
  else
    printf '  [+] %-3s %-9s %s\n' "$code" "${size}B" "$url"
  fi
  sleep "$DELAY"
}
export -f fetch_one
export UA DELAY OUT

echo "[*] fetching $(wc -l < "$LIST") JS assets -> $OUT  (jobs=$JOBS delay=${DELAY}s)"
xargs -a "$LIST" -I{} -P "$JOBS" bash -c 'fetch_one "$@"' _ {}

echo
echo "[*] done. summary by HTTP status:"
cut -f1 out/meta/fetch-index.tsv | sort | uniq -c | sort -rn
echo "[*] total bytes: $(awk -F'\t' '{s+=$2} END{print s+0}' out/meta/fetch-index.tsv)"
