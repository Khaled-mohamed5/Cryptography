#!/usr/bin/env bash
# JS recon pipeline: fetch -> enumerate hidden chunks -> source maps -> scan.
#
# Passive by default: plain GETs for public static assets, low concurrency,
# no authentication, no parameter fuzzing, no writes. Confirm the target is in
# scope for the programme you are reporting to before running it.
#
#   ./analyze.sh                     # full pipeline against js-targets.txt
#   ./analyze.sh fetch scan          # only the named stages
#   TARGETS=my.txt ./analyze.sh      # different URL list

set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGETS="${TARGETS:-$HERE/js-targets.txt}"
OUT="${OUT:-$HERE/out}"
BASE="${BASE:-https://monday.com/nhp/_next}"
JOBS="${JOBS:-4}"            # keep low: this is someone else's origin
UA="${UA:-Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0 Safari/537.36}"

JS_DIR="$OUT/js"; MAP_DIR="$OUT/maps"; SRC_DIR="$OUT/sources"; ANALYSIS="$OUT/analysis"
INDEX="$OUT/url-index.tsv"   # relpath <TAB> source URL

log() { printf '\n\033[1m== %s\033[0m\n' "$*"; }

# fetch_list <file-of-urls> <destdir> — parallel, resumable, records the index.
fetch_list() {
  local list="$1" dest="$2" n
  n=$(grep -cve '^\s*$' "$list" 2>/dev/null || echo 0)
  [ "$n" -eq 0 ] && { echo "  nothing to fetch"; return; }
  mkdir -p "$dest"
  echo "  $n URLs -> $dest (concurrency $JOBS)"
  # Flatten each URL to a unique filename so chunks from different paths cannot collide.
  grep -ve '^\s*$' "$list" | sort -u | xargs -P "$JOBS" -I{} sh -c '
    url="$1"; dest="$2"; ua="$3"; index="$4"
    name=$(printf "%s" "$url" | sed -e "s#^https\?://##" -e "s#[/?&=]#_#g" | cut -c1-180)
    case "$name" in *.js|*.map|*.json) ;; *) name="$name.js" ;; esac
    out="$dest/$name"
    [ -s "$out" ] || curl -sS -f -L --max-time 45 --retry 2 --retry-delay 2 \
        -A "$ua" -o "$out" "$url" 2>/dev/null
    if [ -s "$out" ]; then printf "%s\t%s\n" "$name" "$url" >> "$index"; else rm -f "$out"; fi
  ' _ {} "$dest" "$UA" "$INDEX"
  echo "  downloaded: $(find "$dest" -type f | wc -l) files, $(du -sh "$dest" 2>/dev/null | cut -f1)"
}

stage_fetch() {
  log "STAGE 1/4  fetch crawled JS"
  mkdir -p "$OUT"; : > "$INDEX"
  fetch_list "$TARGETS" "$JS_DIR"
}

stage_chunks() {
  log "STAGE 2/4  enumerate chunks the crawl never saw"
  local runtimes
  runtimes=$(find "$JS_DIR" -type f \( -name '*webpack*' -o -name '*Manifest*' -o -name '*main-*' \) 2>/dev/null)
  if [ -z "$runtimes" ]; then
    echo "  no webpack runtime/manifest downloaded — skipping"; return
  fi
  echo "$runtimes" | sed 's/^/  using: /'
  # shellcheck disable=SC2086
  python3 "$HERE/lib/chunks.py" --base "$BASE" $runtimes > "$OUT/chunks-all.txt"
  # Only fetch what we do not already have.
  cut -f2 "$INDEX" | sort -u > "$OUT/.have"
  comm -23 "$OUT/chunks-all.txt" "$OUT/.have" > "$OUT/chunks-new.txt"
  echo "  $(wc -l < "$OUT/chunks-new.txt") previously unseen chunk URLs"
  fetch_list "$OUT/chunks-new.txt" "$JS_DIR"
}

stage_maps() {
  log "STAGE 3/4  source maps"
  python3 "$HERE/lib/sourcemaps.py" discover "$JS_DIR" \
      --url-index "$INDEX" --blind > "$OUT/map-urls.txt"
  fetch_list "$OUT/map-urls.txt" "$MAP_DIR"
  if [ -n "$(find "$MAP_DIR" -type f -name '*.map' 2>/dev/null)" ]; then
    echo "  !! source maps are being served in production — reportable on its own"
    python3 "$HERE/lib/sourcemaps.py" unpack "$MAP_DIR" "$SRC_DIR"
  else
    echo "  no source maps retrievable (expected on a hardened build)"
  fi
}

stage_scan() {
  log "STAGE 4/4  static analysis"
  python3 "$HERE/lib/scan.py" "$JS_DIR" -o "$ANALYSIS" --in-scope monday.com
  if [ -d "$SRC_DIR" ]; then
    echo
    echo "  --- recovered original sources ---"
    python3 "$HERE/lib/scan.py" "$SRC_DIR" -o "$ANALYSIS-sources" --in-scope monday.com
  fi
  cat <<EOF

Next, by hand (nothing below is automatic):
  1. $ANALYSIS/findings.json      - every secret/sink candidate, with context
  2. $ANALYSIS/hosts-in-scope.txt - new subdomains to fold into the next crawl
  3. $ANALYSIS/api-paths.txt      - endpoints to test with your own two accounts
  4. $ANALYSIS/graphql-operations.txt - operation names to diff against the
                                        published schema; ones missing from the
                                        public schema are the interesting ones
EOF
}

main() {
  local stages=("$@")
  [ ${#stages[@]} -eq 0 ] && stages=(fetch chunks maps scan)
  mkdir -p "$OUT"
  for s in "${stages[@]}"; do
    case "$s" in
      fetch)  stage_fetch  ;;
      chunks) stage_chunks ;;
      maps)   stage_maps   ;;
      scan)   stage_scan   ;;
      *) echo "unknown stage: $s (fetch|chunks|maps|scan)" >&2; exit 2 ;;
    esac
  done
  log "done — artifacts under $OUT/"
}

main "$@"
