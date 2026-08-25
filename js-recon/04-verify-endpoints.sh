#!/usr/bin/env bash
# OPTIONAL, ACTIVE. Probe the endpoints extracted from JS to see which are live.
# Rate limited on purpose - a private program does not want a flood from you.
# Only runs against hosts listed in scope.txt.
set -uo pipefail
cd "$(dirname "$0")"

SCOPE="${SCOPE_FILE:-scope.txt}"
DELAY="${RECON_DELAY:-0.6}"
UA="${RECON_UA:-Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0 Safari/537.36 (bugbounty)}"
BASE="${1:-}"

if [ ! -f out/findings.json ]; then echo "run ./03-analyze.py first"; exit 1; fi
if [ ! -f "$SCOPE" ]; then echo "missing $SCOPE - list one in-scope host per line"; exit 1; fi
if [ -z "$BASE" ]; then
  echo "usage: $0 https://www.bentleymotors.com   # base for root-relative endpoints"; exit 1
fi

in_scope() {
  local h; h="$(printf '%s' "$1" | sed -E 's#^https?://##; s#/.*##; s#:.*##')"
  grep -qx -- "$h" "$SCOPE"
}

mkdir -p out
: > out/endpoints-live.tsv

mapfile -t EPS < <(python3 -c "
import json
for r in json.load(open('out/findings.json'))['endpoints']:
    print(r['endpoint'])" | sort -u)

echo "[*] probing ${#EPS[@]} endpoints (delay ${DELAY}s, scope-gated)"
for ep in "${EPS[@]}"; do
  case "$ep" in
    http://*|https://*) url="$ep" ;;
    //*)                url="https:$ep" ;;
    /*)                 url="${BASE}${ep}" ;;
    *)                  continue ;;
  esac
  # skip unresolved build-time templates
  case "$url" in *'${'*|*'{{'*|*'<%'*) continue ;; esac
  if ! in_scope "$url"; then
    printf 'SKIP\t-\t%s\t(out of scope)\n' "$url" >> out/endpoints-live.tsv
    continue
  fi
  read -r code len ctype < <(curl -sS -o /dev/null -L --max-time 20 -A "$UA" \
      -w '%{http_code} %{size_download} %{content_type}\n' "$url" 2>/dev/null || echo "000 0 -")
  printf '%s\t%s\t%s\t%s\n' "$code" "$len" "$url" "$ctype" >> out/endpoints-live.tsv
  case "$code" in
    200|201|401|403|500) printf '  [%s] %-9s %s\n' "$code" "${len}B" "$url" ;;
  esac
  sleep "$DELAY"
done

echo
echo "[*] status distribution:"
cut -f1 out/endpoints-live.tsv | sort | uniq -c | sort -rn
echo "[*] full results -> out/endpoints-live.tsv"
