#!/usr/bin/env bash
# schema-diff.sh - enumerate the fields that only exist without an API-Version header.
#
#   export TOKEN_C='...'; bash schema-diff.sh
#
# introspect.sh found 194 mutations with no API-Version header and 91 under every
# published version from 2023-10 to 2025-04. Same for both accounts' tokens, so
# it is not scope. Something over a hundred mutations are reachable with an
# ordinary token that no documented version of the API admits to having.
#
# That is worth enumerating properly. Some will be dull - renames, internals that
# power the UI, fields staged for a version that has not shipped. Some may take
# an account_id or a user_id and never have been meant for a customer token.
#
# Read-only: introspection only. Nothing here executes a mutation.
# Output lands in schema-diff-out/ for reading and for attaching to a report.

set -uo pipefail
: "${TOKEN_C:?export TOKEN_C first}"

API=https://api.monday.com/v2
OUT=schema-diff-out
BASE_VERSION="${BASE_VERSION:-2025-04}"   # newest published version to compare against
mkdir -p "$OUT"

R=$'\033[31m'; G=$'\033[32m'; Y=$'\033[33m'; BD=$'\033[1m'; D=$'\033[2m'; N=$'\033[0m'

# dump <label> <version|"">  -> $OUT/<label>.<Query|Mutation>.txt
dump() {
  local label="$1" ver="$2" t
  for t in Query Mutation; do
    local hdr=()
    [ -n "$ver" ] && hdr=(-H "API-Version: $ver")
    curl -s "$API" -H "Authorization: $TOKEN_C" -H 'Content-Type: application/json' \
      "${hdr[@]}" --max-time 30 \
      -d "{\"query\":\"{ __type(name: \\\"$t\\\") { fields { name } } }\"}" 2>/dev/null \
      | grep -o '"name":"[^"]*"' | sed 's/"name":"//;s/"$//' | sort -u > "$OUT/$label.$t.txt"
    sleep 1
  done
}

echo
echo "${BD}=== schema diff: unversioned vs $BASE_VERSION ===${N}"
echo

dump default ""
dump "v$BASE_VERSION" "$BASE_VERSION"

for t in Query Mutation; do
  a="$OUT/default.$t.txt"; b="$OUT/v$BASE_VERSION.$t.txt"
  na=$(wc -l < "$a"); nb=$(wc -l < "$b")
  comm -23 "$a" "$b" > "$OUT/only-unversioned.$t.txt"
  comm -13 "$a" "$b" > "$OUT/only-versioned.$t.txt"
  x=$(wc -l < "$OUT/only-unversioned.$t.txt"); y=$(wc -l < "$OUT/only-versioned.$t.txt")
  printf '  %-9s unversioned %3s   %-8s %3s   only unversioned: %s   only versioned: %s\n' \
    "$t" "$na" "$BASE_VERSION" "$nb" "$x" "$y"
done
echo

# ---- the interesting half: what do the extras look like? ----
RISK='account|admin|internal|impersonat|sudo|service|token|secret|key|billing|plan|subscription|seat|sso|saml|scim|audit|export|migrat|transfer|bypass|override|force|debug|feature|flag|permission|role|grant|revoke|invite|domain|tenant|cross|global|system|backdoor|masquerade'

for t in Query Mutation; do
  f="$OUT/only-unversioned.$t.txt"
  [ -s "$f" ] || continue
  echo "${BD}--- $t fields present only without a version header ($(wc -l < "$f")) ---${N}"
  echo "${R}${BD}  names matching a sensitive keyword:${N}"
  grep -iE "$RISK" "$f" | sed 's/^/     /' || echo "     (none)"
  echo
  echo "${D}  the rest:${N}"
  grep -ivE "$RISK" "$f" | paste -sd' ' - | fold -sw 76 | sed 's/^/     /'
  echo
done

# ---- signatures, so BOLA candidates are visible ----
echo "${BD}=== signatures of the sensitive-looking extras ===${N}"
echo "${D}  a field here that takes an account_id or user_id is a BOLA candidate:"
echo "  reachable with a normal token, and no published version admits it exists${N}"
echo
for t in Query Mutation; do
  f="$OUT/only-unversioned.$t.txt"; [ -s "$f" ] || continue
  curl -s "$API" -H "Authorization: $TOKEN_C" -H 'Content-Type: application/json' --max-time 30 \
    -d "{\"query\":\"{ __type(name: \\\"$t\\\") { fields { name args { name type { name kind ofType { name kind ofType { name } } } } } } }\"}" \
    2>/dev/null > "$OUT/args.$t.json"
  sleep 1
done

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SIGR=""
for c in "$HERE/sigreport.py" "$HERE/tools/sigreport.py" ./sigreport.py ./tools/sigreport.py; do
  [ -f "$c" ] && { SIGR="$c"; break; }
done
if [ -n "$SIGR" ]; then
  python3 "$SIGR" "$OUT" "$RISK" | tee "$OUT/signatures.txt"
else
  echo "${Y}  sigreport.py not found next to this script - signatures skipped."
  echo "  Put it in the same directory and re-run, or read $OUT/args.*.json by hand.${N}"
fi

echo
echo "${BD}--- how to read this ---${N}"
cat <<MSG
  Everything is in $OUT/ - the full field lists and the diffs.

  A larger unversioned schema is not by itself a vulnerability. The unversioned
  endpoint usually serves the current development schema, and shipping fields
  there before they appear in a dated version is ordinary practice.

  It becomes a finding only if one of these fields does something a customer
  token should not be able to do. The ones marked "takes an id" are where to
  look: pick one, call it with account C's ids from account B's token, and see
  whether it answers. That is the same test as before, against a surface that no
  published version of the API acknowledges.

  Send $OUT/only-unversioned.Mutation.txt back and the candidates can be ranked.

  Do not fire the mutations blind. Read the signature first, and never run one
  whose name implies deletion or transfer against anything but your own objects.
MSG
