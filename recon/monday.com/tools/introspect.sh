#!/usr/bin/env bash
# introspect.sh - two questions the sweep results depend on.
#
#   export TOKEN_B='...'; export TOKEN_C='...'; bash introspect.sh
#
# 1. Is the schema filtered by token scope?
#    add_file_to_item is a documented monday mutation and came back as
#    "Cannot query field ... on type Mutation". If the schema each token sees is
#    trimmed to its scope, then every ABSENT verdict collected so far means
#    "not in my scope" rather than "not on the server" - and any hidden-field
#    hunting done with these tokens has been looking through a keyhole.
#
# 2. Where does an item's file actually live?
#    canary.txt is visible in the UI on item 3209838125, but item.assets
#    returns [] to the item's own owner. Something else holds the id.
#
# Read-only. Introspection plus queries against C's own board with C's token.

set -uo pipefail
: "${TOKEN_C:?export TOKEN_C first}"
TOKEN_B="${TOKEN_B:-$TOKEN_C}"

C_BOARD=5103704617
API=https://api.monday.com/v2
R=$'\033[31m'; G=$'\033[32m'; Y=$'\033[33m'; BD=$'\033[1m'; D=$'\033[2m'; N=$'\033[0m'

cq() { curl -s "$API" -H "Authorization: $1" -H 'Content-Type: application/json' \
         --max-time 30 -d "{\"query\":\"$2\"}" 2>/dev/null; sleep 1; }

names() { grep -o '"name":"[^"]*"' | sed 's/"name":"//;s/"$//'; }

echo
echo "${BD}=== 1. is the schema scope-filtered? ===${N}"
echo

for pair in "B:$TOKEN_B" "C:$TOKEN_C"; do
  lbl="${pair%%:*}"; tok="${pair#*:}"
  M=$(cq "$tok" '{ __type(name: \"Mutation\") { fields { name } } }')
  Q=$(cq "$tok" '{ __type(name: \"Query\") { fields { name } } }')
  mc=$(printf '%s' "$M" | names | wc -l)
  qc=$(printf '%s' "$Q" | names | wc -l)

  if printf '%s' "$M" | grep -q '"errors"'; then
    echo "  ${Y}$lbl: introspection refused${N}"
    printf '     %s%s%s\n' "$D" "$(printf '%s' "$M" | head -c 200)" "$N"
    continue
  fi
  echo "  ${BD}$lbl${N}  Query fields: ${G}$qc${N}   Mutation fields: ${G}$mc${N}"
  printf '%s' "$M" | names | grep -iE 'file|asset|upload' | sed "s/^/     mutation: /"
  printf '%s' "$Q" | names | grep -iE 'file|asset|doc' | sed "s/^/     query:    /"
  echo "$lbl $mc $qc" >> /tmp/introspect-counts.$$
done

if [ -f /tmp/introspect-counts.$$ ]; then
  bm=$(awk '$1=="B"{print $2}' /tmp/introspect-counts.$$)
  cm=$(awk '$1=="C"{print $2}' /tmp/introspect-counts.$$)
  echo
  if [ -n "${bm:-}" ] && [ -n "${cm:-}" ] && [ "$bm" != "$cm" ]; then
    echo "  ${R}${BD}SCOPE-FILTERED${N} - B sees $bm mutations, C sees $cm. The schema each"
    echo "  token gets is trimmed. Every ABSENT result so far means 'not in my"
    echo "  scope', not 'not on the server'. Re-run the hidden-field probes with a"
    echo "  token minted with full scopes before drawing any conclusion from them."
  else
    echo "  ${G}same field counts for both tokens${N} - no per-token trimming visible."
    echo "${D}  If add_file_to_item is still missing, it is an API-version difference,"
    echo "  not a scope one. Retry with an API-Version header (see part 3).${N}"
  fi
  rm -f /tmp/introspect-counts.$$
fi

echo
echo "${BD}=== 2. where is canary.txt? ===${N}"
echo "${D}  all queries below use C's own token against C's own board${N}"
echo

show() {
  local label="$1" body="$2"
  printf '  %-34s %s%s%s\n' "$label" "$D" "$(printf '%s' "$body" | head -c 220)" "$N"
  if printf '%s' "$body" | grep -qiE 'canary|assetId|"asset_id"'; then
    echo "     ${G}${BD}^ this route has it${N}"
  fi
}

show "item.assets" \
  "$(cq "$TOKEN_C" "{ boards(ids: [\\\"$C_BOARD\\\"]) { items_page { items { id assets { id name } } } } }")"

show "item.column_values (file column)" \
  "$(cq "$TOKEN_C" "{ boards(ids: [\\\"$C_BOARD\\\"]) { items_page { items { id column_values { id type value } } } } }")"

show "board.updates.assets" \
  "$(cq "$TOKEN_C" "{ boards(ids: [\\\"$C_BOARD\\\"]) { updates { id assets { id name } } } }")"

show "me.account files / docs" \
  "$(cq "$TOKEN_C" "{ docs(limit: 5) { id name } }")"

echo
echo "${BD}=== 3. API-Version ===${N}"
echo "${D}  monday serves several schema versions. If add_file_to_item appears under"
echo "  an explicit version, its absence was versioning, not authorization.${N}"
echo
for v in 2023-10 2024-01 2024-10 2025-01 2025-04; do
  r=$(curl -s "$API" -H "Authorization: $TOKEN_C" -H 'Content-Type: application/json' \
        -H "API-Version: $v" --max-time 25 \
        -d '{"query":"{ __type(name: \"Mutation\") { fields { name } } }"}' 2>/dev/null)
  n=$(printf '%s' "$r" | names | wc -l)
  hit=$(printf '%s' "$r" | names | grep -cE '^add_file_to_(item|update|column)$' || true)
  if printf '%s' "$r" | grep -q '"errors"'; then
    printf '  %-9s %s\n' "$v" "$(printf '%s' "$r" | grep -o '"message":"[^"]*"' | head -1)"
  else
    printf '  %-9s %3s mutation fields   add_file_to_*: %s\n' "$v" "$n" \
      "$([ "$hit" -gt 0 ] && printf '%bYES%b' "$G$BD" "$N" || printf '%bno%b' "$D" "$N")"
  fi
  sleep 1
done

echo
echo "${BD}--- what to do ---${N}"
cat <<'MSG'
  If part 1 says SCOPE-FILTERED: mint a new token for each account with every
  scope enabled, and re-run run-bc.sh and gqlprobe.py probe. Nothing about the
  hidden-schema work is trustworthy until then.

  If part 2 finds the file under column_values: pull assetId out of that JSON
  and pass it in -  C_ASSET=<id> bash plant-canary.sh

  If part 3 shows add_file_to_* under one version and not another, that is
  worth a sentence in the notes but is not a vulnerability - it is how monday
  ships breaking changes.

  Fastest route if all three are inconclusive: open canary.txt in the browser on
  account C. The asset id is in the url and in the network tab. That is one
  click and it unblocks the only test that still matters.
MSG
