#!/usr/bin/env bash
# plant-canary.sh - make sure account C holds a canary, then test B against it.
#
#   export TOKEN_B='<uid 115702202 / actid 36786355>'
#   export TOKEN_C='<uid 115703279 / actid 36786534>'
#   bash plant-canary.sh
#
# Looks for an asset already on C's board first. Only if there is none does it
# upload one, and any write it makes goes to account C, with account C's own
# token, to objects account C owns. Nothing belonging to another account is
# written or touched.
#
# assets(ids:) has returned [] three times because C had no asset to ask for.
# This gets a real id in place so the answer means something.

set -uo pipefail
: "${TOKEN_B:?export TOKEN_B first}"
: "${TOKEN_C:?export TOKEN_C first}"

C_ITEM=3209838125
C_BOARD=5103704617
API=https://api.monday.com/v2
FILE_API=https://api.monday.com/v2/file
MARK="CANARY-$$-$(date +%H%M%S)"

R=$'\033[31m'; G=$'\033[32m'; Y=$'\033[33m'; BD=$'\033[1m'; D=$'\033[2m'; N=$'\033[0m'
TMP=""
cleanup() { [ -n "$TMP" ] && rm -f "$TMP"; }
trap cleanup EXIT

cq() { curl -s "$API" -H "Authorization: $1" -H 'Content-Type: application/json' \
         --max-time 25 -d "{\"query\":\"$2\"}" 2>/dev/null; }

echo
echo "${BD}=== canary check on account C ===${N}"
echo

# ---------- 1. what does C already have? ----------
echo "${BD}[1/5] looking for an asset already on C's board${N}"
HAVE=$(cq "$TOKEN_C" "{ boards(ids: [\\\"$C_BOARD\\\"]) { items_page { items { id name updates { id } assets { id name file_size public_url } } } } }")
echo "${D}  $(printf '%s' "$HAVE" | head -c 400)${N}"

C_ASSET="${C_ASSET:-$(printf '%s' "$HAVE" | grep -o '"assets":\[{"id":"[0-9]*"' | head -1 | grep -o '[0-9]\{3,\}')}"
C_UPDATE="${C_UPDATE:-$(printf '%s' "$HAVE" | grep -o '"updates":\[{"id":"[0-9]*"' | head -1 | grep -o '[0-9]\{3,\}')}"

# ---------- 2. upload only if there is nothing there ----------
if [ -z "${C_ASSET:-}" ]; then
  echo
  echo "${Y}  no asset found - uploading one${N}"
  TMP="${TMPDIR:-/tmp}/canary-$$.txt"
  printf '%s\n' "$MARK" > "$TMP"
  UP=$(curl -s "$FILE_API" -H "Authorization: $TOKEN_C" --max-time 40 \
    -F "query=mutation add_file(\$file: File!) { add_file_to_item(item_id: $C_ITEM, file: \$file) { id name url } }" \
    -F "variables[file]=@$TMP;filename=canary.txt" 2>/dev/null)
  echo "${D}  $UP${N}"
  C_ASSET=$(printf '%s' "$UP" | grep -o '"id":"[0-9]*"' | head -1 | grep -o '[0-9]*')
  if [ -z "${C_ASSET:-}" ]; then
    echo "${R}  upload failed - nothing below can run without an asset id.${N}"
    echo "${Y}  If the error mentions scope, C's token needs boards:write. Or upload"
    echo "  by hand and pass the id in:  C_ASSET=<id> bash plant-canary.sh${N}"
    exit 1
  fi
else
  echo "${G}  found asset $C_ASSET - no upload needed${N}"
fi
echo "${G}  asset id:  $C_ASSET${N}"

# a 0-byte file still proves a metadata leak, but cannot prove a content download
SIZE=$(printf '%s' "$HAVE" | grep -o "\"id\":\"$C_ASSET\",\"name\":\"[^\"]*\",\"file_size\":[0-9]*" | grep -o '[0-9]*$')
if [ "${SIZE:-1}" = "0" ]; then
  echo "${Y}  note: that file is 0 bytes. Fine for the metadata test below, but a"
  echo "  download proof needs content - re-upload a file with a line of text in it.${N}"
fi

# ---------- 3. an update to go with it ----------
if [ -z "${C_UPDATE:-}" ]; then
  echo
  echo "${BD}[2/5] posting an update on item $C_ITEM (as C)${N}"
  UPD=$(cq "$TOKEN_C" "mutation { create_update(item_id: $C_ITEM, body: \\\"$MARK\\\") { id } }")
  echo "${D}  $UPD${N}"
  C_UPDATE=$(printf '%s' "$UPD" | grep -o '"id":"[0-9]*"' | head -1 | grep -o '[0-9]*')
fi
[ -n "${C_UPDATE:-}" ] && echo "${G}  update id: $C_UPDATE${N}" \
                       || echo "${Y}  no update id - update tests skipped${N}"

# ---------- 4. ground truth: what C itself sees ----------
echo
echo "${BD}[3/5] ground truth - C reading its own asset${N}"
OWN=$(cq "$TOKEN_C" "{ assets(ids: [\\\"$C_ASSET\\\"]) { id name file_size public_url uploaded_by { id name } } }")
echo "${D}  $(printf '%s' "$OWN" | head -c 320)${N}"
if printf '%s' "$OWN" | grep -q '"public_url"'; then
  echo "${G}  C can read it. A negative from B below is now a real negative.${N}"
else
  echo "${R}  C cannot read its own asset. Stop - B's result would be meaningless.${N}"
  exit 1
fi

# ---------- 5. the test ----------
echo
echo "${BD}[4/5] the test - B reading C's objects${N}"
echo

t() { # t <label> <body> <needle...>
  local label="$1" body="$2"; shift 2
  printf '  %s\n     %s%s%s\n' "$label" "$D" "$(printf '%s' "$body" | head -c 300)" "$N"
  local hit=0 nd
  if printf '%s' "$body" | grep -q '"data":' && ! printf '%s' "$body" | grep -q '"errors":'; then
    for nd in "$@"; do printf '%s' "$body" | grep -qF "$nd" && hit=1; done
  fi
  if [ "$hit" = 1 ]; then
    echo "  ${R}${BD}>>> HIT - C's object came back to B. This is the finding.${N}"
  elif printf '%s' "$body" | grep -qE '"(assets|updates|items|boards)":\[\]'; then
    echo "  ${G}    pass - authorized away${N}"
  elif printf '%s' "$body" | grep -q '"errors":'; then
    echo "  ${G}    pass - denied${N}"
  else
    echo "  ${Y}    read this one yourself${N}"
  fi
  echo
}

t "assets(ids: $C_ASSET) as B" \
  "$(cq "$TOKEN_B" "{ assets(ids: [\\\"$C_ASSET\\\"]) { id name file_size public_url uploaded_by { id name email } } }")" \
  "canary" "public_url"

if [ -n "${C_UPDATE:-}" ]; then
  t "updates(ids: $C_UPDATE) as B" \
    "$(cq "$TOKEN_B" "{ updates(ids: [\\\"$C_UPDATE\\\"]) { id body text_body creator { id name email } } }")" \
    "$MARK" "text_body"
fi

t "search.updates as B" \
  "$(cq "$TOKEN_B" "{ search { updates(query: \\\"canary\\\") { results { id indexed_data { body board_id } } } } }")" \
  "$C_BOARD"

# ---------- the public_url ----------
echo "${BD}[5/5] fetching C's public_url with no Authorization header at all${N}"
PU=$(printf '%s' "$OWN" | sed 's/.*"public_url":"//;s/".*//' | sed 's/\\u0026/\&/g;s#\\/#/#g')
if [ -n "$PU" ] && [ "$PU" != "null" ]; then
  echo "${D}  $(printf '%s' "$PU" | head -c 130)...${N}"
  CODE=$(curl -s -o /dev/null -w '%{http_code}' --max-time 20 "$PU" 2>/dev/null)
  echo "  HTTP $CODE"
  if [ "$CODE" = "200" ]; then
    echo "  ${Y}${BD}  serves with no credentials.${N}"
    echo "${D}    Not a finding by itself - signed CDN urls normally do this. It becomes"
    echo "    one only if the url is stable over time, survives deleting the file, or"
    echo "    the signature is guessable. Check the query string for an expiry.${N}"
  else
    echo "  ${G}  not served without auth${N}"
  fi
else
  echo "${D}  no public_url returned${N}"
fi

echo
echo "${BD}--- ids, keep these ---${N}"
echo "  asset_id   $C_ASSET"
echo "  update_id  ${C_UPDATE:-none}"
echo "  item_id    $C_ITEM"
echo "  board_id   $C_BOARD"
echo
echo "${D}  For anything marked HIT, save the request_id from the extensions block of"
echo "  both C's response and B's response. Those two side by side are what makes"
echo "  the report reproducible for a triager.${N}"
