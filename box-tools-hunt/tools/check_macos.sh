#!/usr/bin/env bash
#
# Box Tools — macOS security posture audit.
#
# Focus, in order of what pays:
#   1. com.apple.quarantine on files Box Edit downloads. Missing == Gatekeeper never runs.
#   2. Code signature and entitlements on the two app bundles (library validation, get-task-allow).
#   3. Whether anything PRIVILEGED launches or trusts the user-writable bundle directory.
#      Per-user install being user-writable is NOT a finding on its own — do not report it.
#   4. Listening sockets and credential storage.
#
# Read-only.

set -uo pipefail

BOX_DIR="$HOME/Library/Application Support/Box/Box Edit"
RED=$'\033[31m'; GRN=$'\033[32m'; CYN=$'\033[36m'; YLW=$'\033[33m'; RST=$'\033[0m'
head() { printf '\n%s=== %s ===%s\n' "$CYN" "$1" "$RST"; }
hit()  { printf '  %s[!]%s %s\n' "$RED" "$RST" "$1"; }
ok()   { printf '  %s[ok]%s %s\n' "$GRN" "$RST" "$1"; }

head "Install layout"
if [[ -d "$BOX_DIR" ]]; then
  ls -la@ "$BOX_DIR"
else
  hit "Not found at $BOX_DIR — is Box Tools installed for this user?"
  find /Applications "$HOME/Applications" -maxdepth 2 -iname "*Box*" 2>/dev/null
fi

head "Quarantine flag on downloaded files"
# Box Edit's cache location varies by version; search the Box tree for recent files.
# macOS ships bash 3.2, so no mapfile — stage the list in a temp file instead.
RECENT=$(mktemp -t boxhunt)
trap 'rm -f "$RECENT"' EXIT
find "$HOME/Library/Application Support/Box" \
     "$HOME/Library/Containers" -type f -mmin -240 2>/dev/null | head -60 > "$RECENT"
if [[ ! -s "$RECENT" ]]; then
  echo "  No files touched in the last 4h. Open a file from the Box web app, then re-run."
else
  missing=0
  while IFS= read -r f; do
    if xattr -p com.apple.quarantine "$f" >/dev/null 2>&1; then
      printf '  quarantined: %s\n' "${f##*/}"
    else
      case "${f##*.}" in
        app|dmg|pkg|command|terminal|workflow|jar|sh|py|scpt|webloc|inetloc|docm|xlsm|pptm)
          hit "NO quarantine xattr on ${f}"
          missing=$((missing+1)) ;;
        *)
          printf '  no xattr:    %s\n' "${f##*/}" ;;
      esac
    fi
  done < "$RECENT"
  if [[ $missing -gt 0 ]]; then
    printf '\n'
    hit "Executable/macro-capable files arrive without com.apple.quarantine."
    printf '      %sGatekeeper never evaluates them. An unsigned .app or .command shared into a\n' "$YLW"
    printf '      Box folder by a collaborator launches with no prompt. Demo it with a second\n'
    printf '      Box account sharing the file, and screenshot the missing Gatekeeper dialog.%s\n' "$RST"
  fi
fi

head "Code signature and entitlements"
for app in "$BOX_DIR/Box Edit.app" "$BOX_DIR/Box Local Com Server.app"; do
  [[ -d "$app" ]] || continue
  printf '\n  %s\n' "$app"
  codesign -dvvv "$app" 2>&1 | sed 's/^/    /' | grep -Ei 'Authority|TeamIdentifier|flags|Identifier' 
  ents=$(codesign -d --entitlements - "$app" 2>/dev/null)
  printf '%s\n' "$ents" | sed 's/^/    /' | head -30
  grep -q 'get-task-allow'                 <<<"$ents" && hit "get-task-allow present — any local process can attach a debugger and read its memory (tokens)."
  grep -q 'disable-library-validation'     <<<"$ents" && hit "Library validation disabled — dylib injection into a process holding Box credentials."
  grep -q 'allow-dyld-environment-variables' <<<"$ents" && hit "DYLD env vars allowed — injection via DYLD_INSERT_LIBRARIES."
  codesign -dvvv "$app" 2>&1 | grep -q 'flags=.*runtime' || hit "Hardened runtime NOT enabled."
  # Notarization / Gatekeeper assessment
  spctl -a -vvv "$app" 2>&1 | sed 's/^/    spctl: /'
done

head "Privileged components (this is what makes bundle writability matter)"
found_priv=0
for d in /Library/LaunchDaemons /Library/LaunchAgents; do
  while IFS= read -r p; do
    [[ -z "$p" ]] && continue
    found_priv=1
    printf '  %s\n' "$p"
    /usr/libexec/PlistBuddy -c "Print" "$p" 2>/dev/null | sed 's/^/      /' | head -20
    hit "Runs with elevated privileges — check whether its Program/ProgramArguments path is user-writable."
  done < <(grep -rl -i box "$d" 2>/dev/null)
done
ls -la /Library/PrivilegedHelperTools/ 2>/dev/null | grep -i box && found_priv=1
[[ $found_priv -eq 0 ]] && ok "No privileged Box helper found. Bundle writability under \$HOME is therefore NOT a finding."

head "User LaunchAgents"
grep -rl -i box "$HOME/Library/LaunchAgents" 2>/dev/null | while read -r p; do
  printf '  %s\n' "$p"
  /usr/libexec/PlistBuddy -c "Print" "$p" 2>/dev/null | sed 's/^/      /' | head -20
done
launchctl list 2>/dev/null | grep -i box | sed 's/^/  /'

head "Listening sockets"
lsof -nP -iTCP:17223 -sTCP:LISTEN 2>/dev/null | sed 's/^/  /'
lsof -nP -iTCP:17224 -sTCP:LISTEN 2>/dev/null | sed 's/^/  /'
lsof -nP -iTCP -sTCP:LISTEN 2>/dev/null | grep -i box | sed 's/^/  /'
echo "  (Anything bound to * or 0.0.0.0 rather than 127.0.0.1 is network-reachable — that is a finding.)"

head "Credential storage"
security find-generic-password -s "Box" 2>&1 | head -5 | sed 's/^/  keychain: /'
grep -rlE 'access_token|refresh_token|client_secret' \
  "$HOME/Library/Application Support/Box" \
  "$HOME/Library/Preferences" 2>/dev/null | while read -r f; do
    hit "possible plaintext credential material: $f"
done

head "Next"
cat <<'NEXT'
  1. sudo tcpdump -i lo0 -A -s0 'tcp port 17223'   <- learn the real protocol
  2. python3 probe_com_server.py                    <- origin / host / method matrix
  3. serve origin_test.html from a non-Box origin   <- prove cross-origin reachability
NEXT
printf '\n'
