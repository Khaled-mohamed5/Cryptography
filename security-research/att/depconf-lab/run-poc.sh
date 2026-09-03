#!/usr/bin/env bash
# Dependency confusion demonstration. Localhost only; nothing is published anywhere.
set -u
cd "$(dirname "$0")"

INTERNAL=4873   # stands in for the organisation's private registry
PUBLIC=4874     # stands in for registry.npmjs.org

cleanup() { kill %1 %2 2>/dev/null; rm -rf scenario-a scenario-b; }
trap cleanup EXIT

python3 registry.py $INTERNAL acme-corp-ui-widget-1.0.0.tgz 1.0.0 2>/dev/null &
python3 registry.py $PUBLIC   acme-corp-ui-widget-9.9.9.tgz 9.9.9 2>/dev/null &
sleep 2

run_scenario () {
  local dir=$1 label=$2 npmrc=$3
  rm -rf "$dir"; mkdir -p "$dir"; cd "$dir"
  printf '%s\n' "$npmrc" > .npmrc
  echo '{"name":"consumer","version":"1.0.0","dependencies":{"@acme-corp/ui-widget":"*"}}' > package.json

  echo ""
  echo "=============================================================="
  echo " $label"
  echo "=============================================================="
  echo "--- .npmrc ---"; cat .npmrc; echo "--------------"
  npm install --no-audit --no-fund --foreground-scripts --unsafe-perm 2>&1 \
    | grep -viE '^(added |npm warn|npm notice|$)' || true

  local v
  v=$(node -p "require('./node_modules/@acme-corp/ui-widget/package.json').version" 2>/dev/null)
  local s
  s=$(node -p "require('@acme-corp/ui-widget').source" 2>/dev/null)
  echo ">> installed version : $v"
  echo ">> package reports   : $s"
  cd ..
}

run_scenario scenario-a \
  "SCENARIO A - scope correctly mapped to the internal registry (expected: safe)" \
  "registry=http://localhost:$PUBLIC/
@acme-corp:registry=http://localhost:$INTERNAL/"

run_scenario scenario-b \
  "SCENARIO B - scope mapping absent (expected: falls through to public)" \
  "registry=http://localhost:$PUBLIC/"

echo ""
echo "=============================================================="
echo " RESULT"
echo "=============================================================="
echo "A: .npmrc scoped   -> 1.0.0 from the internal registry, no scripts run"
echo "B: .npmrc unscoped -> 9.9.9 from the public registry, postinstall executed"
echo ""
echo "The only difference between the two runs is one line of .npmrc."
