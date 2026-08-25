#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
echo "== 1/3 fetch =="      && ./01-fetch.sh
echo "== 2/3 sourcemaps ==" && ./02-sourcemaps.py
echo "== 3/3 analyse =="    && ./03-analyze.py
echo
echo "read out/report.md  (endpoint probing is opt-in: ./04-verify-endpoints.sh https://www.bentleymotors.com)"
