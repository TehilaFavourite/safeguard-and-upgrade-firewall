#!/usr/bin/env bash
# Coverage gate (Phase 3 decision; engineering standard).
#  1. Completeness: every .sol file in src/ except interfaces must appear in the coverage report. Guards
#     against a filter silently dropping files, as the unanchored '(test|lib|script)' filter dropped
#     src/libraries/ in Phase 2.
#  2. Thresholds, per file: 100% lines and >= 95% branches. Forge lists even unused files (at 0%), so
#     presence alone would pass an untested file.
set -euo pipefail

FILTER="${COVERAGE_FILTER:-^(test|lib|script)/}"
MIN_LINES="${MIN_LINES:-100}"
MIN_BRANCHES="${MIN_BRANCHES:-95}"

report=$(forge coverage --report summary --no-match-coverage "${FILTER}" --no-match-contract 'ForkTest|ForkInfra' 2>&1)

status=0
while IFS= read -r file; do
    row=$(grep -F "| ${file} " <<<"${report}" || true)
    if [ -z "${row}" ]; then
        echo "missing from coverage report: ${file}"
        status=1
        continue
    fi
    lines=$(awk -F'|' '{print $3}' <<<"${row}" | grep -oE '^[ ]*[0-9.]+' | tr -d ' ')
    branches=$(awk -F'|' '{print $5}' <<<"${row}" | grep -oE '^[ ]*[0-9.]+' | tr -d ' ')
    if awk -v v="${lines}" -v m="${MIN_LINES}" 'BEGIN{exit !(v < m)}'; then
        echo "${file}: lines ${lines}% < ${MIN_LINES}%"
        status=1
    fi
    if awk -v v="${branches}" -v m="${MIN_BRANCHES}" 'BEGIN{exit !(v < m)}'; then
        echo "${file}: branches ${branches}% < ${MIN_BRANCHES}%"
        status=1
    fi
done < <(find src -name '*.sol' -not -path 'src/interfaces/*' | sort)

grep -E '^\| (src/|Total)' <<<"${report}"
if [ "${status}" = "0" ]; then
    echo "coverage gate: ok (all src/ files present; lines >= ${MIN_LINES}%, branches >= ${MIN_BRANCHES}%)"
fi
exit "${status}"
