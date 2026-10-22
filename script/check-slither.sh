#!/usr/bin/env bash
# Slither gate (engineering principles; docs/slither-triage.md). Every finding, at any impact level,
# must be on the accepted list (script/slither-accepted.txt), keyed by detector and contract member,
# not by line, so moving code doesn't break the gate. Fails on any new finding, and on any accepted
# entry Slither no longer reports, so the list stays exact.
set -euo pipefail

SLITHER="${SLITHER:-slither}"
ACCEPTED="script/slither-accepted.txt"
dir=$(mktemp -d)
trap 'rm -rf "${dir}"' EXIT
out="${dir}/slither.json" # slither refuses to overwrite an existing file, so the path must be new

# Slither exits non-zero whenever it reports findings; the comparison below decides pass/fail.
"${SLITHER}" . --filter-paths 'lib/|test/|script/' --exclude-dependencies --json "${out}" >/dev/null 2>&1 || true
if ! jq -e '.success' "${out}" >/dev/null; then
    echo "slither failed to run:"
    jq -r '.error // "no output"' "${out}"
    exit 1
fi

found=$(jq -r '.results.detectors // [] | .[] | .check + " " + (.elements[0] |
    (if .type_specific_fields.parent.name then .type_specific_fields.parent.name + "." else "" end) + .name)' \
    "${out}" | sort -u)
accepted=$(sed -e 's/#.*//' -e 's/[[:space:]]*$//' "${ACCEPTED}" | grep -v '^$' | sort -u)

new=$(comm -23 <(echo "${found}") <(echo "${accepted}"))
stale=$(comm -13 <(echo "${found}") <(echo "${accepted}"))
total=$(jq '.results.detectors // [] | length' "${out}")

status=0
if [ -n "${new}" ]; then
    echo "untriaged slither findings (fix, or triage in docs/slither-triage.md and ${ACCEPTED}):"
    sed 's/^/  /' <<<"${new}"
    status=1
fi
if [ -n "${stale}" ]; then
    echo "accepted entries slither no longer reports (prune ${ACCEPTED}):"
    sed 's/^/  /' <<<"${stale}"
    status=1
fi
[ "${status}" -eq 0 ] && echo "slither check: ok (${total} findings, all triaged)"
exit "${status}"
