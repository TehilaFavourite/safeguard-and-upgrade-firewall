#!/usr/bin/env bash
# ADR 0020 (D1): the two test seams must be defined exactly once in src/ and never overridden there.
# Test-only subclasses in test/ may override them. Exit status 1 on any violation.
set -euo pipefail

SRC_DIR="${1:-src}"
status=0

for seam in _checkOperation _compareProtectedState; do
    # Count definitions across src/ (signatures may span several lines, so match on the name).
    # `|| true`: no match is a result to report, not a reason for `set -e` to abort silently.
    defs=$({ grep -rhoE "function[[:space:]]+${seam}[[:space:]]*\(" "${SRC_DIR}" || true; } | wc -l | tr -d ' ')
    if [ "${defs}" != "1" ]; then
        echo "seam ${seam}: expected exactly 1 definition in ${SRC_DIR}/, found ${defs}"
        status=1
    fi
    # Reject any definition whose signature (up to the body or ';') contains `override`.
    hits=$(perl -0777 -ne "while (/function\\s+${seam}\\s*\\([^)]*\\)[^{;]*\\boverride\\b/g) { print \"\$ARGV\\n\" }" \
        $(find "${SRC_DIR}" -name '*.sol') || true)
    if [ -n "${hits}" ]; then
        echo "seam ${seam} is overridden in src/ (only test subclasses may override it):"
        echo "${hits}"
        status=1
    fi
done

if [ "${status}" = "0" ]; then
    echo "seam check: ok"
fi
exit "${status}"
