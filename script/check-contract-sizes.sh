#!/usr/bin/env bash
# Contract size gate (Phase 3 decision). EIP-170 limits runtime code to 24,576 bytes. The guard must
# keep headroom under it. GuardFactory embeds the guard's full init code for `new`, so it is always
# bigger than the guard, and it hits the limit first. Both are gated.
set -euo pipefail

GUARD_MAX="${GUARD_MAX:-22000}"
FACTORY_MAX="${FACTORY_MAX:-24576}"

sizes=$(forge build --sizes --json 2>/dev/null)
guard=$(jq -r '.SafeFirewallGuard.runtime_size' <<<"${sizes}")
factory=$(jq -r '.GuardFactory.runtime_size' <<<"${sizes}")
guard_init=$(jq -r '.SafeFirewallGuard.init_size' <<<"${sizes}")

status=0
if [ "${guard}" -gt "${GUARD_MAX}" ]; then
    echo "SafeFirewallGuard runtime ${guard} B exceeds ${GUARD_MAX} B"
    status=1
fi
if [ "${factory}" -gt "${FACTORY_MAX}" ]; then
    echo "GuardFactory runtime ${factory} B exceeds ${FACTORY_MAX} B (it embeds the guard init code: ${guard_init} B)"
    status=1
fi
echo "sizes: SafeFirewallGuard runtime ${guard} B (max ${GUARD_MAX}), init ${guard_init} B; GuardFactory runtime ${factory} B (max ${FACTORY_MAX})"
exit "${status}"
