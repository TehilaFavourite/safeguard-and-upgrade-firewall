#!/usr/bin/env bash
# Gas snapshot gate (engineering principles; ADR 0022). Usage: script/gas-snapshot.sh [--check]
# Scope: unit-variant tests that are not fuzz tests. Fuzz means change with the inputs, so they are
# noise for a regression gate even with a fixed seed. Fork-variant gas is the same code on other
# state, and it would need RPC in the unit CI job. With this scope the snapshot is deterministic and
# needs no secrets. Gas figures are only comparable within one forge version (pinned, ADR 0022).
set -euo pipefail
forge snapshot --no-match-contract 'ForkTest|ForkInfra' --no-match-test 'testFuzz' "$@"
