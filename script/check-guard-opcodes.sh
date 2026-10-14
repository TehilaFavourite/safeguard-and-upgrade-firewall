#!/usr/bin/env bash
# ADR 0020 decision 7: the guard only ever READS the Safe, through STATICCALL. Fails if the deployed
# runtime code of SafeFirewallGuard contains CALL, DELEGATECALL or CALLCODE before the CBOR metadata.
# (Bytes after the metadata marker are data, not reachable code.)
set -euo pipefail

CONTRACT="${1:-SafeFirewallGuard}"
code=$(forge inspect "${CONTRACT}" deployedBytecode)
code="${code#0x}"

# The Solidity CBOR metadata starts with a2 64 'ipfs' 58 22; everything from there on is data.
marker="a264697066735822"
prefix="${code%%${marker}*}"
if [ "${prefix}" = "${code}" ]; then
    echo "metadata marker not found in ${CONTRACT} runtime code"
    exit 1
fi

forbidden=$(cast disassemble "0x${prefix}" | awk '{print $2}' | grep -cE '^(CALL|DELEGATECALL|CALLCODE)$' || true)
staticcalls=$(cast disassemble "0x${prefix}" | awk '{print $2}' | grep -cE '^STATICCALL$' || true)

if [ "${forbidden}" != "0" ]; then
    echo "${CONTRACT}: ${forbidden} CALL/DELEGATECALL/CALLCODE opcode(s) in runtime code (expected 0)"
    exit 1
fi
echo "opcode check: ok (${CONTRACT}: 0 CALL/DELEGATECALL/CALLCODE, ${staticcalls} STATICCALL)"
