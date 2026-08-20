#!/usr/bin/env python3
"""Validate Zig-generated RFC 8945 TSIG messages with dnspython."""

import struct
import subprocess
import sys

import dns.name
import dns.rdata
import dns.rdataclass
import dns.rdatatype
import dns.tsig

NOW_REQUEST = 1_700_000_000
NOW_RESPONSE = 1_700_000_001
NOW_CONTINUATION = 1_700_000_002


def run_fixture(path: str) -> dict[str, bytes]:
    proc = subprocess.run([path], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    values: dict[str, bytes] = {}
    for line in (proc.stdout + proc.stderr).splitlines():
        if "=" not in line:
            continue
        name, value = line.split("=", 1)
        values[name] = bytes.fromhex(value)
    required = {"request", "response", "continuation"}
    if values.keys() & required != required:
        missing = sorted(required - values.keys())
        raise RuntimeError(f"fixture did not emit: {', '.join(missing)}")
    return values


def find_tsig(wire: bytes):
    if len(wire) < 12:
        raise ValueError("short DNS message")
    qd, an, ns, ar = struct.unpack("!HHHH", wire[4:12])
    off = 12
    for _ in range(qd):
        _, used = dns.name.from_wire(wire, off)
        off += used + 4
    total = an + ns + ar
    for _ in range(total):
        owner_start = off
        owner, used = dns.name.from_wire(wire, off)
        off += used
        rdtype, rdclass, ttl, rdlen = struct.unpack("!HHIH", wire[off : off + 10])
        off += 10
        rdata_off = off
        off += rdlen
        if rdtype == dns.rdatatype.TSIG:
            rdata = dns.rdata.from_wire(rdclass, rdtype, wire, rdata_off, rdlen)
            return owner_start, owner, rdata
    raise ValueError("TSIG not found")


def validate(wire: bytes, key: dns.tsig.Key, now: int, request_mac=b"", ctx=None, multi=False):
    start, owner, rdata = find_tsig(wire)
    next_ctx = dns.tsig.validate(wire, key, owner, rdata, now, request_mac, start, ctx, multi)
    return rdata.mac, next_ctx


def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit("usage: tsig_vectors.py <fixture-executable>")
    values = run_fixture(sys.argv[1])
    key = dns.tsig.Key("key.example", b"shared secret bytes", "hmac-sha256")

    request_mac, _ = validate(values["request"], key, NOW_REQUEST)
    response_mac, response_ctx = validate(values["response"], key, NOW_RESPONSE, request_mac=request_mac, multi=True)
    continuation_mac, _ = validate(
        values["continuation"],
        key,
        NOW_CONTINUATION,
        ctx=response_ctx,
        multi=True,
    )

    if len(request_mac) != 32 or len(response_mac) != 32 or len(continuation_mac) != 32:
        raise AssertionError("unexpected TSIG MAC length")
    print("validated request, response, and continuation TSIGs with dnspython")


if __name__ == "__main__":
    main()
