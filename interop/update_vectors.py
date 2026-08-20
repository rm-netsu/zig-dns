#!/usr/bin/env python3
"""Validate a Zig-generated signed RFC 2136 UPDATE with dnspython."""

import struct
import subprocess
import sys

import dns.message
import dns.name
import dns.opcode
import dns.rdata
import dns.rdataclass
import dns.rdatatype
import dns.tsig

NOW = 1_800_000_000


def run_fixture(path: str) -> bytes:
    proc = subprocess.run([path], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    text = (proc.stdout + proc.stderr).strip()
    for line in reversed(text.splitlines()):
        line = line.strip()
        if line and all(c in "0123456789abcdefABCDEF" for c in line) and len(line) % 2 == 0:
            return bytes.fromhex(line)
    raise RuntimeError("fixture did not emit UPDATE wire hex")


def find_tsig(wire: bytes):
    if len(wire) < 12:
        raise ValueError("short DNS message")
    qd, an, ns, ar = struct.unpack("!HHHH", wire[4:12])
    off = 12
    for _ in range(qd):
        _, used = dns.name.from_wire(wire, off)
        off += used + 4
    for _ in range(an + ns + ar):
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


def without_tsig(wire: bytes, tsig_start: int) -> bytes:
    arcount = struct.unpack("!H", wire[10:12])[0]
    if arcount == 0:
        raise ValueError("TSIG with zero ARCOUNT")
    return wire[:10] + struct.pack("!H", arcount - 1) + wire[12:tsig_start]


def expect_rr(rrsets, owner: str, rdtype: int, rdclass: int, *, deleting: int | None = None, ttl: int | None = None, rdata: str | None = None):
    wanted_name = dns.name.from_text(owner)
    for rrset in rrsets:
        if rrset.name != wanted_name or rrset.rdtype != rdtype or rrset.rdclass != rdclass:
            continue
        if getattr(rrset, "deleting", None) != deleting:
            continue
        if ttl is not None and rrset.ttl != ttl:
            continue
        if rdata is not None and not any(item.to_text() == rdata for item in rrset):
            continue
        return
    raise AssertionError(f"missing RR {owner} type={rdtype} class={rdclass} deleting={deleting} ttl={ttl} rdata={rdata!r}")


def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit("usage: update_vectors.py <fixture-executable>")
    wire = run_fixture(sys.argv[1])
    tsig_start, owner, tsig_rdata = find_tsig(wire)
    key = dns.tsig.Key("update-key.example", b"interop update secret", "hmac-sha256")
    dns.tsig.validate(wire, key, owner, tsig_rdata, NOW, b"", tsig_start, None, False)

    msg = dns.message.from_wire(without_tsig(wire, tsig_start), one_rr_per_rrset=True)
    if msg.opcode() != dns.opcode.UPDATE:
        raise AssertionError("not an UPDATE message")
    if len(msg.question) != 1:
        raise AssertionError("invalid Zone section count")
    zone = msg.question[0]
    if zone.name != dns.name.from_text("example.com") or zone.rdtype != dns.rdatatype.SOA or zone.rdclass != dns.rdataclass.IN:
        raise AssertionError("unexpected Zone section")

    # Prerequisite section (the DNS Answer section on the wire).
    expect_rr(msg.answer, "host.example.com", dns.rdatatype.ANY, dns.rdataclass.IN, deleting=dns.rdataclass.ANY, ttl=0)
    expect_rr(msg.answer, "host.example.com", dns.rdatatype.AAAA, dns.rdataclass.IN, deleting=dns.rdataclass.NONE, ttl=0)
    expect_rr(msg.answer, "host.example.com", dns.rdatatype.A, dns.rdataclass.IN, ttl=0, rdata="192.0.2.1")

    # Update section (the DNS Authority section on the wire).
    expect_rr(msg.authority, "host.example.com", dns.rdatatype.A, dns.rdataclass.IN, ttl=300, rdata="192.0.2.42")
    expect_rr(msg.authority, "host.example.com", dns.rdatatype.TXT, dns.rdataclass.IN, deleting=dns.rdataclass.ANY, ttl=0)
    expect_rr(msg.authority, "stale.example.com", dns.rdatatype.A, dns.rdataclass.IN, deleting=dns.rdataclass.NONE, ttl=0, rdata="192.0.2.99")

    print("validated signed RFC 2136 UPDATE and TSIG with dnspython")


if __name__ == "__main__":
    main()
