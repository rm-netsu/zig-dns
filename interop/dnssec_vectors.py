#!/usr/bin/env python3
"""Independent DNSSEC vector replay using dnspython.

This is an optional interoperability gate. It intentionally does not run from
`zig build test` so the Zig package has no Python runtime dependency.
"""

from __future__ import annotations

import dns.dnssec
import dns.name
import dns.rrset


VECTORS = (
    {
        "name": "RFC 8080 erratum 4935 Ed25519",
        "owner": "example.com.",
        "rr": ("MX", "10 mail.example.com."),
        "dnskey": "257 3 15 l02Woi0iS8Aa25FQkUd9RMzZHJpBoRQwAQEX1SxZJA4=",
        "rrsig": "MX 15 2 3600 1440021600 1438207200 3613 example.com. oL9krJun7xfBOIWcGHi7mag5/hdZrKWw15jPGrHpjQeRAvTdszaPD+QLs3fx8A4M3e23mRZ9VrbpMngwcrqNAg==",
        "now": 1438207200,
    },
    {
        "name": "RFC 6605 ECDSA P-256",
        "owner": "www.example.net.",
        "rr": ("A", "192.0.2.1"),
        "key_owner": "example.net.",
        "dnskey": "257 3 13 GojIhhXUN/u4v54ZQqGSnyhWJwaubCvTmeexv7bR6edbkrSqQpF64cYbcB7wNcP+e+MAnLr+Wi9xMWyQLc8NAA==",
        "rrsig": "A 13 3 3600 1284026679 1281607479 55648 example.net. qx6wLYqmh+l9oCKTN6qIc+bw6ya+KJ8oMz0YP107epXAyGmt+3SNruPFKG7tZoLBLlUzGGus7ZwmwWep666VCw==",
        "now": 1281607479,
    },
    {
        "name": "RFC 6605 ECDSA P-384",
        "owner": "www.example.net.",
        "rr": ("A", "192.0.2.1"),
        "key_owner": "example.net.",
        "dnskey": "257 3 14 xKYaNhWdGOfJ+nPrL8/arkwf2EY3MDJ+SErKivBVSum1w/egsXvSADtNJhyem5RCOpgQ6K8X1DRSEkrbYQ+OB+v8/uX45NBwY8rp65F6Glur8I/mlVNgF6W/qTI37m40",
        "rrsig": "A 14 3 3600 1284027625 1281608425 10771 example.net. /L5hDKIvGDyI1fcARX3z65qrmPsVz73QD1Mr5CEqOiLP95hxQouuroGCeZOvzFaxsT8Glr74hbavRKayJNuydCuzWTSSPdz7wnqXL5bdcJzusdnI0RSMROxxwGipWcJm",
        "now": 1281608425,
    },
    {
        "name": "RFC 5702 RSA-SHA256",
        "owner": "www.example.net.",
        "rr": ("A", "192.0.2.91"),
        "key_owner": "example.net.",
        "dnskey": "256 3 8 AwEAAcFcGsaxxdgiuuGmCkVImy4h99CqT7jwY3pexPGcnUFtR2Fh36BponcwtkZ4cAgtvd4Qs8PkxUdp6p/DlUmObdk=",
        "rrsig": "A 8 3 3600 1893456000 946684800 9033 example.net. kRCOH6u7l0QGy9qpC9l1sLncJcOKFLJ7GhiUOibu4teYp5VE9RncriShZNz85mwlMgNEacFYK/lPtPiVYP4bwg==",
        "now": 946684800,
    },
    {
        "name": "RFC 5702 RSA-SHA512",
        "owner": "www.example.net.",
        "rr": ("A", "192.0.2.91"),
        "key_owner": "example.net.",
        "dnskey": "256 3 10 AwEAAdHoNTOW+et86KuJOWRDp1pndvwb6Y83nSVXXyLA3DLroROUkN6X0O6pnWnjJQujX/AyhqFDxj13tOnD9u/1kTg7cV6rklMrZDtJCQ5PCl/D7QNPsgVsMu1J2Q8gpMpztNFLpPBz1bWXjDtaR7ZQBlZ3PFY12ZTSncorffcGmhOL",
        "rrsig": "A 10 3 3600 1893456000 946684800 3740 example.net. tsb4wnjRUDnB1BUi+t6TMTXThjVnG+eCkWqjvvjhzQL1d0YRoOe0CbxrVDYd0xDtsuJRaeUw1ep94PzEWzr0iGYgZBWm/zpq+9fOuagYJRfDqfReKBzMweOLDiNa8iP5g9vMhpuv6OPlvpXwm9Sa9ZXIbNl1MBGk0fthPgxdDLw=",
        "now": 946684800,
    },
)


def validate(vector: dict[str, object]) -> None:
    owner = str(vector["owner"])
    key_owner = str(vector.get("key_owner", owner))
    rr_type, rr_text = vector["rr"]
    rrset = dns.rrset.from_text(owner, 3600, "IN", rr_type, rr_text)
    rrsigs = dns.rrset.from_text(owner, 3600, "IN", "RRSIG", str(vector["rrsig"]))
    dnskeys = dns.rrset.from_text(key_owner, 3600, "IN", "DNSKEY", str(vector["dnskey"]))
    keys = {dns.name.from_text(key_owner): dnskeys}
    dns.dnssec.validate(rrset, rrsigs, keys, now=int(vector["now"]))


for item in VECTORS:
    validate(item)
    print(f"ok: {item['name']}")

print(f"validated {len(VECTORS)} independent DNSSEC vectors with dnspython")
