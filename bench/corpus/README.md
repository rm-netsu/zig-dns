# Real DNS benchmark corpus

These `.dns` files are deterministic DNS wire fixtures used by `bench/core.zig`.
They are **normalized snapshots built from real RRsets**, not literal packet
captures. The benchmark must stay reproducible even when DNS data changes, so
network access is never performed at benchmark runtime.

Snapshot date: **2026-08-20**.

The corpus covers:

- short A and AAAA answers;
- multi-record NS, CAA, MX, and TXT answers;
- a CNAME chain;
- DS and a large root DNSKEY response;
- NODATA and NXDOMAIN with SOA authority data;
- a large `.com` delegation/referral with 13 NS records, DS, and IPv4/IPv6 glue;
- EDNS on every fixture.

Sources used to construct the RRsets include public DNS observations for
`cloudflare.com`, `status.openai.com`, `gmail.com`, `chatgpt.com`,
`dns.google`, and `example.com`; Google Public DNS for the root DNSKEY RRset
(`https://dns.google/resolve?name=.&type=DNSKEY`); and IANA's `.com`
delegation record (`https://www.iana.org/domains/root/db/com`) for the
referral/glue fixture.

Normalization intentionally permits changes to fields that are not useful for
comparing parser/builder implementations, including message IDs, TTLs, RR
ordering, response flags, and EDNS payload size. The root DNSKEY TTL is fixed
to 3600 seconds. The `.com` delegation uses 172800-second NS/glue TTLs and an
86400-second DS TTL. DNSSEC signatures are excluded from that referral fixture
so it remains stable across signature rollovers.

When refreshing a fixture, record the source/date here and regenerate the
corresponding builder case in `bench/core.zig`. Do not fetch live DNS inside a
benchmark run.
