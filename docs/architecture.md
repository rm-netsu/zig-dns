# Architecture

## Layering

The package is split into small protocol modules rather than a single resolver object.

- `types`, `name`, `message`: wire model and zero-copy parsing.
- `builder`: allocation-free message construction and RFC 1035 compression.
- `rdata`, `dnssec`, `svcb`, `edns`, `validate`: typed interpretation and structural validation.
- `client`, `resolver`, `server`: transaction-oriented composition without transport ownership.
- `udp`, `tcp`, `dot`, `doq`, `doh`: transport adaptation at the DNS-message boundary.

A consumer can stop at any layer. A DNS proxy can use `Message`/`Record` directly, while a stub resolver can use `resolver.FixedTransactions` and still supply its own event loop.

## Ownership and lifetime

Parsing is borrowed. `Message.init(packet)` stores a slice to `packet`, and all `Name`, `Question`, `Record`, RDATA slices, EDNS options, and SVC params obtained from it are valid only while that packet remains unchanged.

Name decompression is explicit. `Name.writeWire`, `writeCanonicalWire`, and `writePresentation` copy only when the application asks for a materialized form.

`tcp.Decoder` owns no memory. Its returned message borrows the storage provided to `Decoder.init` and will be overwritten as the next framed message is assembled.

## Builder transactions

`Builder` writes into caller memory and keeps a caller-provided compression table. High-level builder operations checkpoint:

- output position;
- compression-table length;
- section phase.

If an operation fails locally, it restores that checkpoint. A manual `RecordWriter` can be abandoned with `abort()` before retrying with different input or a larger buffer.

DNS messages are capped to the 16-bit stream-framing limit even when a larger output slice is supplied.

## Names

Compression pointers are accepted only when they point to an earlier packet position. This matches RFC 1035 message compression and avoids forward/self pointer graphs.

The simple dotted API is intended for ordinary DNS names. Full wire names are represented with `name.Uncompressed`, so labels can contain any allowed octet, including bytes that have special meaning in textual zone-file syntax.

Name equality used for transaction matching is label-aware and ASCII case-insensitive; it does not compare a flattened dotted representation.

## Unknown protocol values

`Type`, `Class`, `Opcode`, and `Rcode` are non-exhaustive enums. Unknown RR types and classes are preserved numerically. `Record.rdata` is always available, so new RRTYPEs do not require a library release merely to transit or inspect them.

Strict validation applies structural rules only to RR types it understands. Unknown records remain opaque.
