const std = @import("std");
const types = @import("../types.zig");
const name_mod = @import("../name.zig");
const message = @import("../message.zig");
const builder = @import("../builder.zig");
const client = @import("../client.zig");
const core = @import("../resolver.zig");
const response_mod = @import("../resolver/response.zig");
const alias_mod = @import("../resolver/alias.zig");
const retry_mod = @import("../resolver/retry.zig");
const referral_mod = @import("../resolver/referral.zig");
const dnssec_status = @import("../dnssec/status.zig");

/// Compile-time storage limits for the high-level resolver state machine.
pub const Config = struct {
    max_queries: usize = 64,
    max_alias_depth: usize = 16,
    /// Total canonical wire-name bytes retained per active alias chain.
    alias_storage_bytes: usize = 1024,
};

pub const Handle = struct {
    index: usize,
    generation: u32,
};

/// Transport intent only. The resolver never owns the corresponding socket,
/// TLS session, QUIC connection/stream, or HTTP request.
pub const Transport = enum {
    udp,
    tcp,
    dot,
    doq,
    doh,
};

pub const BeginOptions = struct {
    query: core.QueryOptions = .{ .udp_payload_size = 1232 },
    /// Set when an application-specific EDNS option is mandatory even if DO
    /// and Compact Answers are both disabled.
    edns_required: bool = false,
    /// Number of caller-owned upstream server choices available to this query.
    server_count: usize = 1,
    transport: Transport = .udp,
    /// Caller-injected time used only for optional cache lookup.
    now: u64 = 0,
};

pub const DispatchReason = enum {
    initial,
    timeout,
    other_server,
    truncated,
    edns_fallback,
    alias,
    referral,
};

pub const Dispatch = struct {
    handle: Handle,
    id: u16,
    server_index: usize,
    transport: Transport,
    edns_enabled: bool,
    reason: DispatchReason,
};

pub const CompletionKind = enum {
    answer,
    nodata,
    nxdomain,
    /// The v0.6 lifecycle exposes a structurally validated referral as a
    /// terminal semantic result; iterative referral scheduling is layered in
    /// a later composition step without changing the wire/core API.
    referral,
};

pub const SecurityStatus = dnssec_status.SecurityStatus;

pub const CompletionSource = enum { network, cache };

pub const CacheHit = struct {
    kind: CompletionKind,
    security: SecurityStatus = .indeterminate,
    /// Opaque caller-defined identifier (for example, a fixed-cache slot).
    token: usize,
};

pub const CacheHooks = struct {
    context: *anyopaque,
    lookup: *const fn (*anyopaque, client.WireQuestionKey, u64) ?CacheHit,
    store: ?*const fn (*anyopaque, client.WireQuestionKey, CompletionKind, SecurityStatus, message.Message, u64) void = null,
};

pub const Completion = struct {
    handle: Handle,
    kind: CompletionKind,
    server_index: usize,
    source: CompletionSource,
    security: SecurityStatus,
    cache_token: ?usize = null,
};

pub const ReferralAction = struct {
    handle: Handle,
    /// Zero-copy referral view borrowing the response packet passed to
    /// `onResponse`. Consume its iterators before reusing that packet buffer.
    view: referral_mod.Referral,
    server_index: usize,
};

pub const FailureReason = enum {
    transport_failure,
    malformed_response,
    protocol_failure,
    server_failure,
    retry_budget_exhausted,
    alias_loop,
    alias_limit,
    alias_storage,
    dnssec_bogus,
};

pub const Failure = struct {
    handle: Handle,
    reason: FailureReason,
};

/// Actions are transport instructions, not I/O operations. The caller decides
/// how an upstream server index maps to an address/connection/runtime.
pub const Action = union(enum) {
    /// Send the current query, normally the initial query, an alias follow-up,
    /// or the first attempt at a different server.
    send: Dispatch,
    /// Re-send on the same server/transport (timeout or EDNS fallback).
    retry: Dispatch,
    /// TCP path needed for an initial TCP query or UDP truncation fallback.
    connect_tcp: Dispatch,
    /// DNS-over-TLS path. TLS/session ownership remains caller-side.
    connect_dot: Dispatch,
    /// Open/use one caller-owned QUIC stream for this query.
    open_doq_stream: Dispatch,
    /// Perform one caller-owned HTTP request carrying application/dns-message.
    perform_doh: Dispatch,
    /// Structurally validated delegation requiring caller server selection.
    referral: ReferralAction,
    complete: Completion,
    fail: Failure,
};

pub const Error = client.Error || builder.Error || alias_mod.Error || response_mod.Error || error{
    Full,
    NoServers,
    InvalidHandle,
    IdSpaceExhausted,
    EdnsFeatureWithoutOpt,
    UnknownTransaction,
    CorrelationHandleRequired,
    UnexpectedState,
};

pub fn Resolver(comptime config: Config) type {
    if (config.max_queries == 0) @compileError("Resolver.max_queries must be greater than zero");
    if (config.max_queries > 65535) @compileError("Resolver.max_queries cannot exceed the non-zero DNS ID space");
    if (config.max_alias_depth == std.math.maxInt(usize)) @compileError("Resolver.max_alias_depth is too large");

    return struct {
        const Self = @This();
        const Phase = enum { awaiting_response, referral_pending, complete, failed };

        const Slot = struct {
            active: bool = false,
            generation: u32 = 0,
            phase: Phase = .failed,
            id: u16 = 0,
            qtype: types.Type = .A,
            qclass: types.Class = .IN,
            query_options: core.QueryOptions = .{},
            edns_required: bool = false,
            edns_enabled: bool = false,
            preferred_transport: Transport = .udp,
            transport: Transport = .udp,
            server_count: usize = 0,
            server_index: usize = 0,
            queries_sent: u8 = 0,
            now: u64 = 0,
            security: SecurityStatus = .indeterminate,
            security_set: bool = false,
            alias_entries: [config.max_alias_depth + 1]alias_mod.Entry = undefined,
            alias_storage: [config.alias_storage_bytes]u8 = undefined,
            alias_count: usize = 0,
            alias_used: usize = 0,

            fn chain(self: *Slot) alias_mod.Chain {
                return .{
                    .entries = &self.alias_entries,
                    .storage = &self.alias_storage,
                    .count = self.alias_count,
                    .used = self.alias_used,
                };
            }

            fn saveChain(self: *Slot, chain_state: alias_mod.Chain) void {
                self.alias_count = chain_state.count;
                self.alias_used = chain_state.used;
            }

            fn currentName(self: *Slot) name_mod.Uncompressed {
                var c = self.chain();
                return c.currentName();
            }

            fn currentQuestion(self: *Slot) client.WireQuestionKey {
                return .{ .name = self.currentName(), .qtype = self.qtype, .qclass = self.qclass };
            }
        };

        pub const Storage = struct {
            slots: [config.max_queries]Slot = undefined,
        };

        storage: *Storage,
        cache_hooks: ?CacheHooks = null,
        next_id: u16 = 1,
        next_generation: u32 = 1,

        pub fn initInPlace(storage: *Storage) Self {
            return initStorage(storage, null);
        }

        pub fn initInPlaceWithCache(storage: *Storage, hooks: CacheHooks) Self {
            return initStorage(storage, hooks);
        }

        fn initStorage(storage: *Storage, hooks: ?CacheHooks) Self {
            for (&storage.slots) |*slot| {
                slot.active = false;
                slot.generation = 0;
            }
            return .{ .storage = storage, .cache_hooks = hooks };
        }

        pub fn activeCount(self: *const Self) usize {
            var count: usize = 0;
            for (&self.storage.slots) |*slot| count += @intFromBool(slot.active);
            return count;
        }

        pub fn beginPresentation(self: *Self, q: client.QuestionKey, options: BeginOptions) Error!Action {
            const index = try self.reserveSlot(options);
            var slot = &self.storage.slots[index];
            errdefer slot.active = false;

            const chain_state = try alias_mod.Chain.initPresentation(&slot.alias_entries, &slot.alias_storage, q.name);
            slot.saveChain(chain_state);
            slot.qtype = q.qtype;
            slot.qclass = q.qclass;
            if (self.lookupCache(index, options.now)) |cached| return cached;
            try self.finishBegin(index, options);
            return self.transportAction(index, .initial);
        }

        pub fn beginWire(self: *Self, q: client.WireQuestionKey, options: BeginOptions) Error!Action {
            const index = try self.reserveSlot(options);
            var slot = &self.storage.slots[index];
            errdefer slot.active = false;

            const chain_state = try alias_mod.Chain.initWire(&slot.alias_entries, &slot.alias_storage, q.name);
            slot.saveChain(chain_state);
            slot.qtype = q.qtype;
            slot.qclass = q.qclass;
            if (self.lookupCache(index, options.now)) |cached| return cached;
            try self.finishBegin(index, options);
            return self.transportAction(index, .initial);
        }

        /// Build the current query into caller-owned packet/compression buffers.
        /// EDNS options are supplied per dispatch and are never retained.
        pub fn writeQuery(self: *Self, handle: Handle, out: []u8, compression: []builder.CompressionEntry, edns_options: []const u8) Error![]const u8 {
            var slot = try self.slotFor(handle);
            if (slot.phase != .awaiting_response) return error.UnexpectedState;
            var options = slot.query_options;
            if (!slot.edns_enabled) {
                options.udp_payload_size = null;
                options.dnssec_ok = false;
                options.compact_answers_ok = false;
            }
            return core.buildQueryWire(out, compression, slot.id, slot.currentQuestion(), options, edns_options);
        }

        pub fn currentQuestion(self: *Self, handle: Handle) Error!client.WireQuestionKey {
            const slot = try self.slotFor(handle);
            return slot.currentQuestion();
        }

        pub fn writeCurrentNamePresentation(self: *Self, handle: Handle, out: []u8) Error![]const u8 {
            var slot = try self.slotFor(handle);
            var chain_state = slot.chain();
            return chain_state.writeCurrentPresentation(out);
        }

        /// Match a response by DNS ID. This is useful for UDP and pipelined
        /// TCP where the transport does not already carry a query handle.
        pub fn matchResponse(self: *Self, bytes: []const u8) Error!Handle {
            const m = try message.Message.init(bytes);
            var needs_handle = false;
            for (&self.storage.slots, 0..) |*slot, index| {
                if (!slot.active or slot.phase != .awaiting_response) continue;
                if (usesExternalCorrelation(slot.transport)) {
                    if (slot.id == m.header.id) needs_handle = true;
                    continue;
                }
                if (slot.id != m.header.id) continue;
                return .{ .index = index, .generation = slot.generation };
            }
            if (needs_handle) return error.CorrelationHandleRequired;
            return error.UnknownTransaction;
        }

        pub fn onMatchedResponse(self: *Self, bytes: []const u8) Error!Action {
            return self.onResponse(try self.matchResponse(bytes), bytes);
        }

        /// Consume one response for a known query. Peer/wire failures are fed
        /// into retry policy rather than surfaced as generic parser failures.
        pub fn onResponse(self: *Self, handle: Handle, bytes: []const u8) Error!Action {
            const slot = try self.slotFor(handle);
            return self.onValidatedResponse(handle, bytes, slot.now, .indeterminate);
        }

        pub fn onResponseAt(self: *Self, handle: Handle, bytes: []const u8, now: u64) Error!Action {
            return self.onValidatedResponse(handle, bytes, now, .indeterminate);
        }

        /// Process a response after caller-owned DNSSEC validation. The status
        /// is composed across accepted alias/referral hops and propagated to
        /// terminal completion/cache hooks.
        pub fn onValidatedResponse(self: *Self, handle: Handle, bytes: []const u8, now: u64, security: SecurityStatus) Error!Action {
            var slot = try self.slotFor(handle);
            if (slot.phase != .awaiting_response) return error.UnexpectedState;
            slot.now = now;

            const parsed = client.validateResponseWire(slot.id, slot.currentQuestion(), bytes) catch {
                return self.applyRetry(handle, .malformed_response);
            };
            if (security == .bogus) return self.fail(handle, .dnssec_bogus);

            var followed_alias = false;
            while (true) {
                slot = try self.slotFor(handle);
                const inspected = retry_mod.inspectWire(parsed, slot.currentQuestion()) catch {
                    return self.applyRetry(handle, .malformed_response);
                };

                switch (inspected.outcome) {
                    .cname => |rr| {
                        if (try self.advanceAlias(handle, parsed, rr, false)) |terminal| return terminal;
                        slot = try self.slotFor(handle);
                        self.noteSecurity(slot, security);
                        followed_alias = true;
                    },
                    .dname => |rr| {
                        if (try self.advanceAlias(handle, parsed, rr, true)) |terminal| return terminal;
                        slot = try self.slotFor(handle);
                        self.noteSecurity(slot, security);
                        followed_alias = true;
                    },
                    .answer => {
                        self.noteSecurity(slot, security);
                        return self.completeNetwork(handle, .answer, parsed, now);
                    },
                    .nodata => {
                        // After following a CNAME/DNAME inside this packet, an
                        // empty Authority section means the recursive answer
                        // simply stopped at the alias. Query the target rather
                        // than inventing NODATA for a name that was not the
                        // packet's Question. An SOA is sufficient negative
                        // evidence to complete NODATA in the same response.
                        if (followed_alias and !try hasAuthoritySoa(parsed, slot.qclass)) {
                            return self.dispatchAlias(handle);
                        }
                        self.noteSecurity(slot, security);
                        return self.completeNetwork(handle, .nodata, parsed, now);
                    },
                    .nxdomain => {
                        self.noteSecurity(slot, security);
                        return self.completeNetwork(handle, .nxdomain, parsed, now);
                    },
                    .referral => {
                        self.noteSecurity(slot, security);
                        const referral = try referral_mod.Referral.initWire(parsed, slot.currentQuestion());
                        slot.phase = .referral_pending;
                        return .{ .referral = .{ .handle = handle, .view = referral, .server_index = slot.server_index } };
                    },
                    else => return self.applyDecision(handle, retry_mod.plan(self.attempt(slot), .{ .response = inspected })),
                }
            }
        }

        pub fn onTimeout(self: *Self, handle: Handle) Error!Action {
            const slot = try self.slotFor(handle);
            if (slot.phase != .awaiting_response) return error.UnexpectedState;
            return self.applyDecision(handle, retry_mod.plan(self.attempt(slot), .timeout));
        }

        pub fn onTransportFailure(self: *Self, handle: Handle) Error!Action {
            const slot = try self.slotFor(handle);
            if (slot.phase != .awaiting_response) return error.UnexpectedState;
            return self.applyDecision(handle, retry_mod.plan(self.attempt(slot), .transport_failure));
        }

        /// Continue the same logical QNAME through a caller-selected server
        /// set derived from a prior `.referral` action. Addresses, NS ordering,
        /// bailiwick policy, and connection ownership stay caller-side.
        pub fn followReferral(self: *Self, handle: Handle, server_count: usize, transport: Transport) Error!Action {
            var slot = try self.slotFor(handle);
            if (slot.phase != .referral_pending) return error.UnexpectedState;
            if (server_count == 0) return error.NoServers;
            slot.server_count = server_count;
            slot.server_index = 0;
            slot.preferred_transport = transport;
            slot.transport = transport;
            slot.queries_sent = 1;
            slot.edns_enabled = slot.query_options.udp_payload_size != null;
            slot.phase = .awaiting_response;
            try self.refreshId(slot);
            return self.transportAction(handle.index, .referral);
        }

        /// Treat a referral as the caller's terminal semantic result (useful
        /// for stub-style integrations that do not perform iterative descent).
        pub fn acceptReferral(self: *Self, handle: Handle) Error!Action {
            const slot = try self.slotFor(handle);
            if (slot.phase != .referral_pending) return error.UnexpectedState;
            return self.complete(handle, .referral);
        }

        /// Release or cancel active query state. Handles are generation-checked,
        /// so a stale handle cannot cancel a later query that reuses the same slot.
        pub fn release(self: *Self, handle: Handle) Error!void {
            var slot = try self.slotFor(handle);
            slot.active = false;
        }

        fn reserveSlot(self: *Self, options: BeginOptions) Error!usize {
            if (options.server_count == 0) return error.NoServers;
            const needs_edns = options.edns_required or options.query.dnssec_ok or options.query.compact_answers_ok;
            if (needs_edns and options.query.udp_payload_size == null) return error.EdnsFeatureWithoutOpt;

            for (&self.storage.slots, 0..) |*slot, index| {
                if (slot.active) continue;
                slot.* = .{};
                slot.active = true;
                slot.generation = self.takeGeneration();
                slot.query_options = options.query;
                slot.edns_required = needs_edns;
                slot.edns_enabled = options.query.udp_payload_size != null;
                slot.preferred_transport = options.transport;
                slot.transport = options.transport;
                slot.server_count = options.server_count;
                slot.server_index = 0;
                slot.queries_sent = 1;
                slot.now = options.now;
                slot.security = .indeterminate;
                slot.security_set = false;
                slot.phase = .awaiting_response;
                return index;
            }
            return error.Full;
        }

        fn lookupCache(self: *Self, index: usize, now: u64) ?Action {
            const hooks = self.cache_hooks orelse return null;
            var slot = &self.storage.slots[index];
            const hit = hooks.lookup(hooks.context, slot.currentQuestion(), now) orelse return null;
            if (hit.security == .bogus) {
                slot.phase = .failed;
                return .{ .fail = .{ .handle = self.handleFor(index), .reason = .dnssec_bogus } };
            }
            if (slot.security_set) {
                slot.security = combineSecurity(slot.security, hit.security);
            } else {
                slot.security = hit.security;
                slot.security_set = true;
            }
            slot.phase = .complete;
            return .{ .complete = .{
                .handle = self.handleFor(index),
                .kind = hit.kind,
                .server_index = slot.server_index,
                .source = .cache,
                .security = slot.security,
                .cache_token = hit.token,
            } };
        }

        fn noteSecurity(self: *Self, slot: *Slot, status: SecurityStatus) void {
            _ = self;
            if (!slot.security_set) {
                slot.security = status;
                slot.security_set = true;
                return;
            }
            slot.security = combineSecurity(slot.security, status);
        }

        fn finishBegin(self: *Self, index: usize, options: BeginOptions) Error!void {
            _ = options;
            try self.refreshId(&self.storage.slots[index]);
        }

        fn refreshId(self: *Self, slot: *Slot) Error!void {
            slot.id = if (usesExternalCorrelation(slot.transport)) 0 else try self.allocateId();
        }

        fn transportAction(self: *Self, index: usize, reason: DispatchReason) Action {
            const dispatch_value = self.dispatch(index, reason);
            return switch (dispatch_value.transport) {
                .udp => .{ .send = dispatch_value },
                .tcp => .{ .connect_tcp = dispatch_value },
                .dot => .{ .connect_dot = dispatch_value },
                .doq => .{ .open_doq_stream = dispatch_value },
                .doh => .{ .perform_doh = dispatch_value },
            };
        }

        fn takeGeneration(self: *Self) u32 {
            const result = self.next_generation;
            self.next_generation +%= 1;
            if (self.next_generation == 0) self.next_generation = 1;
            return result;
        }

        fn allocateId(self: *Self) Error!u16 {
            var attempts: usize = 0;
            while (attempts < 65535) : (attempts += 1) {
                const candidate = self.next_id;
                self.next_id +%= 1;
                if (self.next_id == 0) self.next_id = 1;
                if (candidate == 0) continue;

                var used = false;
                for (&self.storage.slots) |*slot| {
                    if (slot.active and slot.id == candidate) {
                        used = true;
                        break;
                    }
                }
                if (!used) return candidate;
            }
            return error.IdSpaceExhausted;
        }

        fn slotFor(self: *Self, handle: Handle) Error!*Slot {
            if (handle.index >= config.max_queries) return error.InvalidHandle;
            const slot = &self.storage.slots[handle.index];
            if (!slot.active or slot.generation != handle.generation) return error.InvalidHandle;
            return slot;
        }

        fn handleFor(self: *Self, index: usize) Handle {
            const slot = &self.storage.slots[index];
            return .{ .index = index, .generation = slot.generation };
        }

        fn dispatch(self: *Self, index: usize, reason: DispatchReason) Dispatch {
            const slot = &self.storage.slots[index];
            return .{
                .handle = self.handleFor(index),
                .id = slot.id,
                .server_index = slot.server_index,
                .transport = slot.transport,
                .edns_enabled = slot.edns_enabled,
                .reason = reason,
            };
        }

        fn attempt(self: *Self, slot: *Slot) retry_mod.Attempt {
            _ = self;
            return .{
                .transport = if (slot.transport == .udp) .udp else .tcp,
                .queries_sent = slot.queries_sent,
                .other_servers_available = slot.server_index + 1 < slot.server_count,
                .edns_used = slot.edns_enabled,
                .edns_required = slot.edns_required,
            };
        }

        fn applyRetry(self: *Self, handle: Handle, event: retry_mod.Event) Error!Action {
            const slot = try self.slotFor(handle);
            return self.applyDecision(handle, retry_mod.plan(self.attempt(slot), event));
        }

        fn applyDecision(self: *Self, handle: Handle, decision: retry_mod.Decision) Error!Action {
            var slot = try self.slotFor(handle);
            switch (decision.action) {
                .retry_udp => {
                    slot.queries_sent += 1;
                    return .{ .retry = self.dispatch(handle.index, .timeout) };
                },
                .fallback_tcp => {
                    slot.transport = .tcp;
                    slot.queries_sent = 1;
                    try self.refreshId(slot);
                    return .{ .connect_tcp = self.dispatch(handle.index, .truncated) };
                },
                .retry_other_server => return self.advanceServer(handle, decision.reason),
                .retry_without_edns => {
                    // An EDNS fallback is another transmission to the same
                    // server/transport and must respect the same RFC 9520 cap.
                    if (slot.queries_sent >= retry_mod.max_queries_per_server_transport) {
                        return self.advanceServer(handle, .retry_budget_exhausted);
                    }
                    slot.edns_enabled = false;
                    slot.queries_sent += 1;
                    try self.refreshId(slot);
                    return .{ .retry = self.dispatch(handle.index, .edns_fallback) };
                },
                .terminal => return self.fail(handle, failureReason(decision.reason)),
            }
        }

        fn advanceServer(self: *Self, handle: Handle, reason: retry_mod.Reason) Error!Action {
            var slot = try self.slotFor(handle);
            if (slot.server_index + 1 >= slot.server_count) return self.fail(handle, failureReason(reason));
            slot.server_index += 1;
            slot.transport = slot.preferred_transport;
            slot.queries_sent = 1;
            slot.edns_enabled = slot.query_options.udp_payload_size != null;
            try self.refreshId(slot);
            return self.transportAction(handle.index, .other_server);
        }

        fn advanceAlias(self: *Self, handle: Handle, parsed: message.Message, rr: message.Record, is_dname: bool) Error!?Action {
            var slot = try self.slotFor(handle);
            var chain_state = slot.chain();

            if (is_dname) {
                // A synthesized CNAME may be absent in DNSSEC-aware DNAME
                // responses. If present, verify it before advancing.
                var answers = try parsed.records(.answer);
                while (try answers.next()) |candidate| {
                    if (candidate.rr_type != .CNAME or candidate.class != slot.qclass) continue;
                    const current = chain_state.currentName();
                    const current_name = try name_mod.Name.init(current.bytes, 0);
                    if (!try candidate.name.eqlIgnoreCase(current_name)) continue;
                    alias_mod.validateSynthesizedCname(current, rr, candidate) catch {
                        return try self.applyRetry(handle, .malformed_response);
                    };
                    break;
                }
                chain_state.followDname(rr) catch |err| return try self.aliasError(handle, err);
            } else {
                chain_state.followCname(rr) catch |err| return try self.aliasError(handle, err);
            }

            slot.saveChain(chain_state);
            return null;
        }

        fn dispatchAlias(self: *Self, handle: Handle) Error!Action {
            var slot = try self.slotFor(handle);
            if (self.lookupCache(handle.index, slot.now)) |cached| return cached;
            slot = try self.slotFor(handle);
            slot.queries_sent = 1;
            try self.refreshId(slot);
            return self.transportAction(handle.index, .alias);
        }

        fn aliasError(self: *Self, handle: Handle, err: alias_mod.Error) Error!Action {
            return switch (err) {
                error.AliasLoop => self.fail(handle, .alias_loop),
                error.AliasLimit => self.fail(handle, .alias_limit),
                error.NoSpace => self.fail(handle, .alias_storage),
                else => self.applyRetry(handle, .malformed_response),
            };
        }

        fn completeNetwork(self: *Self, handle: Handle, kind: CompletionKind, parsed: message.Message, now: u64) Error!Action {
            var slot = try self.slotFor(handle);
            if (self.cache_hooks) |hooks| {
                if (hooks.store) |store| store(hooks.context, slot.currentQuestion(), kind, slot.security, parsed, now);
            }
            return self.complete(handle, kind);
        }

        fn complete(self: *Self, handle: Handle, kind: CompletionKind) Error!Action {
            var slot = try self.slotFor(handle);
            slot.phase = .complete;
            return .{ .complete = .{
                .handle = handle,
                .kind = kind,
                .server_index = slot.server_index,
                .source = .network,
                .security = if (slot.security_set) slot.security else .indeterminate,
            } };
        }

        fn fail(self: *Self, handle: Handle, reason: FailureReason) Error!Action {
            var slot = try self.slotFor(handle);
            slot.phase = .failed;
            return .{ .fail = .{ .handle = handle, .reason = reason } };
        }
    };
}

fn hasAuthoritySoa(parsed: message.Message, qclass: types.Class) message.ParseError!bool {
    var authority = try parsed.records(.authority);
    while (try authority.next()) |rr| {
        if (rr.class == qclass and rr.rr_type == .SOA) return true;
    }
    return false;
}

fn combineSecurity(a: SecurityStatus, b: SecurityStatus) SecurityStatus {
    if (a == .bogus or b == .bogus) return .bogus;
    if (a == .indeterminate or b == .indeterminate) return .indeterminate;
    if (a == .insecure or b == .insecure) return .insecure;
    return .secure;
}

fn usesExternalCorrelation(transport: Transport) bool {
    return transport == .doq or transport == .doh;
}

fn failureReason(reason: retry_mod.Reason) FailureReason {
    return switch (reason) {
        .transport_failure => .transport_failure,
        .malformed_response => .malformed_response,
        .server_failure => .server_failure,
        .retry_budget_exhausted, .timeout => .retry_budget_exhausted,
        .protocol_failure, .truncated, .edns_unsupported, .accepted => .protocol_failure,
    };
}
