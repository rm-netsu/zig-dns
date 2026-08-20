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

pub const BeginOptions = struct {
    query: core.QueryOptions = .{ .udp_payload_size = 1232 },
    /// Set when an application-specific EDNS option is mandatory even if DO
    /// and Compact Answers are both disabled.
    edns_required: bool = false,
    /// Number of caller-owned upstream server choices available to this query.
    server_count: usize = 1,
    transport: retry_mod.Transport = .udp,
};

pub const DispatchReason = enum {
    initial,
    timeout,
    other_server,
    truncated,
    edns_fallback,
    alias,
};

pub const Dispatch = struct {
    handle: Handle,
    id: u16,
    server_index: usize,
    transport: retry_mod.Transport,
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

pub const Completion = struct {
    handle: Handle,
    kind: CompletionKind,
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
    /// UDP truncation requires a TCP-capable path for the same logical query.
    connect_tcp: Dispatch,
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
    UnexpectedState,
};

pub fn Resolver(comptime config: Config) type {
    if (config.max_queries == 0) @compileError("Resolver.max_queries must be greater than zero");
    if (config.max_queries > 65535) @compileError("Resolver.max_queries cannot exceed the non-zero DNS ID space");
    if (config.max_alias_depth == std.math.maxInt(usize)) @compileError("Resolver.max_alias_depth is too large");

    return struct {
        const Self = @This();
        const Phase = enum { awaiting_response, complete, failed };

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
            preferred_transport: retry_mod.Transport = .udp,
            transport: retry_mod.Transport = .udp,
            server_count: usize = 0,
            server_index: usize = 0,
            queries_sent: u8 = 0,
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
        next_id: u16 = 1,
        next_generation: u32 = 1,

        pub fn initInPlace(storage: *Storage) Self {
            for (&storage.slots) |*slot| {
                slot.active = false;
                slot.generation = 0;
            }
            return .{ .storage = storage };
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
            try self.finishBegin(index, options);
            return .{ .send = self.dispatch(index, .initial) };
        }

        pub fn beginWire(self: *Self, q: client.WireQuestionKey, options: BeginOptions) Error!Action {
            const index = try self.reserveSlot(options);
            var slot = &self.storage.slots[index];
            errdefer slot.active = false;

            const chain_state = try alias_mod.Chain.initWire(&slot.alias_entries, &slot.alias_storage, q.name);
            slot.saveChain(chain_state);
            slot.qtype = q.qtype;
            slot.qclass = q.qclass;
            try self.finishBegin(index, options);
            return .{ .send = self.dispatch(index, .initial) };
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
            for (&self.storage.slots, 0..) |*slot, index| {
                if (!slot.active or slot.phase != .awaiting_response) continue;
                if (slot.id != m.header.id) continue;
                return .{ .index = index, .generation = slot.generation };
            }
            return error.UnknownTransaction;
        }

        pub fn onMatchedResponse(self: *Self, bytes: []const u8) Error!Action {
            return self.onResponse(try self.matchResponse(bytes), bytes);
        }

        /// Consume one response for a known query. Peer/wire failures are fed
        /// into retry policy rather than surfaced as generic parser failures.
        pub fn onResponse(self: *Self, handle: Handle, bytes: []const u8) Error!Action {
            var slot = try self.slotFor(handle);
            if (slot.phase != .awaiting_response) return error.UnexpectedState;

            const parsed = client.validateResponseWire(slot.id, slot.currentQuestion(), bytes) catch {
                return self.applyRetry(handle, .malformed_response);
            };
            const inspected = retry_mod.inspectWire(parsed, slot.currentQuestion()) catch {
                return self.applyRetry(handle, .malformed_response);
            };

            switch (inspected.outcome) {
                .cname => |rr| return self.followAlias(handle, parsed, rr, false),
                .dname => |rr| return self.followAlias(handle, parsed, rr, true),
                .answer => return self.complete(handle, .answer),
                .nodata => return self.complete(handle, .nodata),
                .nxdomain => return self.complete(handle, .nxdomain),
                .referral => return self.complete(handle, .referral),
                else => return self.applyDecision(handle, retry_mod.plan(self.attempt(slot), .{ .response = inspected })),
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

        /// Release terminal query state. Handles are generation-checked, so a
        /// stale handle cannot cancel a later query that reuses the same slot.
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
                slot.phase = .awaiting_response;
                return index;
            }
            return error.Full;
        }

        fn finishBegin(self: *Self, index: usize, options: BeginOptions) Error!void {
            _ = options;
            self.storage.slots[index].id = try self.allocateId();
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
                .transport = slot.transport,
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
                    slot.id = try self.allocateId();
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
                    slot.id = try self.allocateId();
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
            slot.id = try self.allocateId();
            return .{ .send = self.dispatch(handle.index, .other_server) };
        }

        fn followAlias(self: *Self, handle: Handle, parsed: message.Message, rr: message.Record, is_dname: bool) Error!Action {
            var slot = try self.slotFor(handle);
            var chain_state = slot.chain();

            if (is_dname) {
                // If the response carries the synthesized CNAME required by a
                // recursive DNAME response, verify it before advancing.
                var answers = try parsed.records(.answer);
                while (try answers.next()) |candidate| {
                    if (candidate.rr_type != .CNAME or candidate.class != slot.qclass) continue;
                    const current = chain_state.currentName();
                    const current_name = try name_mod.Name.init(current.bytes, 0);
                    if (!try candidate.name.eqlIgnoreCase(current_name)) continue;
                    alias_mod.validateSynthesizedCname(current, rr, candidate) catch {
                        return self.applyRetry(handle, .malformed_response);
                    };
                    break;
                }
                chain_state.followDname(rr) catch |err| return self.aliasError(handle, err);
            } else {
                chain_state.followCname(rr) catch |err| return self.aliasError(handle, err);
            }

            slot.saveChain(chain_state);
            slot.queries_sent = 1;
            slot.id = try self.allocateId();
            return .{ .send = self.dispatch(handle.index, .alias) };
        }

        fn aliasError(self: *Self, handle: Handle, err: alias_mod.Error) Error!Action {
            return switch (err) {
                error.AliasLoop => self.fail(handle, .alias_loop),
                error.AliasLimit => self.fail(handle, .alias_limit),
                error.NoSpace => self.fail(handle, .alias_storage),
                else => self.applyRetry(handle, .malformed_response),
            };
        }

        fn complete(self: *Self, handle: Handle, kind: CompletionKind) Error!Action {
            var slot = try self.slotFor(handle);
            slot.phase = .complete;
            return .{ .complete = .{ .handle = handle, .kind = kind, .server_index = slot.server_index } };
        }

        fn fail(self: *Self, handle: Handle, reason: FailureReason) Error!Action {
            var slot = try self.slotFor(handle);
            slot.phase = .failed;
            return .{ .fail = .{ .handle = handle, .reason = reason } };
        }
    };
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
