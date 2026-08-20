const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const mod = b.addModule("dns", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });

    const tests = b.addTest(.{ .root_module = mod });
    const run_tests = b.addRunArtifact(tests);
    const test_step = b.step("test", "Run DNS tests");
    test_step.dependOn(&run_tests.step);

    const check = b.step("check", "Compile tests, docs, and examples");
    check.dependOn(&tests.step);

    const docs = b.addObject(.{ .name = "dns-docs", .root_module = mod });
    _ = docs.getEmittedDocs();
    check.dependOn(&docs.step);

    const inspect_mod = b.createModule(.{
        .root_source_file = b.path("examples/inspect.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{.{ .name = "dns", .module = mod }},
    });
    const inspect = b.addExecutable(.{ .name = "dns-inspect-example", .root_module = inspect_mod });
    check.dependOn(&inspect.step);

    const example_step = b.step("example-inspect", "Run the DNS inspection example");
    const run_inspect = b.addRunArtifact(inspect);
    example_step.dependOn(&run_inspect.step);
    const resolver_mod = b.createModule(.{
        .root_source_file = b.path("examples/resolver.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{.{ .name = "dns", .module = mod }},
    });
    const resolver_example = b.addExecutable(.{ .name = "dns-resolver-example", .root_module = resolver_mod });
    check.dependOn(&resolver_example.step);

    const resolver_step = b.step("example-resolver", "Run the resolver composition example");
    const run_resolver = b.addRunArtifact(resolver_example);
    resolver_step.dependOn(&run_resolver.step);

    const dnssec_mod = b.createModule(.{
        .root_source_file = b.path("examples/dnssec.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{.{ .name = "dns", .module = mod }},
    });
    const dnssec_example = b.addExecutable(.{ .name = "dns-dnssec-example", .root_module = dnssec_mod });
    check.dependOn(&dnssec_example.step);

    const dnssec_step = b.step("example-dnssec", "Run the DNSSEC composition example");
    const run_dnssec = b.addRunArtifact(dnssec_example);
    dnssec_step.dependOn(&run_dnssec.step);

    const core_bench_mod = b.createModule(.{
        .root_source_file = b.path("bench/core.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{.{ .name = "dns", .module = mod }},
    });
    const core_bench = b.addExecutable(.{ .name = "dns-core-bench", .root_module = core_bench_mod });
    check.dependOn(&core_bench.step);
    const core_bench_step = b.step("bench-core", "Benchmark core DNS hot paths");
    core_bench_step.dependOn(&b.addRunArtifact(core_bench).step);

    const dnssec_bench_mod = b.createModule(.{
        .root_source_file = b.path("bench/dnssec.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{.{ .name = "dns", .module = mod }},
    });
    const dnssec_bench = b.addExecutable(.{ .name = "dns-dnssec-bench", .root_module = dnssec_bench_mod });
    check.dependOn(&dnssec_bench.step);
    const dnssec_bench_step = b.step("bench-dnssec", "Benchmark DNSSEC hot paths");
    dnssec_bench_step.dependOn(&b.addRunArtifact(dnssec_bench).step);

    const transfer_bench_mod = b.createModule(.{
        .root_source_file = b.path("bench/transfer.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{.{ .name = "dns", .module = mod }},
    });
    const transfer_bench = b.addExecutable(.{ .name = "dns-transfer-bench", .root_module = transfer_bench_mod });
    check.dependOn(&transfer_bench.step);
    const transfer_bench_step = b.step("bench-transfer", "Benchmark AXFR and IXFR state machines");
    transfer_bench_step.dependOn(&b.addRunArtifact(transfer_bench).step);

    const interop_dnssec = b.step("interop-dnssec", "Validate DNSSEC RFC vectors with dnspython");
    const run_dnssec_interop = b.addSystemCommand(&.{ "python3", b.pathFromRoot("interop/dnssec_vectors.py") });
    interop_dnssec.dependOn(&run_dnssec_interop.step);

    const update_example_mod = b.createModule(.{
        .root_source_file = b.path("examples/update.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{.{ .name = "dns", .module = mod }},
    });
    const update_example = b.addExecutable(.{ .name = "dns-update-example", .root_module = update_example_mod });
    check.dependOn(&update_example.step);
    const update_example_step = b.step("example-update", "Run the signed DNS UPDATE example");
    update_example_step.dependOn(&b.addRunArtifact(update_example).step);

    const transfer_example_mod = b.createModule(.{
        .root_source_file = b.path("examples/transfer.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{.{ .name = "dns", .module = mod }},
    });
    const transfer_example = b.addExecutable(.{ .name = "dns-transfer-example", .root_module = transfer_example_mod });
    check.dependOn(&transfer_example.step);
    const transfer_example_step = b.step("example-transfer", "Run the streaming AXFR example");
    transfer_example_step.dependOn(&b.addRunArtifact(transfer_example).step);

    const tsig_fixture_mod = b.createModule(.{
        .root_source_file = b.path("interop/tsig_fixture.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{.{ .name = "dns", .module = mod }},
    });
    const tsig_fixture = b.addExecutable(.{ .name = "dns-tsig-interop-fixture", .root_module = tsig_fixture_mod });
    check.dependOn(&tsig_fixture.step);

    const interop_tsig = b.step("interop-tsig", "Validate TSIG messages with dnspython");
    const run_tsig_interop = b.addSystemCommand(&.{ "python3", b.pathFromRoot("interop/tsig_vectors.py") });
    run_tsig_interop.addArtifactArg(tsig_fixture);
    interop_tsig.dependOn(&run_tsig_interop.step);
    const update_fixture_mod = b.createModule(.{
        .root_source_file = b.path("interop/update_fixture.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{.{ .name = "dns", .module = mod }},
    });
    const update_fixture = b.addExecutable(.{ .name = "dns-update-interop-fixture", .root_module = update_fixture_mod });
    check.dependOn(&update_fixture.step);

    const interop_update = b.step("interop-update", "Validate signed UPDATE with dnspython");
    const run_update_interop = b.addSystemCommand(&.{ "python3", b.pathFromRoot("interop/update_vectors.py") });
    run_update_interop.addArtifactArg(update_fixture);
    interop_update.dependOn(&run_update_interop.step);
}
