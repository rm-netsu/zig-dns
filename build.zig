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
}
