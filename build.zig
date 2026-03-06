const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // Library module
    const mod = b.addModule("httpz", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
    });

    // Executable
    const exe = b.addExecutable(.{
        .name = "httpz",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "httpz", .module = mod },
            },
        }),
    });

    b.installArtifact(exe);

    // Run step
    const run_step = b.step("run", "Run the HTTP server");
    const run_cmd = b.addRunArtifact(exe);
    run_step.dependOn(&run_cmd.step);
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    // Module tests
    const mod_tests = b.addTest(.{
        .root_module = mod,
    });

    const run_mod_tests = b.addRunArtifact(mod_tests);

    // Exe tests
    const exe_tests = b.addTest(.{
        .root_module = exe.root_module,
    });

    const run_exe_tests = b.addRunArtifact(exe_tests);

    // Test step
    const test_step = b.step("test", "Run all tests");
    test_step.dependOn(&run_mod_tests.step);
    test_step.dependOn(&run_exe_tests.step);

    // Coverage step using kcov
    const coverage_step = b.step("coverage", "Run tests with kcov code coverage");

    // Module tests cover everything via refAllDecls in root.zig
    const cov_mod_test = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/root.zig"),
            .target = target,
        }),
    });

    const kcov_mod = b.addSystemCommand(&.{"kcov"});
    kcov_mod.addPrefixedDirectoryArg("--include-path=", b.path("src"));
    kcov_mod.addArg("kcov-output");
    kcov_mod.addArtifactArg(cov_mod_test);
    coverage_step.dependOn(&kcov_mod.step);

    // Exe tests for main.zig handler coverage
    const cov_exe_test = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .imports = &.{
                .{ .name = "httpz", .module = mod },
            },
        }),
    });

    const kcov_exe = b.addSystemCommand(&.{"kcov"});
    kcov_exe.addPrefixedDirectoryArg("--include-path=", b.path("src"));
    kcov_exe.addArg("kcov-output");
    kcov_exe.addArtifactArg(cov_exe_test);
    coverage_step.dependOn(&kcov_exe.step);
}
