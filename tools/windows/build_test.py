#!/usr/bin/env python3
# Copyright 2017 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Builds crosvm in debug/release mode on all supported target architectures.

A sysroot for each target architectures is required. The defaults are all generic boards' sysroots,
but they can be changed with the command line arguments.

To test changes more quickly, set the --noclean option. This prevents the target directories from
being removed before building and testing.

For easy binary size comparison, use the --size-only option to only do builds that will result in a
binary size output, which are non-test release builds.

This script automatically determines which packages will need to be tested based on the directory
structure with Cargo.toml files. Only top-level crates are tested directly. To skip a top-level
package, add an empty .build_test_skip file to the directory. Rarely, if a package needs to have its
tests run single-threaded, add an empty .build_test_serial file to the directory.
"""

from __future__ import print_function
import argparse
import functools
import multiprocessing.pool
import os
import shutil
import subprocess
import sys

sys.path.append(os.path.dirname(sys.path[0]))

from enabled_features import ENABLED_FEATURES, BUILD_FEATURES
from files_to_include import DLLS, BINARIES
from prepare_dlls import build_dlls, copy_dlls

# Is Windows
IS_WINDOWS = os.name == "nt"

ARM_TRIPLE = os.getenv("ARM_TRIPLE", "armv7a-cros-linux-gnueabihf")
AARCH64_TRIPLE = os.getenv("AARCH64_TRIPLE", "aarch64-cros-linux-gnu")
X86_64_TRIPLE = os.getenv("X86_64_TRIPLE", "x86_64-unknown-linux-gnu")
X86_64_WIN_MSVC_TRIPLE = os.getenv("X86_64_WIN_MSVC_TRIPLE", "x86_64-pc-windows-msvc")
SYMBOL_EXPORTS = ["NvOptimusEnablement", "AmdPowerXpressRequestHighPerformance"]

LINUX_BUILD_ONLY_MODULES = [
    "io_jail",
    "poll_token_derive",
    "wire_format_derive",
    "bit_field_derive",
    "linux_input_sys",
    "vfio_sys",
]

# Bright green.
PASS_COLOR = "\033[1;32m"
# Bright red.
FAIL_COLOR = "\033[1;31m"
# Default color.
END_COLOR = "\033[0m"


def crosvm_binary_name():
    return "crosvm.exe" if IS_WINDOWS else "crosvm"


def get_target_path(triple, kind, test_it):
    """Constructs a target path based on the configuration parameters.

    Args:
      triple: Target triple. Example: 'x86_64-unknown-linux-gnu'.
      kind: 'debug' or 'release'.
      test_it: If this target is tested.
    """
    target_path = os.path.abspath(os.path.join(os.sep, "tmp", "{}_{}".format(triple, kind)))
    if test_it:
        target_path += "_test"
    return target_path


def validate_symbols(triple, is_release):
    kind = "release" if is_release else "debug"
    target_path = get_target_path(triple, kind, False)
    binary_path = os.path.join(target_path, triple, kind, crosvm_binary_name())
    with open(binary_path, mode="rb") as f:
        contents = f.read().decode("ascii", errors="ignore")
        return all(symbol in contents for symbol in SYMBOL_EXPORTS)


def build_target(
    triple,
    is_release,
    env,
    only_build_targets,
    test_module_parallel,
    test_module_serial,
):
    """Does a cargo build for the triple in release or debug mode.

    Args:
      triple: Target triple. Example: 'x86_64-unknown-linux-gnu'.
      is_release: True to build a release version.
      env: Enviroment variables to run cargo with.
      only_build_targets: Only build packages that will be tested.
    """
    args = ["cargo", "build", "--target=%s" % triple]

    if is_release:
        args.append("--release")

    if only_build_targets:
        test_modules = test_module_parallel + test_module_serial
        if not IS_WINDOWS:
            test_modules += LINUX_BUILD_ONLY_MODULES
        for mod in test_modules:
            args.append("-p")
            args.append(mod)

    args.append("--features")
    args.append(",".join(BUILD_FEATURES))

    if subprocess.Popen(args, env=env).wait() != 0:
        return False, "build error"
    if IS_WINDOWS and not validate_symbols(triple, is_release):
        return False, "error validating discrete gpu symbols"

    return True, "pass"


def test_target_modules(triple, is_release, env, no_run, modules, parallel):
    """Does a cargo test on given modules for the triple and configuration.

    Args:
      triple: Target triple. Example: 'x86_64-unknown-linux-gnu'.
      is_release: True to build a release version.
      env: Enviroment variables to run cargo with.
      no_run: True to pass --no-run flag to cargo test.
      modules: List of module strings to test.
      parallel: True to run the tests in parallel threads.
    """
    args = ["cargo", "test", "--target=%s" % triple]

    if is_release:
        args.append("--release")

    if no_run:
        args.append("--no-run")

    for mod in modules:
        args.append("-p")
        args.append(mod)

    args.append("--features")
    args.append(",".join(ENABLED_FEATURES))

    if not parallel:
        args.append("--")
        args.append("--test-threads=1")
    return subprocess.Popen(args, env=env).wait() == 0


def test_target(triple, is_release, env, no_run, test_modules_parallel, test_modules_serial):
    """Does a cargo test for the given triple and configuration.

    Args:
      triple: Target triple. Example: 'x86_64-unknown-linux-gnu'.
      is_release: True to build a release version.
      env: Enviroment variables to run cargo with.
      no_run: True to pass --no-run flag to cargo test.
    """

    parallel_result = test_target_modules(
        triple, is_release, env, no_run, test_modules_parallel, True
    )

    serial_result = test_target_modules(triple, is_release, env, no_run, test_modules_serial, False)

    return parallel_result and serial_result


def build_or_test(
    sysroot,
    triple,
    kind,
    skip_file_name,
    test_it=False,
    no_run=False,
    clean=False,
    copy_output=False,
    copy_directory=None,
    only_build_targets=False,
):
    """Runs relevant builds/tests for the given triple and configuration

    Args:
      sysroot: path to the target's sysroot directory.
      triple: Target triple. Example: 'x86_64-unknown-linux-gnu'.
      kind: 'debug' or 'release'.
      skip_file_name: Skips building and testing a crate if this file is found in
                      crate's root directory.
      test_it: True to test this triple and kind.
      no_run: True to just compile and not run tests (only if test_it=True)
      clean: True to skip cleaning the target path.
      copy_output: True to copy build artifacts to external directory.
      output_directory: Destination of copy of build artifacts.
      only_build_targets: Only build packages that will be tested.
    """
    if not os.path.isdir(sysroot) and not IS_WINDOWS:
        return False, "sysroot missing"

    target_path = get_target_path(triple, kind, test_it)

    if clean:
        shutil.rmtree(target_path, True)

    is_release = kind == "release"

    env = os.environ.copy()
    env["TARGET_CC"] = "%s-clang" % triple
    env["SYSROOT"] = sysroot
    env["CARGO_TARGET_DIR"] = target_path

    if not IS_WINDOWS:
        # The lib dir could be in either lib or lib64 depending on the target. Rather than checking to see
        # which one is valid, just add both and let the dynamic linker and pkg-config search.
        libdir = os.path.join(sysroot, "usr", "lib")
        lib64dir = os.path.join(sysroot, "usr", "lib64")
        libdir_pc = os.path.join(libdir, "pkgconfig")
        lib64dir_pc = os.path.join(lib64dir, "pkgconfig")

        # This line that changes the dynamic library path is needed for upstream, but breaks
        # downstream's crosvm linux kokoro presubmits.
        # env['LD_LIBRARY_PATH'] = libdir + ':' + lib64dir
        env["PKG_CONFIG_ALLOW_CROSS"] = "1"
        env["PKG_CONFIG_LIBDIR"] = libdir_pc + ":" + lib64dir_pc
        env["PKG_CONFIG_SYSROOT_DIR"] = sysroot
        if "KOKORO_JOB_NAME" not in os.environ:
            env["RUSTFLAGS"] = "-C linker=" + env["TARGET_CC"]
            if is_release:
                env["RUSTFLAGS"] += " -Cembed-bitcode=yes -Clto"

    if IS_WINDOWS and not test_it:
        for symbol in SYMBOL_EXPORTS:
            env["RUSTFLAGS"] = env.get("RUSTFLAGS", "") + " -C link-args=/EXPORT:{}".format(symbol)

    deps_dir = os.path.join(target_path, triple, kind, "deps")
    if not os.path.exists(deps_dir):
        os.makedirs(deps_dir)

    target_dirs = [deps_dir]
    if copy_output:
        os.makedirs(os.path.join(copy_directory, kind), exist_ok=True)
        if not test_it:
            target_dirs.append(os.path.join(copy_directory, kind))

    copy_dlls(os.getcwd(), target_dirs, kind)

    (test_modules_parallel, test_modules_serial) = get_test_modules(skip_file_name)
    print("modules to test in parallel:\n", test_modules_parallel)
    print("modules to test serially:\n", test_modules_serial)

    if not test_modules_parallel and not test_modules_serial:
        print("All build and tests skipped.")
        return True, "pass"

    if test_it:
        if not test_target(
            triple, is_release, env, no_run, test_modules_parallel, test_modules_serial
        ):
            return False, "test error"
    else:
        res, err = build_target(
            triple,
            is_release,
            env,
            only_build_targets,
            test_modules_parallel,
            test_modules_serial,
        )
        if not res:
            return res, err

    # We only care about the non-test binaries, so only copy the output from cargo build.
    if copy_output and not test_it:
        binary_src = os.path.join(target_path, triple, kind, crosvm_binary_name())
        pdb_src = binary_src.replace(".exe", "") + ".pdb"
        binary_dst = os.path.join(copy_directory, kind)
        shutil.copy(binary_src, binary_dst)
        shutil.copy(pdb_src, binary_dst)

    return True, "pass"


def get_test_modules(skip_file_name):
    """Returns a list of modules to test.
    Args:
      skip_file_name: Skips building and testing a crate if this file is found in
                      crate's root directory.
    """
    if IS_WINDOWS and not os.path.isfile(skip_file_name):
        test_modules_parallel = ["crosvm"]
    else:
        test_modules_parallel = []
    test_modules_serial = []

    file_in_crate = lambda file_name: os.path.isfile(os.path.join(crate.path, file_name))
    serial_file_name = "{}build_test_serial".format(".win_" if IS_WINDOWS else ".")
    with os.scandir() as it:
        for crate in it:
            if file_in_crate("Cargo.toml"):
                if file_in_crate(skip_file_name):
                    continue
                if file_in_crate(serial_file_name):
                    test_modules_serial.append(crate.name)
                else:
                    test_modules_parallel.append(crate.name)

    test_modules_parallel.sort()
    test_modules_serial.sort()

    return (test_modules_parallel, test_modules_serial)


def get_stripped_size(triple):
    """Returns the formatted size of the given triple's release binary.

    Args:
      triple: Target triple. Example: 'x86_64-unknown-linux-gnu'.
    """
    target_path = get_target_path(triple, "release", False)
    bin_path = os.path.join(target_path, triple, "release", crosvm_binary_name())
    proc = subprocess.Popen(["%s-strip" % triple, bin_path])

    if proc.wait() != 0:
        return "failed"

    return "%dKiB" % (os.path.getsize(bin_path) / 1024)


def get_parser():
    """Gets the argument parser"""
    parser = argparse.ArgumentParser(description=__doc__)
    if IS_WINDOWS:
        parser.add_argument(
            "--x86_64-msvc-sysroot",
            default="build/amd64-msvc",
            help="x86_64 sysroot directory (default=%(default)s)",
        )
    else:
        parser.add_argument(
            "--arm-sysroot",
            default="/build/arm-generic",
            help="ARM sysroot directory (default=%(default)s)",
        )
        parser.add_argument(
            "--aarch64-sysroot",
            default="/build/arm64-generic",
            help="AARCH64 sysroot directory (default=%(default)s)",
        )
        parser.add_argument(
            "--x86_64-sysroot",
            default="/build/amd64-generic",
            help="x86_64 sysroot directory (default=%(default)s)",
        )

    parser.add_argument(
        "--noclean",
        dest="clean",
        default=True,
        action="store_false",
        help="Keep the tempororary build directories.",
    )
    parser.add_argument(
        "--copy",
        default=False,
        help="Copies .exe files to an output directory for later use",
    )
    parser.add_argument(
        "--copy-directory",
        default="/output",
        help="Destination of .exe files when using --copy",
    )
    parser.add_argument(
        "--serial",
        default=True,
        action="store_false",
        dest="parallel",
        help="Run cargo build serially rather than in parallel",
    )
    # TODO(b/154029826): Remove this option once all sysroots are available.
    parser.add_argument(
        "--x86_64-only",
        default=False,
        action="store_true",
        help="Only runs tests on x86_64 sysroots",
    )
    parser.add_argument(
        "--only-build-targets",
        default=False,
        action="store_true",
        help="Builds only the tested modules. If false, builds the entire crate",
    )
    parser.add_argument(
        "--size-only",
        dest="size_only",
        default=False,
        action="store_true",
        help="Only perform builds that output their binary size (i.e. release non-test).",
    )
    parser.add_argument(
        "--job_type",
        default="local",
        choices=["kokoro", "local"],
        help="Set to kokoro if this script is executed by a kokoro job, otherwise local",
    )
    parser.add_argument(
        "--skip_file_name",
        default=".win_build_test_skip" if IS_WINDOWS else ".build_test_skip",
        choices=[
            ".build_test_skip",
            ".win_build_test_skip",
            ".windows_build_test_skip",
        ],
        help="Skips building and testing a crate if the crate contains specified file in its root directory.",
    )
    parser.add_argument(
        "--build_mode",
        default="release",
        choices=["release", "debug"],
        help="Build mode of the binaries.",
    )

    return parser


def main(argv):
    opts = get_parser().parse_args(argv)
    os.environ["RUST_BACKTRACE"] = "1"
    if IS_WINDOWS:
        if opts.build_mode == "release":
            build_test_cases = [
                # (sysroot path, target triple, debug/release, skip_file_name, should test?)
                (
                    opts.x86_64_msvc_sysroot,
                    X86_64_WIN_MSVC_TRIPLE,
                    "release",
                    opts.skip_file_name,
                    True,
                ),
                (
                    opts.x86_64_msvc_sysroot,
                    X86_64_WIN_MSVC_TRIPLE,
                    "release",
                    opts.skip_file_name,
                    False,
                ),
            ]
        elif opts.build_mode == "debug":
            build_test_cases = [
                (
                    opts.x86_64_msvc_sysroot,
                    X86_64_WIN_MSVC_TRIPLE,
                    "debug",
                    opts.skip_file_name,
                    True,
                ),
            ]
    else:
        build_test_cases = [
            # (sysroot path, target triple, debug/release, skip_file_name, should test?)
            (opts.x86_64_sysroot, X86_64_TRIPLE, "debug", opts.skip_file_name, False),
            (opts.x86_64_sysroot, X86_64_TRIPLE, "release", opts.skip_file_name, False),
            (opts.x86_64_sysroot, X86_64_TRIPLE, "debug", opts.skip_file_name, True),
            (opts.x86_64_sysroot, X86_64_TRIPLE, "release", opts.skip_file_name, True),
        ]
        if not opts.x86_64_only:
            build_test_cases = [
                # (sysroot path, target triple, debug/release, skip_file_name, should test?)
                (opts.arm_sysroot, ARM_TRIPLE, "debug", opts.skip_file_name, False),
                (opts.arm_sysroot, ARM_TRIPLE, "release", opts.skip_file_name, False),
                (
                    opts.aarch64_sysroot,
                    AARCH64_TRIPLE,
                    "debug",
                    opts.skip_file_name,
                    False,
                ),
                (
                    opts.aarch64_sysroot,
                    AARCH64_TRIPLE,
                    "release",
                    opts.skip_file_name,
                    False,
                ),
            ] + build_test_cases
        os.chdir(os.path.dirname(sys.argv[0]))

    if opts.size_only:
        # Only include non-test release builds
        build_test_cases = [
            case for case in build_test_cases if case[2] == "release" and not case[4]
        ]

    # First we need to build necessary DLLs.
    # Because build_or_test may be called by multithreads in parallel,
    # we want to build the DLLs only once up front.
    modes = set()
    for case in build_test_cases:
        modes.add(case[2])
    for mode in modes:
        build_dlls(os.getcwd(), mode, opts.job_type, BUILD_FEATURES)

    # set keyword args to build_or_test based on opts
    build_partial = functools.partial(
        build_or_test,
        no_run=True,
        clean=opts.clean,
        copy_output=opts.copy,
        copy_directory=opts.copy_directory,
        only_build_targets=opts.only_build_targets,
    )

    if opts.parallel:
        pool = multiprocessing.pool.Pool(len(build_test_cases))
        results = pool.starmap(build_partial, build_test_cases, 1)
    else:
        results = [build_partial(*case) for case in build_test_cases]

    print_summary("build", build_test_cases, results, opts)

    # exit early if any builds failed
    if not all([r[0] for r in results]):
        return 1

    # run tests for cases where should_test is True
    test_cases = [case for case in build_test_cases if case[4]]

    # Run tests serially. We set clean=False so it re-uses the results of the build phase.
    results = [
        build_or_test(
            *case,
            no_run=False,
            clean=False,
            copy_output=opts.copy,
            copy_directory=opts.copy_directory,
            only_build_targets=opts.only_build_targets,
        )
        for case in test_cases
    ]

    print_summary("test", test_cases, results, opts)

    if not all([r[0] for r in results]):
        return 1

    return 0


def print_summary(title, cases, results, opts):
    print("---")
    print(f"{title} summary:")
    for test_case, result in zip(cases, results):
        _, triple, kind, _, test_it = test_case
        title = "%s_%s" % (triple.split("-")[0], kind)
        if test_it:
            title += "_test"

        success, result_msg = result

        result_color = FAIL_COLOR
        if success:
            result_color = PASS_COLOR

        display_size = ""
        # Stripped binary isn't available when only certain packages are built, the tool is not available
        # on Windows.
        if (
            success
            and kind == "release"
            and not test_it
            and not opts.only_build_targets
            and not IS_WINDOWS
        ):
            display_size = get_stripped_size(triple) + " stripped binary"

        print("%20s: %s%15s%s %s" % (title, result_color, result_msg, END_COLOR, display_size))


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
