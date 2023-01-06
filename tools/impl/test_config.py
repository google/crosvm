# Copyright 2021 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import enum
from typing import List, Dict

BUILD_FEATURES: Dict[str, str] = {
    "x86_64-unknown-linux-gnu": "linux-x86_64",
    "aarch64-unknown-linux-gnu": "linux-aarch64",
    "armv7-unknown-linux-gnueabihf": "linux-armhf",
    "x86_64-pc-windows-gnu": "win64",
    "x86_64-pc-windows-msvc": "win64",
}

# Configuration of integration tests
#
# The configuration below only applies to integration tests to fine tune which tests can be run
# on which platform (e.g. aarch64 emulation does not pass kvm tests).
#
# This configuration does NOT apply to unit tests.

# List of integration tests that will ask for root privileges.
ROOT_TESTS = [
    "package(net_util) & binary(unix_tap)",
]

# Do not run these tests on any platform.
DO_NOT_RUN = [
    "package(io_uring)",
]

# Do not run these tests for aarch64 builds
DO_NOT_RUN_AARCH64 = [
    "package(hypervisor)",
    "package(e2e_tests)",
    "package(kvm)",
]

# Do not run these tests for win64 builds
DO_NOT_RUN_WIN64 = [
    "package(e2e_tests)",
]

# Deprecated test configuration for tools/run_tests
#
# This will eventually be fully replaced the above configuration


class TestOption(enum.Enum):
    # Do not build tests for all, or just some platforms.
    DO_NOT_BUILD = "do_not_build"
    DO_NOT_BUILD_AARCH64 = "do_not_build_aarch64"
    DO_NOT_BUILD_ARMHF = "do_not_build_armhf"
    DO_NOT_BUILD_X86_64 = "do_not_build_x86_64"
    DO_NOT_BUILD_WIN64 = "do_not_build_win64"

    # Build tests, but do not run for all, or just some platforms.
    DO_NOT_RUN = "do_not_run"
    DO_NOT_RUN_ARMHF = "do_not_run_armhf"
    DO_NOT_RUN_AARCH64 = "do_not_run_aarch64"
    DO_NOT_RUN_X86_64 = "do_not_run_x86_64"
    DO_NOT_RUN_WIN64 = "do_not_run_win64"

    # Do not run on foreign architecture kernel (e.g. running armhf on aarch64
    # or running aarch64 on the host with user-space emulation)
    # This option is expected on tests that use kernel APIs not supported in
    # user space emulation or in armhf compatibility mode (most notably
    # /dev/kvm usage)
    DO_NOT_RUN_ON_FOREIGN_KERNEL = "do_not_run_on_foreign_kernel"

    # Run tests single-threaded
    SINGLE_THREADED = "single_threaded"

    # This test needs to be the only one runnning to prevent interference with other tests.
    RUN_EXCLUSIVE = "run_exclusive"

    # This unit test requires special privileges and needs to be run in a test VM like an
    # integration test.
    # Note: This flag should be transitory and tests should be refactored to only require
    # privileges in integration tests.
    UNIT_AS_INTEGRATION_TEST = "unit_as_integration_test"

    # This test needs longer than usual to run.
    LARGE = "large"

    # Integration test that requires root privileges to execute.
    # Note that this does not apply to unit tests, which will never be allowed privileged access
    # to the system.
    REQUIRES_ROOT = "requires_root"


# Configuration to restrict how and where tests of a certain crate can
# be build and run.
#
# Please add a bug number when restricting a tests.

CRATE_OPTIONS: Dict[str, List[TestOption]] = {
    "hypervisor": [
        TestOption.DO_NOT_RUN_AARCH64,
    ],  # b/181672912
    "e2e_tests": [  # b/180196508
        TestOption.LARGE,
        TestOption.DO_NOT_RUN_AARCH64,
        TestOption.DO_NOT_RUN_WIN64,  # b/262270352
    ],
    "io_uring": [TestOption.DO_NOT_RUN],  # b/202294403
    "kvm": [
        TestOption.DO_NOT_RUN_AARCH64,
    ],  # b/181674144
    "sandbox": [TestOption.DO_NOT_RUN],
    "net_util": [TestOption.REQUIRES_ROOT],
}
