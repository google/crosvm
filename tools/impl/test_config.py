# Copyright 2021 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import enum
from typing import List, Dict


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


# Configuration to restrict how and where tests of a certain crate can
# be build and run.
#
# Please add a bug number when restricting a tests.

# This is just too big to keep in main list for now
WIN64_DISABLED_CRATES = [
    "aarch64",
    "cros_asyncv2",
    "cros-fuzz",
    "crosvm_plugin",
    "crosvm-fuzz",
    "ffi",
    "ffmpeg",
    "fuse",
    "fuzz",
    "gpu_display",
    "e2e_tests",
    "io_uring",
    "kvm",
    "libcras_stub",
    "libva",
    "libvda",
    "minijail-sys",
    "minijail",
    "p9",
    "qcow_utils",
    "rutabaga_gralloc",
    "swap",
    "system_api_stub",
    "tpm2-sys",
    "tpm2",
    "usb_util",
]

CRATE_OPTIONS: Dict[str, List[TestOption]] = {
    "crosvm-fuzz": [TestOption.DO_NOT_BUILD],  # b/194499769
    "cros-fuzz": [TestOption.DO_NOT_BUILD],
    "fuzz": [TestOption.DO_NOT_BUILD],
    "hypervisor": [
        TestOption.DO_NOT_RUN_AARCH64,
    ],  # b/181672912
    "e2e_tests": [  # b/180196508
        TestOption.LARGE,
        TestOption.DO_NOT_RUN_AARCH64,
    ],
    "io_uring": [TestOption.DO_NOT_RUN],  # b/202294403
    "kvm": [
        TestOption.DO_NOT_RUN_AARCH64,
    ],  # b/181674144
    "libvda": [TestOption.DO_NOT_RUN],  # b/202293971
    "sandbox": [TestOption.DO_NOT_RUN],
}

for name in WIN64_DISABLED_CRATES:
    CRATE_OPTIONS[name] = CRATE_OPTIONS.get(name, []) + [TestOption.DO_NOT_BUILD_WIN64]

BUILD_FEATURES: Dict[str, str] = {
    "x86_64-unknown-linux-gnu": "linux-x86_64",
    "aarch64-unknown-linux-gnu": "linux-aarch64",
    "armv7-unknown-linux-gnueabihf": "linux-armhf",
    "x86_64-pc-windows-gnu": "win64",
    "x86_64-pc-windows-msvc": "win64",
}
