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
    "integration_tests",
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
    "system_api_stub",
    "tpm2-sys",
    "tpm2",
    "usb_util",
]

CRATE_OPTIONS: Dict[str, List[TestOption]] = {
    "cros_async": [TestOption.LARGE, TestOption.RUN_EXCLUSIVE],
    "crosvm": [TestOption.SINGLE_THREADED, TestOption.UNIT_AS_INTEGRATION_TEST],
    "crosvm_plugin": [
        TestOption.DO_NOT_BUILD_AARCH64,
        TestOption.DO_NOT_BUILD_ARMHF,
    ],
    "crosvm-fuzz": [TestOption.DO_NOT_BUILD],  # b/194499769
    "disk": [TestOption.DO_NOT_RUN_AARCH64, TestOption.DO_NOT_RUN_ARMHF],  # b/202294155
    "ffmpeg": [TestOption.DO_NOT_BUILD_ARMHF],
    "cros-fuzz": [TestOption.DO_NOT_BUILD],
    "fuzz": [TestOption.DO_NOT_BUILD],
    "hypervisor": [
        TestOption.DO_NOT_RUN_AARCH64,
        TestOption.DO_NOT_RUN_ARMHF,
        TestOption.DO_NOT_RUN_ON_FOREIGN_KERNEL,
    ],  # b/181672912
    "integration_tests": [  # b/180196508
        TestOption.SINGLE_THREADED,
        TestOption.RUN_EXCLUSIVE,
        TestOption.LARGE,
        TestOption.DO_NOT_RUN_AARCH64,
        TestOption.DO_NOT_RUN_ARMHF,
        TestOption.DO_NOT_RUN_ON_FOREIGN_KERNEL,
    ],
    "io_uring": [TestOption.DO_NOT_RUN],  # b/202294403
    "kvm_sys": [TestOption.DO_NOT_RUN_ON_FOREIGN_KERNEL],
    "kvm": [
        TestOption.DO_NOT_RUN_AARCH64,
        TestOption.DO_NOT_RUN_ARMHF,
        TestOption.DO_NOT_RUN_ON_FOREIGN_KERNEL,
    ],  # b/181674144
    "libcrosvm_control": [TestOption.DO_NOT_BUILD_ARMHF],  # b/210015864
    "libva": [
        # Libva only makes sense for x86 Linux platforms, disable building on others.
        TestOption.DO_NOT_BUILD_AARCH64,
        TestOption.DO_NOT_BUILD_ARMHF,
        TestOption.DO_NOT_BUILD_WIN64,
        # Only run libva on Linux x86. Note that all tests are not enabled, see b/238047780.
        TestOption.DO_NOT_RUN_AARCH64,
        TestOption.DO_NOT_RUN_ARMHF,
    ],
    "libvda": [TestOption.DO_NOT_BUILD],  # b/202293971
    "rutabaga_gfx": [TestOption.DO_NOT_BUILD_ARMHF],  # b/210015864
    "sandbox": [TestOption.DO_NOT_RUN],
    "vhost": [TestOption.DO_NOT_RUN_ON_FOREIGN_KERNEL, TestOption.UNIT_AS_INTEGRATION_TEST],
    "vm_control": [TestOption.DO_NOT_BUILD_ARMHF],  # b/210015864
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
