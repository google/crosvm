# Copyright 2021 The Chromium OS Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import enum


class TestOption(enum.Enum):
    # Do not build tests for all, or just some platforms.
    DO_NOT_BUILD = "do_not_build"
    DO_NOT_BUILD_AARCH64 = "do_not_build_aarch64"
    DO_NOT_BUILD_ARMHF = "do_not_build_armhf"
    DO_NOT_BUILD_X86_64 = "do_not_build_x86_64"

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



# Configuration to restrict how and where tests of a certain crate can
# be build and run.
#
# Please add a bug number when restricting a tests.
CRATE_OPTIONS: dict[str, list[TestOption]] = {
    "aarch64": [TestOption.DO_NOT_BUILD_X86_64, TestOption.DO_NOT_BUILD_ARMHF], #b/210015864
    "crosvm_plugin": [TestOption.DO_NOT_BUILD_AARCH64, TestOption.DO_NOT_BUILD_ARMHF],
    "devices": [TestOption.SINGLE_THREADED, TestOption.DO_NOT_RUN_ON_FOREIGN_KERNEL],
    "disk": [TestOption.DO_NOT_RUN_AARCH64, TestOption.DO_NOT_RUN_ARMHF],  # b/202294155
    "crosvm-fuzz": [TestOption.DO_NOT_BUILD],  # b/194499769
    "hypervisor": [TestOption.DO_NOT_RUN_AARCH64, TestOption.DO_NOT_RUN_ON_FOREIGN_KERNEL],  # b/181672912
    "integration_tests": [  # b/180196508
        TestOption.SINGLE_THREADED,
        TestOption.DO_NOT_RUN_AARCH64,
        TestOption.DO_NOT_RUN_ON_FOREIGN_KERNEL,
    ],
    "io_uring": [TestOption.DO_NOT_RUN],  # b/202294403
    "kvm_sys": [TestOption.DO_NOT_RUN_ON_FOREIGN_KERNEL],
    "kvm": [TestOption.DO_NOT_RUN_AARCH64, TestOption.DO_NOT_RUN_ON_FOREIGN_KERNEL],  # b/181674144
    "libcras_stub": [TestOption.DO_NOT_BUILD],  # empty stub crate
    "libvda": [TestOption.DO_NOT_BUILD],  # b/202293971
    "system_api_stub": [TestOption.DO_NOT_BUILD],  # empty stub crate
    "x86_64": [TestOption.DO_NOT_BUILD_AARCH64, TestOption.DO_NOT_BUILD_ARMHF],
    "sys_util": [TestOption.SINGLE_THREADED],
    "sys_util_core": [TestOption.SINGLE_THREADED],
    "rutabaga_gfx_ffi": [TestOption.DO_NOT_BUILD],  # b/206689789
    "rutabaga_gfx": [TestOption.DO_NOT_BUILD_ARMHF], #b/210015864
    "vhost": [TestOption.DO_NOT_RUN_ON_FOREIGN_KERNEL],
    "vm_control": [TestOption.DO_NOT_BUILD_ARMHF], #b/210015864
    "libcrosvm_control": [TestOption.DO_NOT_BUILD_ARMHF], #b/210015864
}

BUILD_FEATURES: dict[str, str] = {
    "x86_64": "all-linux",
    "aarch64": "all-linux",
    "armhf": "all-linux-armhf"
}
