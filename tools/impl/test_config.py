# Copyright 2021 The Chromium OS Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import enum
import os


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

    # This test needs longer than usual to run.
    LARGE = "large"

# Configuration to restrict how and where tests of a certain crate can
# be build and run.
#
# Please add a bug number when restricting a tests.

# This is just too big to keep in main list for now
WIN64_DISABLED_CRATES = [
        "aarch64",
        "acpi_tables",
        "arch",
        "assertions",
        "audio_streams",
        "bit_field_derive",
        "bit_field",
        "cros_async",
        "cros_asyncv2",
        "cros-fuzz",
        "crosvm_control",
        "crosvm_plugin",
        "crosvm-fuzz",
        "crosvm",
        "data_model",
        "devices",
        "disk",
        "ffi",
        "fuse",
        "fuzz",
        "gpu_display",
        "hypervisor",
        "integration_tests",
        "io_uring",
        "kernel_cmdline",
        "kernel_loader",
        "kvm_sys",
        "kvm",
        "libcras_stub",
        "libvda",
        "linux_input_sys",
        "minijail-sys",
        "minijail",
        "net_sys",
        "net_util",
        "p9",
        "power_monitor",
        "protos",
        "qcow_utils",
        "resources",
        "rutabaga_gfx",
        "rutabaga_gralloc",
        "sync",
        "sys_util",
        "system_api_stub",
        "tpm2-sys",
        "tpm2",
        "usb_sys",
        "usb_util",
        "vfio_sys",
        "vhost",
        "virtio_sys",
        "vm_control",
        "vm_memory",
        "vmm_vhost",
        "wire_format_derive",
        "x86_64",
        ]

CRATE_OPTIONS: dict[str, list[TestOption]] = {
    "base": [TestOption.SINGLE_THREADED, TestOption.LARGE],
    "cros_async": [TestOption.LARGE],
    "crosvm": [TestOption.SINGLE_THREADED],
    "crosvm_plugin": [
        TestOption.DO_NOT_BUILD_AARCH64,
        TestOption.DO_NOT_BUILD_ARMHF,
        ],
    "crosvm-fuzz": [TestOption.DO_NOT_BUILD],  # b/194499769
    "devices": [
        TestOption.SINGLE_THREADED,
        TestOption.LARGE,
        TestOption.DO_NOT_RUN_ON_FOREIGN_KERNEL,
    ],
    "disk": [TestOption.DO_NOT_RUN_AARCH64, TestOption.DO_NOT_RUN_ARMHF],  # b/202294155
    "fuzz": [TestOption.DO_NOT_BUILD],
    "hypervisor": [
        TestOption.DO_NOT_RUN_AARCH64,
        TestOption.DO_NOT_RUN_ON_FOREIGN_KERNEL,
    ],  # b/181672912
    "integration_tests": [  # b/180196508
        TestOption.SINGLE_THREADED,
        TestOption.LARGE,
        TestOption.DO_NOT_RUN_AARCH64,
        TestOption.DO_NOT_RUN_ON_FOREIGN_KERNEL,
    ],
    "io_uring": [TestOption.DO_NOT_RUN],  # b/202294403
    "kvm_sys": [TestOption.DO_NOT_RUN_ON_FOREIGN_KERNEL],
    "kvm": [
        TestOption.DO_NOT_RUN_AARCH64,
        TestOption.DO_NOT_RUN_ON_FOREIGN_KERNEL,
    ],  # b/181674144
    "libcrosvm_control": [TestOption.DO_NOT_BUILD_ARMHF],  # b/210015864
    "libvda": [TestOption.DO_NOT_BUILD],  # b/202293971
    "rutabaga_gfx": [TestOption.DO_NOT_BUILD_ARMHF],  # b/210015864
    "sys_util": [TestOption.SINGLE_THREADED],
    "sys_util_core": [TestOption.SINGLE_THREADED],
    "vhost": [TestOption.DO_NOT_RUN_ON_FOREIGN_KERNEL],
    "vm_control": [TestOption.DO_NOT_BUILD_ARMHF],  # b/210015864
}

for name in WIN64_DISABLED_CRATES:
    CRATE_OPTIONS[name] = CRATE_OPTIONS.get(name, []) + [TestOption.DO_NOT_BUILD_WIN64]

BUILD_FEATURES: dict[str, str] = {
    "x86_64": "linux-x86_64",
    "aarch64": "linux-aarch64",
    "armhf": "linux-armhf",
    "win64": "win64",
}
