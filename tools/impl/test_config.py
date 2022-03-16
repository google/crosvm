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
if os.name == "posix":
    CRATE_OPTIONS: dict[str, list[TestOption]] = {
        "base": [TestOption.SINGLE_THREADED, TestOption.LARGE],
        "cros_async": [TestOption.LARGE],
        "crosvm_plugin": [TestOption.DO_NOT_BUILD_AARCH64, TestOption.DO_NOT_BUILD_ARMHF],
        "crosvm": [TestOption.SINGLE_THREADED],
        "devices": [
            TestOption.SINGLE_THREADED,
            TestOption.LARGE,
            TestOption.DO_NOT_RUN_ON_FOREIGN_KERNEL,
        ],
        "disk": [TestOption.DO_NOT_RUN_AARCH64, TestOption.DO_NOT_RUN_ARMHF],  # b/202294155
        "crosvm-fuzz": [TestOption.DO_NOT_BUILD],  # b/194499769
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
        "libvda": [TestOption.DO_NOT_BUILD],  # b/202293971
        "sys_util": [TestOption.SINGLE_THREADED],
        "sys_util_core": [TestOption.SINGLE_THREADED],
        "rutabaga_gfx": [TestOption.DO_NOT_BUILD_ARMHF],  # b/210015864
        "vhost": [TestOption.DO_NOT_RUN_ON_FOREIGN_KERNEL],
        "vm_control": [TestOption.DO_NOT_BUILD_ARMHF],  # b/210015864
        "libcrosvm_control": [TestOption.DO_NOT_BUILD_ARMHF],  # b/210015864
    }

    BUILD_FEATURES: dict[str, str] = {
        "x86_64": "linux-x86_64",
        "aarch64": "linux-aarch64",
        "armhf": "linux-armhf",
    }
elif os.name == "nt":
    CRATE_OPTIONS: dict[str, list[TestOption]] = {
        "aarch64": [TestOption.DO_NOT_BUILD],
        "acpi_tables": [TestOption.DO_NOT_BUILD],
        "arch": [TestOption.DO_NOT_BUILD],
        "audio_streams": [TestOption.DO_NOT_BUILD],
        "balloon_control": [],
        "base": [TestOption.DO_NOT_BUILD],
        "bit_field_derive": [TestOption.DO_NOT_BUILD],
        "bit_field": [TestOption.DO_NOT_BUILD],
        "cros_async": [TestOption.DO_NOT_BUILD],
        "cros_asyncv2": [TestOption.DO_NOT_BUILD],
        "cros-fuzz": [TestOption.DO_NOT_BUILD],
        "crosvm_control": [TestOption.DO_NOT_BUILD],
        "crosvm_plugin": [TestOption.DO_NOT_BUILD],
        "crosvm-fuzz": [TestOption.DO_NOT_BUILD],
        "crosvm": [TestOption.DO_NOT_BUILD],
        "devices": [TestOption.DO_NOT_BUILD],
        "disk": [TestOption.DO_NOT_BUILD],
        "ffi": [TestOption.DO_NOT_BUILD],
        "fuse": [TestOption.DO_NOT_BUILD],
        "fuzz": [TestOption.DO_NOT_BUILD],
        "gpu_display": [TestOption.DO_NOT_BUILD],
        "hypervisor": [TestOption.DO_NOT_BUILD],
        "integration_tests": [TestOption.DO_NOT_BUILD],
        "io_uring": [TestOption.DO_NOT_BUILD],
        "kernel_cmdline": [TestOption.DO_NOT_BUILD],
        "kernel_loader": [TestOption.DO_NOT_BUILD],
        "kvm_sys": [TestOption.DO_NOT_BUILD],
        "kvm": [TestOption.DO_NOT_BUILD],
        "libcras_stub": [TestOption.DO_NOT_BUILD],
        "libvda": [TestOption.DO_NOT_BUILD],
        "linux_input_sys": [TestOption.DO_NOT_BUILD],
        "minijail-sys": [TestOption.DO_NOT_BUILD],
        "minijail": [TestOption.DO_NOT_BUILD],
        "net_sys": [TestOption.DO_NOT_BUILD],
        "net_util": [TestOption.DO_NOT_BUILD],
        "p9": [TestOption.DO_NOT_BUILD],
        "poll_token_derive": [],
        "power_monitor": [TestOption.DO_NOT_BUILD],
        "protos": [TestOption.DO_NOT_BUILD],
        "qcow_utils": [TestOption.DO_NOT_BUILD],
        "resources": [TestOption.DO_NOT_BUILD],
        "rutabaga_gfx": [TestOption.DO_NOT_BUILD],
        "rutabaga_gralloc": [TestOption.DO_NOT_BUILD],
        "sync": [TestOption.DO_NOT_BUILD],
        "sys_util": [TestOption.DO_NOT_BUILD],
        "sys_util_core": [],
        "system_api_stub": [TestOption.DO_NOT_BUILD],
        "tpm2-sys": [TestOption.DO_NOT_BUILD],
        "tpm2": [TestOption.DO_NOT_BUILD],
        "usb_sys": [TestOption.DO_NOT_BUILD],
        "usb_util": [TestOption.DO_NOT_BUILD],
        "vfio_sys": [TestOption.DO_NOT_BUILD],
        "vhost": [TestOption.DO_NOT_BUILD],
        "virtio_sys": [TestOption.DO_NOT_BUILD],
        "vm_control": [TestOption.DO_NOT_BUILD],
        "vm_memory": [TestOption.DO_NOT_BUILD],
        "vmm_vhost": [TestOption.DO_NOT_BUILD],
        "wire_format_derive": [TestOption.DO_NOT_BUILD],
        "x86_64": [TestOption.DO_NOT_BUILD],
    }

    BUILD_FEATURES: dict[str, str] = {
        "x86_64": "",
    }
else:
    raise Exception(f"Unsupported build target: {os.name}")
