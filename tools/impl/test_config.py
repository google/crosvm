# Copyright 2021 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

from typing import Dict

BUILD_FEATURES: Dict[str, str] = {
    "x86_64-unknown-linux-gnu": "linux-x86_64",
    "aarch64-unknown-linux-gnu": "linux-aarch64",
    "armv7-unknown-linux-gnueabihf": "linux-armhf",
    "x86_64-pc-windows-gnu": "win64",
    "x86_64-pc-windows-msvc": "win64",
}

# Do not build these on riscv64. They don't yet have riscv64 support of the backing libraries in the
# dev container.
DO_NOT_BUILD_RISCV64 = [
    "libvda",
    "libva",
    "ffmpeg",
    "vmm_vhost",
    "system_api",
    "gpu_display",
]

# Configuration of integration tests
#
# The configuration below only applies to integration tests to fine tune which tests can be run
# on which platform (e.g. aarch64 emulation does not pass kvm tests).
#
# This configuration does NOT apply to unit tests.

# List of integration tests that will ask for root privileges.
ROOT_TESTS = [
    "package(e2e_tests) & binary(pci_hotplug)",
    "package(e2e_tests) & binary(swap)",
    "package(net_util) & binary(unix_tap)",
    "package(cros_tracing) & binary(trace_marker)",
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

# Avoid e2e tests and benchmarks to be automatically included as unit tests
E2E_TESTS = [
    "package(e2e_tests)",
]
