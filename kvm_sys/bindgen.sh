#!/usr/bin/env bash
# Copyright 2022 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# Regenerate kvm_sys bindgen bindings.

set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

source tools/impl/bindgen-common.sh

KVM_EXTRAS="// Added by kvm_sys/bindgen.sh
// TODO(tjeznach): Remove this when reporting KVM_IOAPIC_NUM_PINS is no longer required.
pub const KVM_CAP_IOAPIC_NUM_PINS: u32 = 8191;
// TODO(qwandor): Update this once the pKVM patches are merged upstream with a stable capability ID.
pub const KVM_CAP_ARM_PROTECTED_VM: u32 = 0xffbadab1;
pub const KVM_CAP_ARM_PROTECTED_VM_FLAGS_SET_FW_IPA: u32 = 0;
pub const KVM_CAP_ARM_PROTECTED_VM_FLAGS_INFO: u32 = 1;
pub const KVM_VM_TYPE_ARM_PROTECTED: u32 = 0x80000000;"

bindgen_generate \
    --raw-line "${KVM_EXTRAS}" \
    --blocklist-item='__kernel.*' \
    --blocklist-item='__BITS_PER_LONG' \
    --blocklist-item='__FD_SETSIZE' \
    --blocklist-item='_?IOC.*' \
    "${BINDGEN_LINUX_X86_HEADERS}/include/linux/kvm.h" \
    -- \
    -isystem "${BINDGEN_LINUX_X86_HEADERS}/include" \
    | replace_linux_int_types \
    > kvm_sys/src/x86/bindings.rs

bindgen_generate \
    --raw-line "${KVM_EXTRAS}" \
    --blocklist-item='__kernel.*' \
    --blocklist-item='__BITS_PER_LONG' \
    --blocklist-item='__FD_SETSIZE' \
    --blocklist-item='_?IOC.*' \
    "${BINDGEN_LINUX_ARM64_HEADERS}/include/linux/kvm.h" \
    -- \
    -isystem "${BINDGEN_LINUX_ARM64_HEADERS}/include" \
    | replace_linux_int_types \
    > kvm_sys/src/aarch64/bindings.rs
