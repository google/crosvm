#!/usr/bin/env bash
# Copyright 2022 The Chromium OS Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
#
# Regenerate vfio_sys bindgen bindings.

set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

source tools/impl/bindgen-common.sh

# VFIO_TYPE is translated as a u8 since it is a char constant, but it needs to be u32 for use in
# ioctl macros.
fix_vfio_type() {
    sed -E -e 's/^pub const VFIO_TYPE: u8 = (.*)u8;/pub const VFIO_TYPE: u32 = \1;/'
}

VFIO_EXTRA="// Added by vfio_sys/bindgen.sh
#[repr(C)]
#[derive(Debug, Default)]
pub struct vfio_region_info_with_cap {
    pub region_info: vfio_region_info,
    pub cap_info: __IncompleteArrayField<u8>,
}"

bindgen_generate \
    --raw-line "${VFIO_EXTRA}" \
    --allowlist-var='VFIO_.*' \
    --blocklist-item='VFIO_DEVICE_API_.*_STRING' \
    --allowlist-type='vfio_.*' \
    "${BINDGEN_LINUX}/include/uapi/linux/vfio.h" \
    -- \
    -D__user= \
    | replace_linux_int_types | fix_vfio_type \
    > vfio_sys/src/vfio.rs
