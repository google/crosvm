#!/usr/bin/env bash
# Copyright 2022 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# Regenerate virtio_sys bindgen bindings.

set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

source tools/impl/bindgen-common.sh


VIRTIO_NET_EXTRA="// Added by virtio_sys/bindgen.sh
use data_model::DataInit;

// Safe because virtio_net_hdr_mrg_rxbuf has no implicit padding.
unsafe impl DataInit for virtio_net_hdr_mrg_rxbuf {}"

bindgen_generate \
    --allowlist-type='vhost_.*' \
    --allowlist-var='VHOST_.*' \
    "${BINDGEN_LINUX_X86_HEADERS}/include/linux/vhost.h" \
    -- \
    -isystem "${BINDGEN_LINUX_X86_HEADERS}/include" \
    | replace_linux_int_types \
    > virtio_sys/src/vhost.rs

bindgen_generate \
    --allowlist-var='VIRTIO_.*' \
    --allowlist-type='virtio_.*' \
    "${BINDGEN_LINUX_X86_HEADERS}/include/linux/virtio_config.h" \
    -- \
    -isystem "${BINDGEN_LINUX_X86_HEADERS}/include" \
    | replace_linux_int_types \
    > virtio_sys/src/virtio_config.rs

VIRTIO_FS_EXTRA="// Added by virtio_sys/bindgen.sh
use data_model::DataInit;
use data_model::Le32;

// Safe because all members are plain old data and any value is valid.
unsafe impl DataInit for virtio_fs_config {}"

bindgen_generate \
    --raw-line "${VIRTIO_FS_EXTRA}" \
    --allowlist-var='VIRTIO_FS_.*' \
    --allowlist-type='virtio_fs_.*' \
    "${BINDGEN_LINUX_X86_HEADERS}/include/linux/virtio_fs.h" \
    -- \
    -isystem "${BINDGEN_LINUX_X86_HEADERS}/include" \
    | replace_linux_int_types \
    | replace_linux_endian_types \
    > virtio_sys/src/virtio_fs.rs

VIRTIO_IDS_EXTRAS="
//! This file defines virtio device IDs. IDs with large values (counting down
//! from 63) are nonstandard and not defined by the virtio specification.

// Added by virtio_sys/bindgen.sh - do not edit the generated file.
// TODO(abhishekbh): Fix this after this device is accepted upstream.
pub const VIRTIO_ID_VHOST_USER: u32 = 61;
"

bindgen_generate \
    --raw-line "${VIRTIO_IDS_EXTRAS}" \
    --allowlist-var='VIRTIO_ID_.*' \
    --allowlist-type='virtio_.*' \
    "${BINDGEN_LINUX_X86_HEADERS}/include/linux/virtio_ids.h" \
    -- \
    -isystem "${BINDGEN_LINUX_X86_HEADERS}/include" \
    | replace_linux_int_types \
    | rustfmt \
    > virtio_sys/src/virtio_ids.rs

bindgen_generate \
    --raw-line "${VIRTIO_NET_EXTRA}" \
    --allowlist-var='VIRTIO_NET_.*' \
    --allowlist-type='virtio_net_.*' \
    --blocklist-type='virtio_net_ctrl_mac' \
    "${BINDGEN_LINUX_X86_HEADERS}/include/linux/virtio_net.h" \
    -- \
    -isystem "${BINDGEN_LINUX_X86_HEADERS}/include" \
    | replace_linux_int_types \
    > virtio_sys/src/virtio_net.rs

bindgen_generate \
    --allowlist-var='VRING_.*' \
    --allowlist-var='VIRTIO_RING_.*' \
    --allowlist-type='vring.*' \
    "${BINDGEN_LINUX_X86_HEADERS}/include/linux/virtio_ring.h" \
    -- \
    -isystem "${BINDGEN_LINUX_X86_HEADERS}/include" \
    | replace_linux_int_types \
    > virtio_sys/src/virtio_ring.rs

bindgen_generate \
    --allowlist-var='VIRTIO_.*' \
    --allowlist-type='virtio_.*' \
    "${BINDGEN_LINUX_X86_HEADERS}/include/linux/virtio_mmio.h" \
    -- \
    -isystem "${BINDGEN_LINUX_X86_HEADERS}/include" \
    | replace_linux_int_types \
    > virtio_sys/src/virtio_mmio.rs
