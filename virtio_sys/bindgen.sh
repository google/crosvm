#!/usr/bin/env bash
# Copyright 2022 The Chromium OS Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
#
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
