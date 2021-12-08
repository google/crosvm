#!/usr/bin/env bash
# Copyright 2022 The Chromium OS Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
#
# Regenerate virtio_sys bindgen bindings.

set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

source tools/impl/bindgen-common.sh

bindgen_generate \
    --allowlist-type='vhost_.*' \
    --allowlist-var='VHOST_.*' \
    --allowlist-var='VIRTIO_.*' \
    "${BINDGEN_LINUX_X86_HEADERS}/include/linux/vhost.h" \
    -- \
    -isystem "${BINDGEN_LINUX_X86_HEADERS}/include" \
    | replace_linux_int_types \
    > virtio_sys/src/vhost.rs

bindgen_generate \
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
