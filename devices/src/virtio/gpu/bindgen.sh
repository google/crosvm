#!/usr/bin/env bash
# Copyright 2022 The Chromium OS Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
#
# Regenerate virtio-gpu udmabuf bindgen bindings.

set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../../../.."

source tools/impl/bindgen-common.sh

bindgen_generate \
    --allowlist-type='udmabuf_.*' \
    --allowlist-var="UDMABUF_.*" \
    "${BINDGEN_LINUX}/include/uapi/linux/udmabuf.h" \
    | replace_linux_int_types | rustfmt \
    > devices/src/virtio/gpu/udmabuf_bindings.rs
