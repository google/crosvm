#!/usr/bin/env bash
# Copyright 2025 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# Regenerate halla_sys bindgen bindings.

set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../../../.."

source tools/impl/bindgen-common.sh

HVM_HEADER_FILE="${BINDGEN_LINUX_ARM64_HEADERS}/include/linux/hvm_common.h"
HVM_SYS_BASE="hypervisor/src/halla/halla_sys"
HVM_BINDINGS="${HVM_SYS_BASE}/aarch64/bindings.rs"

bindgen_generate \
    --blocklist-item='__kernel.*' \
    --blocklist-item='__BITS_PER_LONG' \
    --blocklist-item='__FD_SETSIZE' \
    --blocklist-item='_?IOC.*' \
    ${HVM_HEADER_FILE} \
    -- \
    -isystem "${BINDGEN_LINUX_ARM64_HEADERS}/include" \
    | replace_linux_int_types \
    > ${HVM_BINDINGS}
