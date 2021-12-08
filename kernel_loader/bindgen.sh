#!/usr/bin/env bash
# Copyright 2022 The Chromium OS Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
#
# Regenerate kernel_loader bindgen bindings.

set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

source tools/impl/bindgen-common.sh

bindgen_generate \
    --allowlist-type='Elf64_Ehdr' \
    --allowlist-type='Elf64_Phdr' \
    --allowlist-var='.+' \
    "${BINDGEN_LINUX_X86_HEADERS}/include/linux/elf.h" \
    -- \
    -isystem "${BINDGEN_LINUX_X86_HEADERS}/include" \
    | replace_linux_int_types \
    > kernel_loader/src/elf.rs
