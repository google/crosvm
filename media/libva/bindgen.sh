#!/usr/bin/env bash
# Copyright 2022 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# Regenerate libva bindgen bindings.

set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."
source tools/impl/bindgen-common.sh
bindgen_generate \
    --raw-line "pub mod constants;" \
    --with-derive-eq \
    --constified-enum-module "VA.*" \
    --allowlist-function "va.*" \
    --allowlist-type ".*MPEG2.*|.*VP8.*|.*VP9.*|.*H264.*" \
    "media/libva/libva-wrapper.h" \
    > media/libva/src/bindings/va.rs

bindgen_generate \
    --allowlist-var "VA.*" \
    "media/libva/libva-wrapper.h" \
    > media/libva/src/bindings/va/constants.rs
