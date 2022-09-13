#!/usr/bin/env bash
# Copyright 2022 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# Regenerate ffmpeg bindgen bindings.

set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."

VERSIONS="media/ffmpeg/VERSIONS"

source tools/impl/bindgen-common.sh

bindgen_generate \
    --allowlist-function "av_.*" \
    --allowlist-function "avcodec_.*" \
    --allowlist-function "sws_.*" \
    --allowlist-function "av_image_.*" \
    --allowlist-var "FF_PROFILE.*" \
    --allowlist-var "AV_.*" \
    --allowlist-var "AVERROR_.*" \
    media/ffmpeg/src/bindings.h \
    > media/ffmpeg/src/ffmpeg.rs

echo "# These version numbers are updated by the bindgen.sh script" >$VERSIONS
echo "avcodec: `pkg-config --modversion libavcodec`" >>$VERSIONS
echo "avutil: `pkg-config --modversion libavutil`" >>$VERSIONS
echo "swscale: `pkg-config --modversion libswscale`" >>$VERSIONS

if ! git --no-pager diff --exit-code $VERSIONS; then
    echo "Libraries versions updated in the $VERSIONS file."
    echo "Please check the minimum required versions in build.rs and make sure that"
    echo "the major number is the same"
fi
