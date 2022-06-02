#!/usr/bin/env bash
# Copyright 2022 The Chromium OS Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
#
# Regenerate ffmpeg bindgen bindings.

set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."

VERSIONS="media/ffmpeg/VERSIONS"

#source tools/impl/bindgen-common.sh

bindgen media/ffmpeg/src/bindings.h -o media/ffmpeg/src/ffmpeg.rs \
    --allowlist-function "av_.*" \
    --allowlist-function "avcodec_.*" \
    --allowlist-function "sws_.*" \
    --allowlist-function "av_image_.*" \
    --allowlist-var "FF_PROFILE.*" \
    --allowlist-var "AV_.*" \
    --allowlist-var "AVERROR_.*"

echo "# These version numbers are updated by the gen_bindings.sh script" >$VERSIONS
echo "avcodec: `pkg-config --modversion libavcodec`" >>$VERSIONS
echo "avutil: `pkg-config --modversion libavutil`" >>$VERSIONS
echo "swscale: `pkg-config --modversion libswscale`" >>$VERSIONS

echo "Libraries versions updated in the VERSIONS file."
echo "Please check the minimum required versions in build.rs and make sure that"
echo "the major number is the same"
