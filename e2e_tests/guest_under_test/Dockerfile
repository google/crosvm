# Copyright 2020 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
ARG ARCH
FROM ${ARCH}/alpine:3.16

RUN apk add --no-cache pciutils nmap-ncat

# Note: This docker file is run from the $(target)/rootfs directory specified in
#       the Makefile.
COPY ./delegate /bin/delegate
