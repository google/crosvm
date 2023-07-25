#!/bin/bash
# Copyright 2023 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

mount -t proc none /proc
mount -t sysfs none /sys
mount -t devtmpfs none /dev

if [ -f "/dev/sda" ]; then
    mount /dev/sda /newroot
else
    mount /dev/vda /newroot
fi

mkdir -p /newroot/proc /newroot/sys /newroot/dev || true

mount --move /sys /newroot/sys
mount --move /proc /newroot/proc
mount --move /dev /newroot/dev

cp /bin/delegate /newroot/bin/delegate || true

cd /newroot && chroot /newroot /bin/delegate
