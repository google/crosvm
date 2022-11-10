#!/usr/bin/env bash
# Copyright 2022 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# Ensure there's only 1 instance of setup-user.sh running
flock /tmp/entrypoint_lock /tools/setup-user.sh

# Give KVM device correct permission
if [ -e "/dev/kvm" ]; then
    chmod 666 /dev/kvm
fi

# Give a vhost device correct permission
if [ -e "/dev/vhost-vsock" ]; then
    chmod 666 /dev/vhost-vsock
fi

# Run provided command or interactive shell
if [[ $# -eq 0 ]]; then
    sudo -u crosvmdev /bin/bash -l
else
    # Use "@Q" expansion to correctly quote the arguments.
    # For more details, see the "${parameter@operator}" section of
    # https://www.gnu.org/software/bash/manual/html_node/Shell-Parameter-Expansion.html.
    sudo -u crosvmdev /bin/bash -l -c "${*@Q}"
fi
