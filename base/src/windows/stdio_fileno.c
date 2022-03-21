// Copyright 2022 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <stdio.h>

int stdout_fileno() {
    return fileno(stdout);
}

int stderr_fileno() {
    return fileno(stderr);
}
