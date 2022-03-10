// Copyright 2022 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#[cfg(unix)]
fn main() {}

#[cfg(windows)]
fn main() {
    cc::Build::new()
        .file("src\\stdio_fileno.c")
        .compile("stdio_fileno");
}
