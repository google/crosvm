// Copyright 2022 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

fn main() {
    // Skip installing dependencies when generating documents.
    if std::env::var("CARGO_DOC").is_ok() {
        return;
    }

    cc::Build::new()
        .file("src/windows/stdio_fileno.c")
        .compile("stdio_fileno");
}
