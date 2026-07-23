// Copyright 2026 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

fn main() {
    println!("cargo:rustc-check-cfg=cfg(zerocopy_derive_union_into_bytes)");
    println!("cargo::rustc-cfg=zerocopy_derive_union_into_bytes");
}
