// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::env;
use std::fs::File;
use std::io::Write;

fn main() {
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap();

    println!("cargo::rustc-check-cfg=cfg(goldfish)"); // Silences warnings
                                                      // Override prefix from environment variable (with a default)
    let prefix = format!(
        r##"prefix={prefix}"##,
        prefix = env::var("PREFIX").unwrap_or_else(|_| "/usr".to_string())
    );

    // Generate .pc file contents
    let pc_contents = format!(
        "{}{}",
        prefix,
        r###"
exec_prefix=${prefix}
includedir=${prefix}/include
libdir=${exec_prefix}/lib

Name: rutabaga_gfx_ffi
Description: C FFI bindings to Rutabaga VGI
Version: 0.1.6
Cflags: -I${includedir}
Libs: -L${libdir} -lrutabaga_gfx_ffi
"###,
    );

    // Write the .pc file to the output directory
    let mut pc_file = File::create(format!(
        "{}/{}/rutabaga_gfx_ffi.pc",
        env::var("CARGO_TARGET_DIR").as_deref().unwrap_or("target"),
        env::var("PROFILE").unwrap()
    ))
    .unwrap();
    pc_file.write_all(pc_contents.as_bytes()).unwrap();

    println!("cargo:rerun-if-changed=build.rs"); // Rebuild if build.rs changes

    if target_os.contains("linux") || target_os.contains("nto") {
        println!("cargo:rustc-cdylib-link-arg=-Wl,-soname,librutabaga_gfx_ffi.so.0");
    }
}
