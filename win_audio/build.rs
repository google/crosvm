// Copyright 2022 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

fn main() {
    #[cfg(windows)]
    {
        use std::env;
        let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
        println!("cargo:rustc-link-lib=static=r8brain");
        #[cfg(debug_assertions)]
        {
            let dll_dir = format!(
                r#"{}\..\..\..\third_party\r8brain\r8brain\x64\Debug\"#,
                manifest_dir
            );
            println!(r#"cargo:rustc-link-search={}"#, dll_dir);
            println!(
                r#"cargo:rustc-env=PATH={};{}"#,
                env::var("PATH").unwrap(),
                dll_dir
            );
        }
        #[cfg(not(debug_assertions))]
        {
            let dll_dir = format!(
                r#"{}\..\..\..\third_party\r8brain\r8brain\x64\Release\"#,
                manifest_dir
            );
            println!(r#"cargo:rustc-link-search={}"#, dll_dir);
            println!(
                r#"cargo:rustc-env=PATH={};{}"#,
                env::var("PATH").unwrap(),
                dll_dir
            );
        }
    }
}
