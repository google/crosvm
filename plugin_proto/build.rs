// Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

extern crate protoc_rust;

use std::env;
use std::fs;
use std::io::Write;
use std::path::PathBuf;

fn main() {
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());

    protoc_rust::run(protoc_rust::Args {
        out_dir: out_dir.as_os_str().to_str().unwrap(),
        input: &["protos/plugin.proto"],
        includes: &["protos"],
    })
    .expect("protoc");

    let mut mod_out = fs::File::create(out_dir.join("proto_include.rs")).unwrap();
    writeln!(
        mod_out,
        "#[path = \"{}\"] pub mod plugin_proto;\npub use plugin_proto::*;",
        out_dir.join("plugin.rs").display()
    )
    .unwrap();
}
