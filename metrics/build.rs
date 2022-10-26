// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::env;
use std::fs;
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;

use protoc_rust::Codegen;
use protoc_rust::Customize;

fn main() {
    build_protos();
}

// TODO(mikehoyle): Unify all proto-building logic across crates into a common build dependency.
fn build_protos() {
    let proto_files = vec!["protos/event_details.proto"];
    let out_dir = format!(
        "{}/metrics_protos",
        env::var("OUT_DIR").expect("OUT_DIR env does not exist.")
    );
    fs::create_dir_all(&out_dir).unwrap();

    Codegen::new()
        .out_dir(&out_dir)
        .inputs(&proto_files)
        .customize(Customize {
            serde_derive: Some(true),
            ..Default::default()
        })
        .run()
        .unwrap();
    create_gen_file(proto_files, &out_dir);
}

fn create_gen_file(proto_files: Vec<&str>, out_dir: &str) {
    let generated = PathBuf::from(&out_dir).join("generated.rs");
    let out = File::create(generated).expect("Failed to create generated file.");

    for proto in proto_files {
        let file_stem = PathBuf::from(proto)
            .file_stem()
            .unwrap()
            .to_str()
            .unwrap()
            .to_owned();
        let out_dir = out_dir.replace('\\', "/");
        writeln!(&out, "#[path = \"{}/{}.rs\"]", out_dir, file_stem)
            .expect("failed to write to generated.");
        writeln!(&out, "pub mod {}_proto;", file_stem).expect("failed to write to generated.");
    }
}
