// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Contains utilities to build protos & make them available to Rust.

use std::collections::HashSet;
use std::fs;
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;

use protoc_rust::Customize;

/// Builds a set of Rust protos based on the provided proto files. The individual protos will be
/// dumped into `out_dir` (will be created if needed), along with a file that wraps them
/// `out_dir/generated.rs`. The wrapper file can then be included using a pattern like:
/// ```ignore
/// pub mod protos {
///    // Suppose the `out_dir` supplied to `build_protos` was
///    // format!("{}/my_crate_protos", env!("OUT_DIR"))
///    include!(concat!(env!("OUT_DIR"), "/my_crate_protos/generated.rs"));
/// }
/// // Protos are available at protos::proto_file_name.
/// ```
pub fn build_protos(out_dir: &PathBuf, proto_paths: &[PathBuf]) {
    build_protos_explicit(
        out_dir,
        proto_paths,
        proto_paths,
        to_includes(proto_paths).as_slice(),
    )
}

/// Allows for more control than build_protos (useful when the proto build is more complex).
pub fn build_protos_explicit(
    out_dir: &PathBuf,
    proto_paths: &[PathBuf],
    rebuild_if_changed_paths: &[PathBuf],
    includes: &[PathBuf],
) {
    for file in rebuild_if_changed_paths {
        // Triggers rebuild if the file has newer mtime.
        println!(
            "cargo:rerun-if-changed={}",
            file.to_str().expect("proto path must be UTF-8")
        );
    }
    fs::create_dir_all(out_dir).unwrap();
    gen_protos(out_dir, proto_paths, includes);
    create_gen_file(out_dir, proto_paths);
}

/// Given a list of proto files, extract the set of include directories needed to pass to the proto
/// compiler.
fn to_includes(proto_paths: &[PathBuf]) -> Vec<PathBuf> {
    let mut include_paths = HashSet::new();

    for proto in proto_paths {
        include_paths.insert(
            proto
                .parent()
                .expect("protos must be files in a directory")
                .to_owned(),
        );
    }

    include_paths.drain().collect::<Vec<PathBuf>>()
}

fn gen_protos(out_dir: &PathBuf, proto_paths: &[PathBuf], includes: &[PathBuf]) {
    if let Err(e) = protoc_rust::Codegen::new()
        .out_dir(out_dir)
        .inputs(proto_paths)
        .includes(includes)
        .customize(Customize {
            serde_derive: Some(true),
            ..Default::default()
        })
        .run()
    {
        println!("failed to build Rust protos: {}", e);
        println!("protos in failed build: {:?}", proto_paths);
        println!("includes in failed build: {:?}", includes);
    }
}

fn create_gen_file(out_dir: &PathBuf, proto_files: &[PathBuf]) {
    let generated = PathBuf::from(&out_dir).join("generated.rs");
    let out = File::create(generated).expect("Failed to create generated file.");

    for proto_path in proto_files {
        let file_stem = proto_path.file_stem().unwrap().to_str().unwrap();
        let out_dir = out_dir
            .to_str()
            .expect("path must be UTF-8")
            .replace('\\', "/");
        writeln!(&out, "#[path = \"{}/{}.rs\"]", out_dir, file_stem)
            .expect("failed to write to generated.");
        writeln!(&out, "pub mod {};", file_stem).expect("failed to write to generated.");
    }
}
