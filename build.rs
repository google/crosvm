// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::env;
use std::fs;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;

fn rewrite_policies(seccomp_policy_path: &Path, rewrote_policy_folder: &Path) {
    for entry in fs::read_dir(seccomp_policy_path).unwrap() {
        let policy_file = entry.unwrap();
        let policy_file_content = fs::read_to_string(policy_file.path()).unwrap();
        let policy_file_content_rewrote =
            policy_file_content.replace("/usr/share/policy/crosvm", ".");
        fs::write(
            rewrote_policy_folder.join(policy_file.file_name()),
            policy_file_content_rewrote,
        )
        .unwrap();
    }
}

fn compile_policies(out_dir: &Path, rewrote_policy_folder: &Path, minijail_dir: &Path) {
    let compiled_policy_folder = out_dir.join("policy_output");
    fs::create_dir_all(&compiled_policy_folder).unwrap();
    let mut include_all_bytes = String::from("std::collections::HashMap::from([\n");
    for entry in fs::read_dir(&rewrote_policy_folder).unwrap() {
        let policy_file = entry.unwrap();
        if policy_file.path().extension().unwrap() == "policy" {
            let output_file_path = compiled_policy_folder.join(
                policy_file
                    .path()
                    .with_extension("bpf")
                    .file_name()
                    .unwrap(),
            );
            Command::new(minijail_dir.join("tools/compile_seccomp_policy.py"))
                .arg("--arch-json")
                .arg(rewrote_policy_folder.join("constants.json"))
                .arg("--default-action")
                .arg("trap")
                .arg(policy_file.path())
                .arg(&output_file_path)
                .spawn()
                .unwrap()
                .wait()
                .expect("Compile bpf failed");
            let s = format!(
                r#"("{}", include_bytes!("{}").to_vec()),"#,
                policy_file.path().file_stem().unwrap().to_str().unwrap(),
                output_file_path.to_str().unwrap()
            );
            include_all_bytes += s.as_str();
        }
    }
    include_all_bytes += "])";
    fs::write(out_dir.join("bpf_includes.in"), include_all_bytes).unwrap();
}

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=seccomp");

    if env::var("CARGO_CFG_TARGET_FAMILY").unwrap() != "unix" {
        return;
    }

    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let src_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let minijail_dir = if let Ok(minijail_dir_env) = env::var("MINIJAIL_DIR") {
        PathBuf::from(minijail_dir_env)
    } else {
        src_dir.join("third_party/minijail")
    };

    // Disable embedding of seccomp policy files on ChromeOS builds.
    println!("cargo:rerun-if-env-changed=CROSVM_BUILD_VARIANT");
    if env::var("CROSVM_BUILD_VARIANT").unwrap_or_default() == "chromeos" {
        fs::write(out_dir.join("bpf_includes.in"), "Default::default()").unwrap();
        return;
    }

    // check policies exist for target architecuture
    let seccomp_arch_name = match env::var("CARGO_CFG_TARGET_ARCH").unwrap().as_str() {
        "armv7" => "arm".to_owned(),
        x => x.to_owned(),
    };
    let seccomp_policy_path = src_dir.join("seccomp").join(&seccomp_arch_name);
    assert!(
        seccomp_policy_path.is_dir(),
        "Seccomp policy dir doesn't exist"
    );

    let rewrote_policy_folder = out_dir.join("policy_input");
    fs::create_dir_all(&rewrote_policy_folder).unwrap();
    rewrite_policies(&seccomp_policy_path, &rewrote_policy_folder);
    compile_policies(&out_dir, &rewrote_policy_folder, &minijail_dir);
}
