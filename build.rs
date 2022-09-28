// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::env;
use std::fs;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;

fn generate_preprocessed(minijail_dir: &Path, out_dir: &Path) {
    let env_cc = cc::Build::new()
        .get_compiler()
        .path()
        .as_os_str()
        .to_owned();

    Command::new(minijail_dir.join("gen_constants.sh"))
        .env("CC", &env_cc)
        .env("SRC", &minijail_dir)
        .arg(out_dir.join("libconstants.gen.c"))
        .spawn()
        .unwrap()
        .wait()
        .expect("Generate kernel constant table failed");

    Command::new(minijail_dir.join("gen_syscalls.sh"))
        .env("CC", &env_cc)
        .env("SRC", &minijail_dir)
        .arg(out_dir.join("libsyscalls.gen.c"))
        .spawn()
        .unwrap()
        .wait()
        .expect("Generate syscall table failed");
}

fn generate_llvm_ir(minijail_dir: &Path, out_dir: &Path, target: &str) {
    Command::new("clang")
        .arg("-target")
        .arg(target)
        .arg("-S")
        .arg("-emit-llvm")
        .arg("-I")
        .arg(minijail_dir)
        .arg(out_dir.join("libconstants.gen.c"))
        .arg(out_dir.join("libsyscalls.gen.c"))
        .current_dir(&out_dir)
        .spawn()
        .unwrap()
        .wait()
        .expect("Convert kernel constants and syscalls to llvm ir failed");
}

fn generate_constants_json(minijail_dir: &Path, out_dir: &Path) {
    Command::new(minijail_dir.join("tools/generate_constants_json.py"))
        .arg("--output")
        .arg(out_dir.join("constants.json"))
        .arg(out_dir.join("libconstants.gen.ll"))
        .arg(out_dir.join("libsyscalls.gen.ll"))
        .spawn()
        .unwrap()
        .wait()
        .expect("Generate constants.json failed");
}

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
                .arg(out_dir.join("constants.json"))
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

    let target = env::var("TARGET").unwrap();

    // Disable embedding of seccomp policy files on ChromeOS builds.
    println!("cargo:rerun-if-env-changed=CROSVM_BUILD_VARIANT");
    if env::var("CROSVM_BUILD_VARIANT").unwrap_or(String::new()) == "chromeos" {
        fs::write(out_dir.join("bpf_includes.in"), "Default::default()").unwrap();
        return;
    }

    generate_preprocessed(&minijail_dir, &out_dir);
    generate_llvm_ir(&minijail_dir, &out_dir, &target);
    generate_constants_json(&minijail_dir, &out_dir);

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
