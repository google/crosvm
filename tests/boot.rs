// Copyright 2019 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::env;
use std::fs;
use std::io::{stdout, Write};
use std::mem;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Once;

use libc::{cpu_set_t, sched_getaffinity};

use crosvm::{linux, Config, Executable};
use devices::{SerialParameters, SerialType};

const CHROOT_KERNEL_PATH: &str = "/mnt/host/source/src/third_party/kernel/v4.19/";
const CONTAINER_VM_DEFCONFIG: &str = "arch/x86/configs/chromiumos-container-vm-x86_64_defconfig";
const KERNEL_REPO: &str = "https://chromium.googlesource.com/chromiumos/third_party/kernel";
const KERNEL_REPO_BRANCH: &str = "chromeos-4.19";
// TODO(zachr): this URL is a placeholder until the automated builder is running and we've settled
// on a location.
const KERNEL_PREBUILT: &str = "http://storage.googleapis.com/crosvm-testing";

/// Returns the number of CPUs that this process and its children can use by querying our process's
/// CPU affinity.
fn get_cpu_count() -> usize {
    unsafe {
        let mut set: cpu_set_t = mem::zeroed();
        let ret = sched_getaffinity(0, mem::size_of::<cpu_set_t>(), &mut set);
        if ret != 0 {
            // A good guess.
            4
        } else {
            // The cpu_set_t is normally counted using the CPU_COUNT macro, but we don't have that
            // in Rust. Because it's always a bitset, we will treat it like one here.
            let set: [u8; mem::size_of::<cpu_set_t>()] = mem::transmute(set);
            set.iter().map(|b| b.count_ones() as usize).sum()
        }
    }
}

/// Clones a chrome os kernel into the given path.
fn clone_kernel_source(dir: &Path) {
    let status = Command::new("git")
        .args(&[
            "clone",
            "--depth",
            "1",
            "--branch",
            KERNEL_REPO_BRANCH,
            KERNEL_REPO,
        ])
        .arg(dir)
        .status()
        .expect("failed to execute git");
    if !status.success() {
        panic!("failed to clone kernel source: {}", status);
    }
}

// Kernel binary algorithm.
// 1: If CROSVM_CARGO_TEST_KERNEL_BINARY is in the env:
//        If CROSVM_CARGO_TEST_KERNEL_BINARY is empty, skip step 3.
//        If CROSVM_CARGO_TEST_KERNEL_BINARY does not exist, panic.
// 2: If "bzImage" exists in the target directory use that.
// 3: Download "bzImage" from the KERNEL_PREBUILT url and use that.
//    If the download does not work, go to the kernel source algorithm.
//
// Kernel source algorithm
// 1: If CROSVM_CARGO_TEST_KERNEL_SOURCE is in the env, use that.
//    If CROSVM_CARGO_TEST_KERNEL_SOURCE does not exist, panic
// 2: If CHROOT_KERNEL_PATH exists, use that.
// 3: Checkout and use the chromeos kernel.
//
// Kernel config algorithm
// 1: If the .config already exists in the kernel source, use that.
// 2: If the CONTAINER_VM_DEFCONFIG exists in the kernel source, use that.
// 3: Use `make defconfig`.
fn prepare_kernel_once(dir: &Path) {
    let kernel_binary = dir.join("bzImage");

    let mut download_prebuilt = true;
    if let Ok(env_kernel_binary) = env::var("CROSVM_CARGO_TEST_KERNEL_BINARY") {
        if env_kernel_binary.is_empty() {
            download_prebuilt = false;
        } else {
            println!(
                "using kernel binary from enviroment `{}`",
                env_kernel_binary
            );
            let env_kernel_binary = PathBuf::from(env_kernel_binary);
            if env_kernel_binary.exists() {
                symlink(env_kernel_binary, &kernel_binary)
                    .expect("failed to create symlink for kernel binary");
                return;
            } else {
                panic!(
                    "expected kernel binary at `{}`",
                    env_kernel_binary.display()
                )
            }
        }
    }

    println!("looking for kernel binary at `{}`", kernel_binary.display());
    if kernel_binary.exists() {
        println!("using kernel binary at `{}`", kernel_binary.display());
        return;
    }

    if download_prebuilt {
        // Resolve the base URL into a specific path for this architecture.
        let kernel_prebuilt = format!(
            "{}/{}/{}",
            KERNEL_PREBUILT,
            env::consts::ARCH,
            "latest-bzImage"
        );
        println!(
            "downloading prebuilt kernel binary from `{}`",
            kernel_prebuilt
        );
        let status = Command::new("curl")
            .args(&["--fail", "--location"])
            .arg("--output")
            .arg(&kernel_binary)
            .arg(kernel_prebuilt)
            .status();
        if let Ok(status) = status {
            if status.success() {
                println!("using prebuilt kernel binary");
                return;
            }
        }

        println!("failed to download prebuilt kernel binary");
    }

    let kernel_source = if let Ok(env_kernel_source) = env::var("CROSVM_CARGO_TEST_KERNEL_SOURCE") {
        if Path::new(&env_kernel_source).is_dir() {
            PathBuf::from(env_kernel_source)
        } else {
            panic!("expected kernel source at `{}`", env_kernel_source);
        }
    } else if Path::new(CHROOT_KERNEL_PATH).is_dir() {
        PathBuf::from(CHROOT_KERNEL_PATH)
    } else {
        let kernel_source = dir.join("kernel-source");
        // Check for kernel source
        if !kernel_source.is_dir() {
            clone_kernel_source(&kernel_source);
        }
        kernel_source
    };

    println!("building kernel from source `{}`", kernel_source.display());

    // Special provisions for using the ChromeOS kernel source and its config used in crostini.
    let current_config = kernel_source.join(".config");
    let container_vm_defconfig = kernel_source.join(CONTAINER_VM_DEFCONFIG);
    if current_config.exists() {
        fs::copy(current_config, dir.join(".config"))
            .expect("failed to copy existing kernel config");
    } else if container_vm_defconfig.exists() {
        fs::copy(container_vm_defconfig, dir.join(".config"))
            .expect("failed to copy  chromiumos container vm kernel config");
    } else {
        // TODO(zachr): the defconfig for vanilla kernels is probably inadequate. There should
        // probably be a step where additional options are added to the resulting .config.
        let status = Command::new("make")
            .current_dir(&kernel_source)
            .arg(format!("O={}", dir.display()))
            .arg("defconfig")
            .status()
            .expect("failed to execute make");
        if !status.success() {
            panic!("failed to default config kernel: {}", status);
        }
    }

    let output = Command::new("make")
        .current_dir(&kernel_source)
        .arg(format!("O={}", dir.display()))
        .args(&["bzImage", "-j"])
        .arg(format!("{}", get_cpu_count()))
        .output()
        .expect("failed to execute make");
    if !output.status.success() {
        let _ = stdout().lock().write(&output.stderr);
        panic!("failed to build kernel: {}", output.status);
    }

    fs::copy(dir.join("arch/x86/boot/bzImage"), &kernel_binary)
        .expect("failed to copy kernel binary");
}

/// Gets the target directory path for artifacts.
fn get_target_path() -> PathBuf {
    env::current_exe()
        .ok()
        .map(|mut path| {
            path.pop();
            path
        })
        .expect("failed to get target dir")
}

/// Thread-safe method for preparing a kernel and returning the path to its binary.
fn prepare_kernel() -> PathBuf {
    // Lots of unit tests need the kernel, but it should only get prepared once by any arbitrary
    // test. The rest of the tests should wait until the arbitrary one finishes.
    let default_linux_dir = get_target_path();
    static PREP_ONCE: Once = Once::new();
    PREP_ONCE.call_once(|| prepare_kernel_once(&default_linux_dir));
    default_linux_dir.join("bzImage")
}

#[test]
fn boot() {
    let kernel_path = prepare_kernel();

    let mut c = Config::default();
    c.sandbox = false;
    c.serial_parameters.insert(
        1,
        SerialParameters {
            type_: SerialType::Sink,
            path: None,
            num: 1,
            console: false,
            stdin: false,
        },
    );
    c.executable_path = Some(Executable::Kernel(kernel_path));

    let r = linux::run_config(c);
    r.expect("failed to run linux");
}
