// Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#![cfg(feature = "plugin")]

extern crate rand;
extern crate sys_util;

use rand::{thread_rng, Rng};

use std::ffi::OsString;
use std::fs::{File, remove_file};
use std::io::{Write, Read};
use std::env::{current_exe, var_os};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread::sleep;
use std::os::unix::io::AsRawFd;
use std::time::Duration;

use sys_util::{SharedMemory, ioctl};

struct RemovePath(PathBuf);
impl Drop for RemovePath {
    fn drop(&mut self) {
        if let Err(e) = remove_file(&self.0) {
            eprintln!("failed to remove path: {:?}", e);
        }
    }
}

fn get_target_path() -> PathBuf {
    current_exe()
        .ok()
        .map(|mut path| {
                 path.pop();
                 if path.ends_with("deps") {
                     path.pop();
                 }
                 path
             })
        .expect("failed to get crosvm binary directory")
}

fn build_plugin(src: &str) -> RemovePath {
    let mut out_bin = PathBuf::from("target");
    let libcrosvm_plugin_dir = get_target_path();
    out_bin.push(thread_rng()
                     .gen_ascii_chars()
                     .take(10)
                     .collect::<String>());
    let mut child = Command::new(var_os("CC").unwrap_or(OsString::from("cc")))
        .args(&["-Icrosvm_plugin", "-pthread", "-o"]) // crosvm.h location and set output path.
        .arg(&out_bin)
        .arg("-L") // Path of shared object to link to.
        .arg(&libcrosvm_plugin_dir)
        .arg("-lcrosvm_plugin")
        .arg("-Wl,-rpath") // Search for shared object in the same path when exec'd.
        .arg(&libcrosvm_plugin_dir)
        .args(&["-Wl,-rpath", "."]) // Also check current directory in case of sandboxing.
        .args(&["-xc", "-"]) // Read source code from piped stdin.
        .stdin(Stdio::piped())
        .spawn()
        .expect("failed to spawn compiler");
    {
        let stdin = child.stdin.as_mut().expect("failed to open stdin");
        stdin
            .write_all(src.as_bytes())
            .expect("failed to write source to stdin");
    }

    let status = child.wait().expect("failed to wait for compiler");
    assert!(status.success(), "failed to build plugin");

    RemovePath(PathBuf::from(out_bin))
}

fn run_plugin(bin_path: &Path, with_sandbox: bool) {
    let mut crosvm_path = get_target_path();
    crosvm_path.push("crosvm");
    let mut cmd = Command::new(crosvm_path);
    cmd.args(&["run",
                "-c",
                "1",
                "--seccomp-policy-dir",
                "tests",
                "--plugin"])
        .arg(bin_path
                 .canonicalize()
                 .expect("failed to canonicalize plugin path"));
    if !with_sandbox {
        cmd.arg("--disable-sandbox");
    }

    let mut child = cmd.spawn().expect("failed to spawn crosvm");
    for _ in 0..12 {
        match child.try_wait().expect("failed to wait for crosvm") {
            Some(status) => {
                assert!(status.success());
                return;
            }
            None => sleep(Duration::from_millis(100)),
        }
    }
    child.kill().expect("failed to kill crosvm");
    panic!("crosvm process has timed out");
}

fn test_plugin(src: &str) {
    let bin_path = build_plugin(src);
    // Run with and without the sandbox enabled.
    run_plugin(&bin_path.0, false);
    run_plugin(&bin_path.0, true);
}

fn keep_fd_on_exec<F: AsRawFd>(f: &F) {
    unsafe {
        ioctl(f, 0x5450 /* FIONCLEX */);
    }
}

/// Takes assembly source code and returns the resulting assembly code.
fn build_assembly(src: &str) -> Vec<u8> {
    // Creates a shared memory region with the assembly source code in it.
    let in_shm = SharedMemory::new(None).unwrap();
    let mut in_shm_file: File = in_shm.into();
    keep_fd_on_exec(&in_shm_file);
    in_shm_file.write_all(src.as_bytes()).unwrap();

    // Creates a shared memory region that will hold the nasm output.
    let mut out_shm_file: File = SharedMemory::new(None).unwrap().into();
    keep_fd_on_exec(&out_shm_file);

    // Runs nasm with the input and output files set to the FDs of the above shared memory regions,
    // which we have preserved accross exec.
    let status = Command::new("nasm")
        .arg(format!("/proc/self/fd/{}", in_shm_file.as_raw_fd()))
        .args(&["-f", "bin", "-o"])
        .arg(format!("/proc/self/fd/{}", out_shm_file.as_raw_fd()))
        .status()
        .expect("failed to spawn assembler");
    assert!(status.success());

    let mut out_bytes = Vec::new();
    out_shm_file.read_to_end(&mut out_bytes).unwrap();
    out_bytes
}

// Converts the input bytes to an output string in the format "0x01,0x02,0x03...".
fn format_as_hex(data: &[u8]) -> String {
    let mut out = String::new();
    for (i, d) in data.iter().enumerate() {
        out.push_str(&format!("0x{:02x}", d));
        if i < data.len() - 1 {
            out.push(',')
        }
    }
    out
}

// A testing framework for creating simple plugins.
struct MiniPlugin {
    // The size in bytes of the guest memory based at 0x0000.
    mem_size: u64,
    // The address in guest memory to load the assembly code.
    load_address: u32,
    // The nasm syntax 16-bit assembly code that will assembled and loaded into guest memory.
    assembly_src: &'static str,
    // The C source code that will be included in the mini_plugin_template.c file. This code must
    // define the forward declarations above the {src} line so that the completed plugin source will
    // compile.
    src: &'static str,
}

impl Default for MiniPlugin {
    fn default() -> Self {
        MiniPlugin {
            mem_size: 0x2000,
            load_address: 0x1000,
            assembly_src: "hlt",
            src: "",
        }
    }
}

// Builds and tests the given MiniPlugin definiton.
fn test_mini_plugin(plugin: &MiniPlugin) {
    // Adds a preamble to ensure the output opcodes are 16-bit real mode and the lables start at the
    // load address.
    let assembly_src = format!("org 0x{:x}\nbits 16\n{}",
                               plugin.load_address,
                               plugin.assembly_src);

    // Builds the assembly and convert it to a C literal array format.
    let assembly = build_assembly(&assembly_src);
    let assembly_hex = format_as_hex(&assembly);

    // Glues the pieces of this plugin together and tests the completed plugin.
    let generated_src = format!(include_str!("mini_plugin_template.c"),
                                mem_size = plugin.mem_size,
                                load_address = plugin.load_address,
                                assembly_code = assembly_hex,
                                src = plugin.src);
    test_plugin(&generated_src);
}

#[test]
fn test_adder() {
    test_plugin(include_str!("plugin_adder.c"));
}

#[test]
fn test_dirty_log() {
    test_plugin(include_str!("plugin_dirty_log.c"));
}

#[test]
fn test_ioevent() {
    test_plugin(include_str!("plugin_ioevent.c"));
}

#[test]
fn test_irqfd() {
    test_plugin(include_str!("plugin_irqfd.c"));
}

#[test]
fn test_debugregs() {
    let mini_plugin = MiniPlugin {
        assembly_src: "org 0x1000
             bits 16
             mov dr0, ebx
             mov eax, dr1
             mov byte [0x3000], 1",
        src: r#"
            #define DR1_VALUE 0x12
            #define RBX_VALUE 0xabcdef00
            #define KILL_ADDRESS 0x3000

            int g_kill_evt;
            struct kvm_regs g_regs;
            struct kvm_debugregs g_dregs;

            int setup_vm(struct crosvm *crosvm, void *mem) {
                g_kill_evt = crosvm_get_shutdown_eventfd(crosvm);
                crosvm_reserve_range(crosvm, CROSVM_ADDRESS_SPACE_MMIO, KILL_ADDRESS, 1);
                return 0;
            }

            int handle_vpcu_init(struct crosvm_vcpu *vcpu, struct kvm_regs *regs,
                                 struct kvm_sregs *sregs)
            {
                regs->rbx = RBX_VALUE;
                struct kvm_debugregs dregs;
                crosvm_vcpu_get_debugregs(vcpu, &dregs);
                dregs.db[1] = DR1_VALUE;
                crosvm_vcpu_set_debugregs(vcpu, &dregs);
                return 0;
            }

            int handle_vpcu_evt(struct crosvm_vcpu *vcpu, struct crosvm_vcpu_event evt) {
                if (evt.kind == CROSVM_VCPU_EVENT_KIND_IO_ACCESS &&
                        evt.io_access.address_space == CROSVM_ADDRESS_SPACE_MMIO &&
                        evt.io_access.address == KILL_ADDRESS &&
                        evt.io_access.is_write &&
                        evt.io_access.length == 1 &&
                        evt.io_access.data[0] == 1)
                {
                    uint64_t dummy = 1;
                    crosvm_vcpu_get_debugregs(vcpu, &g_dregs);
                    crosvm_vcpu_get_regs(vcpu, &g_regs);
                    write(g_kill_evt, &dummy, sizeof(dummy));
                    return 1;
                }
                return 0;
            }

            int check_result(struct crosvm *vcpu, void *mem) {
                if (g_dregs.db[1] != DR1_VALUE) {
                    fprintf(stderr, "dr1 register has unexpected value: 0x%x\n", g_dregs.db[1]);
                    return 1;
                }
                if (g_dregs.db[0] != RBX_VALUE) {
                    fprintf(stderr, "dr0 register has unexpected value: 0x%x\n", g_dregs.db[0]);
                    return 1;
                }
                if (g_regs.rax != DR1_VALUE) {
                    fprintf(stderr, "eax register has unexpected value: 0x%x\n", g_regs.rax);
                    return 1;
                }
                return 0;
            }"#,
        ..Default::default()
    };
    test_mini_plugin(&mini_plugin);
}
