// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Testing virtio-console multiport feature.

#![cfg(any(target_os = "android", target_os = "linux"))]

use std::ffi::CString;
use std::fs::OpenOptions;
use std::io::Read;
use std::io::Write;
use std::path::PathBuf;

use base::error;
use base::EventToken;
use base::WaitContext;
use base::WorkerThread;
use fixture::utils::create_vu_console_multiport_config;
use fixture::vhost_user::VhostUserBackend;
use fixture::vm::Config as VmConfig;
use fixture::vm::TestVm;
use tempfile::NamedTempFile;
use tempfile::TempDir;

fn run_vhost_user_console_multiport_test_portname(config: VmConfig) -> anyhow::Result<()> {
    let socket = NamedTempFile::new().unwrap();
    let temp_dir = TempDir::new()?;

    // Prepare 2 virtio-console with only output
    let file_path = vec![
        (temp_dir.path().join("vconsole0.out"), PathBuf::new()),
        (temp_dir.path().join("vconsole1.out"), PathBuf::new()),
    ];
    let vu_config = create_vu_console_multiport_config(socket.path(), file_path.clone());
    let _vu_device = VhostUserBackend::new(vu_config).unwrap();

    let config = config.extra_args(vec![
        "--mem".to_owned(),
        "512".to_owned(),
        "--vhost-user-console".to_string(),
        socket.path().to_str().unwrap().to_string(),
    ]);
    let mut vm = TestVm::new(config).unwrap();

    // mount sysfs to check details
    vm.exec_in_guest("mount -t sysfs sysfs /sys")?;

    // Get portlist
    let result = vm
        .exec_in_guest("ls /sys/class/virtio-ports/")
        .expect("No virtio-ports dir");
    let mut portlist: Vec<&str> = result.stdout.trim_end().split('\n').collect();
    // Remove serial virtio-console created defaultly
    portlist.remove(0);
    for (i, port) in portlist.into_iter().enumerate() {
        let portname = vm
            .exec_in_guest(format!("cat /sys/class/virtio-ports/{}/name", port).as_str())
            .expect("Failed to read portname")
            .stdout;
        assert_eq!(portname.trim_end(), format!("port{}", i).as_str());
    }
    Ok(())
}

/// Tests vhost-user console device with `crosvm device`.
#[test]
fn vhost_user_console_portname_check() -> anyhow::Result<()> {
    let config = VmConfig::new();
    run_vhost_user_console_multiport_test_portname(config)?;
    Ok(())
}

fn run_vhost_user_console_multiport_test_output(config: VmConfig) -> anyhow::Result<()> {
    let socket = NamedTempFile::new().unwrap();
    let temp_dir = TempDir::new()?;

    // Prepare 2 virtio-console with only output
    let file_path = vec![
        (temp_dir.path().join("vconsole0.out"), PathBuf::new()),
        (temp_dir.path().join("vconsole1.out"), PathBuf::new()),
    ];
    let vu_config = create_vu_console_multiport_config(socket.path(), file_path.clone());
    let _vu_device = VhostUserBackend::new(vu_config).unwrap();

    let config = config.extra_args(vec![
        "--mem".to_owned(),
        "512".to_owned(),
        "--vhost-user-console".to_string(),
        socket.path().to_str().unwrap().to_string(),
    ]);
    let mut vm = TestVm::new(config).unwrap();

    // mount sysfs to check details
    vm.exec_in_guest("mount -t sysfs sysfs /sys")?;

    // Get portlist
    let result = vm
        .exec_in_guest("ls /sys/class/virtio-ports/")
        .expect("No virtio-ports dir");
    let mut portlist: Vec<&str> = result.stdout.trim_end().split('\n').collect();
    // Remove serial virtio-console created defaultly
    portlist.remove(0);

    // Test output flow.
    for (i, port) in portlist.into_iter().enumerate() {
        vm.exec_in_guest(format!("echo \"hello {}\" > /dev/{}", port, port).as_str())
            .expect("Failed to echo data to port");

        let mut output_file = OpenOptions::new()
            .read(true)
            .write(true)
            .append(true)
            .open(&file_path[i].0)
            .expect("vu-console: open output failed");

        let mut data = String::new();
        output_file
            .read_to_string(&mut data)
            .expect("vu-console: read data failed");

        assert_eq!(data.trim(), format!("hello {}", port).as_str());
    }
    Ok(())
}

#[test]
fn vhost_user_console_check_output() -> anyhow::Result<()> {
    let config = VmConfig::new();
    run_vhost_user_console_multiport_test_output(config)?;
    Ok(())
}

/// Generate the workthread to monitor input and transmit data to output fifo
///
/// Create fifo according to input and output name.
/// Then spawn a thread to monitor them, simultaneously watch a kill_event to stop thread.
fn generate_workthread_to_monitor_fifo(
    idx: usize,
    infile: PathBuf,
    outfile: PathBuf,
) -> WorkerThread<()> {
    #[derive(EventToken)]
    enum Token {
        InputDataAvailable,
        Kill,
    }
    let cpath_in = CString::new(infile.to_str().unwrap()).unwrap();
    let cpath_out = CString::new(outfile.to_str().unwrap()).unwrap();
    // SAFETY: make two fifos here for monitor thread, path is guaranteed to be valid
    unsafe {
        libc::mkfifo(cpath_in.as_ptr(), 0o777);
        libc::mkfifo(cpath_out.as_ptr(), 0o777);
    }
    WorkerThread::start(format!("monitor_vconsole{}", idx), move |kill_event| {
        let mut tx = OpenOptions::new().write(true).open(outfile).unwrap();
        let mut rx = OpenOptions::new().read(true).open(infile).unwrap();
        let mut msg = vec![0; 256];
        let wait_ctx: WaitContext<Token> = match WaitContext::build_with(&[
            (&rx, Token::InputDataAvailable),
            (&kill_event, Token::Kill),
        ]) {
            Ok(wait_ctx) => wait_ctx,
            Err(e) => {
                error!("failed creating WaitContext: {}", e);
                return;
            }
        };
        'monitor_loop: loop {
            let wait_events = match wait_ctx.wait() {
                Ok(wait_events) => wait_events,
                Err(e) => {
                    error!("failed polling for events: {}", e);
                    break;
                }
            };
            for wait_event in wait_events.iter().filter(|e| e.is_readable) {
                match wait_event.token {
                    Token::InputDataAvailable => {
                        let bytes = rx.read(&mut msg).expect("Failed to read from port");
                        if bytes > 0 {
                            if tx.write_all(&msg.to_ascii_uppercase()[..bytes]).is_err() {
                                break 'monitor_loop;
                            }
                        }
                    }
                    Token::Kill => break 'monitor_loop,
                }
            }
        }
    })
}

/// Tests vhost-user-console input function with multiport feature.
///
/// If we want to test multiport function about input flow,
/// we need to prepare monitor threads for each ports.
/// The purpose of this thread is to get all data from rx queue, and transmit them to tx queue.
/// To increase reliability, monitor thread changes data to uppercase.
///
/// Once monitor threads created, VhostUserBackend for console will work as expected.
fn run_vhost_user_console_multiport_test_input(config: VmConfig) -> anyhow::Result<()> {
    let socket = NamedTempFile::new().unwrap();
    let temp_dir = TempDir::new()?;

    // Prepare 2 virtio-console with both input and output
    let mut file_path = vec![];
    for idx in 0..2 {
        let fifo_name_out = format!("vconsole{}.out", idx);
        let fifo_name_in = format!("vconsole{}.in", idx);
        file_path.push((
            temp_dir.path().join(fifo_name_out),
            temp_dir.path().join(fifo_name_in),
        ));
    }

    let mut thread_vec = vec![];
    for idx in 0..2 {
        thread_vec.push(generate_workthread_to_monitor_fifo(
            idx,
            (*file_path.get(idx).unwrap().0).to_path_buf(),
            (*file_path.get(idx).unwrap().1).to_path_buf(),
        ));
    }

    let vu_config = create_vu_console_multiport_config(socket.path(), file_path.clone());
    let _vu_device = VhostUserBackend::new(vu_config).unwrap();

    let config = config.extra_args(vec![
        "--mem".to_owned(),
        "512".to_owned(),
        "--vhost-user-console".to_string(),
        socket.path().to_str().unwrap().to_string(),
    ]);
    let mut vm = TestVm::new(config).unwrap();

    // mount sysfs to check details
    vm.exec_in_guest("mount -t sysfs sysfs /sys")?;

    // Get portlist
    let result = vm
        .exec_in_guest("ls /sys/class/virtio-ports/")
        .expect("No virtio-ports dir");
    let mut portlist: Vec<&str> = result.stdout.trim_end().split('\n').collect();
    // Remove serial virtio-console created defaultly
    portlist.remove(0);

    let file_fd = 5;
    // Test input flow.
    for port in portlist.into_iter() {
        // Bind file_fd to operate /dev/vportXpX, then write to fd, finnally read it.
        let result = vm
            .exec_in_guest(
                format!(
                    "exec {}<>/dev/{} && echo \"hello {}\" >&{} && head -1 <&{}",
                    file_fd, port, port, file_fd, file_fd
                )
                .as_str(),
            )
            .expect("Failed to echo data to port")
            .stdout;
        // Close this fd
        vm.exec_in_guest(format!("exec {}>&-", file_fd).as_str())
            .expect("Failed to close device fd");
        // In monitor thread, tx message will change to uppercase
        assert_eq!(
            result.trim_end(),
            format!("hello {}", port).to_uppercase().as_str()
        );
    }
    for handler in thread_vec.into_iter() {
        handler.stop();
    }
    Ok(())
}

#[test]
fn vhost_user_console_check_input() -> anyhow::Result<()> {
    let config = VmConfig::new();
    run_vhost_user_console_multiport_test_input(config)?;
    Ok(())
}
