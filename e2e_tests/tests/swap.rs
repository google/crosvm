// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Testing vmm-swap

#![cfg(unix)]

use std::time::Duration;
use std::time::Instant;

use anyhow::bail;
use base::test_utils::call_test_with_sudo;
use fixture::vm::Config;
use fixture::vm::TestVm;
use swap::SwapState;
use swap::SwapStatus;

const SWAP_STATE_CHANGE_TIMEOUT: Duration = Duration::from_secs(2);
const SWAP_FILE_PATH: &str = "/tmp/swap_test";

fn get_swap_state(vm: &mut TestVm) -> SwapState {
    let output = vm.swap_command("status").unwrap();
    let status = serde_json::from_slice::<SwapStatus>(&output).unwrap();
    status.state
}

fn wait_until_swap_state_change(
    vm: &mut TestVm,
    state: SwapState,
    transition_state: &[SwapState],
    timeout: Duration,
) -> anyhow::Result<()> {
    let start = Instant::now();
    loop {
        let current_state = get_swap_state(vm);
        if current_state == state {
            return Ok(());
        }
        if start.elapsed() > timeout {
            bail!(
                "state change timeout: current: {:?}, target: {:?}",
                current_state,
                state
            );
        }
        if !transition_state.contains(&current_state) {
            bail!(
                "unexpected state while waiting: current: {:?}, target: {:?}",
                current_state,
                state
            );
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

fn create_tmpfs_file_in_guest(vm: &mut TestVm, size: usize) {
    vm.exec_in_guest("mount -t tmpfs -o size=64m /dev/shm /tmp")
        .unwrap();
    vm.exec_in_guest(&format!(
        "head -c {} /dev/urandom > {}",
        size, SWAP_FILE_PATH
    ))
    .unwrap();
}

fn load_checksum_tmpfs_file(vm: &mut TestVm) -> String {
    // Use checksum to validate that the RAM on the guest is not broken. Sending the whole content
    // does not work due to the protocol of the connection between host and guest.
    vm.exec_in_guest(&format!("cat {} | sha256sum", SWAP_FILE_PATH))
        .unwrap()
}

#[ignore = "Only to be called by swap_enabled"]
#[test]
fn swap_enabled_impl() {
    let mut config = Config::new();
    config = config.extra_args(vec!["--swap".to_string(), ".".to_string()]);
    let mut vm = TestVm::new_sudo(config).unwrap();

    assert_eq!(get_swap_state(&mut vm), SwapState::Ready);
    vm.swap_command("enable").unwrap();
    assert_eq!(get_swap_state(&mut vm), SwapState::Pending);
    vm.swap_command("trim").unwrap();
    wait_until_swap_state_change(
        &mut vm,
        SwapState::Pending,
        &[SwapState::TrimInProgress],
        SWAP_STATE_CHANGE_TIMEOUT,
    )
    .unwrap();
    vm.swap_command("out").unwrap();
    wait_until_swap_state_change(
        &mut vm,
        SwapState::Active,
        &[SwapState::SwapOutInProgress],
        SWAP_STATE_CHANGE_TIMEOUT,
    )
    .unwrap();
    vm.swap_command("disable").unwrap();
    wait_until_swap_state_change(
        &mut vm,
        SwapState::Ready,
        &[SwapState::SwapInInProgress],
        SWAP_STATE_CHANGE_TIMEOUT,
    )
    .unwrap();
}

#[test]
fn swap_enabled() {
    call_test_with_sudo("swap_enabled_impl");
}

#[ignore = "Only to be called by swap_out_multiple_times"]
#[test]
fn swap_out_multiple_times_impl() {
    let mut config = Config::new();
    config = config.extra_args(vec!["--swap".to_string(), ".".to_string()]);
    let mut vm = TestVm::new_sudo(config).unwrap();

    assert_eq!(get_swap_state(&mut vm), SwapState::Ready);
    vm.swap_command("enable").unwrap();
    assert_eq!(get_swap_state(&mut vm), SwapState::Pending);
    vm.swap_command("trim").unwrap();
    wait_until_swap_state_change(
        &mut vm,
        SwapState::Pending,
        &[SwapState::TrimInProgress],
        SWAP_STATE_CHANGE_TIMEOUT,
    )
    .unwrap();
    vm.swap_command("out").unwrap();
    wait_until_swap_state_change(
        &mut vm,
        SwapState::Active,
        &[SwapState::SwapOutInProgress],
        SWAP_STATE_CHANGE_TIMEOUT,
    )
    .unwrap();
    vm.swap_command("enable").unwrap();
    assert_eq!(get_swap_state(&mut vm), SwapState::Pending);
    vm.swap_command("trim").unwrap();
    wait_until_swap_state_change(
        &mut vm,
        SwapState::Pending,
        &[SwapState::TrimInProgress],
        SWAP_STATE_CHANGE_TIMEOUT,
    )
    .unwrap();
    vm.swap_command("out").unwrap();
    wait_until_swap_state_change(
        &mut vm,
        SwapState::Active,
        &[SwapState::SwapOutInProgress],
        SWAP_STATE_CHANGE_TIMEOUT,
    )
    .unwrap();
    vm.swap_command("enable").unwrap();
    assert_eq!(get_swap_state(&mut vm), SwapState::Pending);
    vm.swap_command("disable").unwrap();
    wait_until_swap_state_change(
        &mut vm,
        SwapState::Ready,
        &[SwapState::SwapInInProgress],
        SWAP_STATE_CHANGE_TIMEOUT,
    )
    .unwrap();
}

#[test]
fn swap_out_multiple_times() {
    call_test_with_sudo("swap_out_multiple_times_impl");
}

#[ignore = "Only to be called by swap_disabled_without_swapped_out"]
#[test]
fn swap_disabled_without_swapped_out_impl() {
    let mut config = Config::new();
    config = config.extra_args(vec!["--swap".to_string(), ".".to_string()]);
    let mut vm = TestVm::new_sudo(config).unwrap();

    assert_eq!(get_swap_state(&mut vm), SwapState::Ready);
    vm.swap_command("enable").unwrap();
    assert_eq!(get_swap_state(&mut vm), SwapState::Pending);
    vm.swap_command("disable").unwrap();
    wait_until_swap_state_change(
        &mut vm,
        SwapState::Ready,
        &[SwapState::SwapInInProgress],
        SWAP_STATE_CHANGE_TIMEOUT,
    )
    .unwrap();
}

#[test]
fn swap_disabled_without_swapped_out() {
    call_test_with_sudo("swap_disabled_without_swapped_out_impl");
}

#[ignore = "Only to be called by stopped_with_swap_enabled"]
#[test]
fn stopped_with_swap_enabled_impl() {
    let mut config = Config::new();
    config = config.extra_args(vec!["--swap".to_string(), ".".to_string()]);
    let mut vm = TestVm::new_sudo(config).unwrap();

    assert_eq!(get_swap_state(&mut vm), SwapState::Ready);
    vm.swap_command("enable").unwrap();
    assert_eq!(get_swap_state(&mut vm), SwapState::Pending);
    vm.swap_command("trim").unwrap();
    wait_until_swap_state_change(
        &mut vm,
        SwapState::Pending,
        &[SwapState::TrimInProgress],
        SWAP_STATE_CHANGE_TIMEOUT,
    )
    .unwrap();
    vm.swap_command("out").unwrap();
    wait_until_swap_state_change(
        &mut vm,
        SwapState::Active,
        &[SwapState::SwapOutInProgress],
        SWAP_STATE_CHANGE_TIMEOUT,
    )
    .unwrap();
    // dropping TestVm sends crosvm stop command and wait until the process exits.
}

#[test]
fn stopped_with_swap_enabled() {
    call_test_with_sudo("stopped_with_swap_enabled_impl");
}

#[ignore = "Only to be called by memory_contents_preserved_while_vmm_swap_enabled"]
#[test]
fn memory_contents_preserved_while_vmm_swap_enabled_impl() {
    let mut config = Config::new();
    config = config.extra_args(vec!["--swap".to_string(), ".".to_string()]);
    let mut vm = TestVm::new_sudo(config).unwrap();
    create_tmpfs_file_in_guest(&mut vm, 1024 * 1024);
    let checksum = load_checksum_tmpfs_file(&mut vm);

    assert_eq!(get_swap_state(&mut vm), SwapState::Ready);
    vm.swap_command("enable").unwrap();
    assert_eq!(get_swap_state(&mut vm), SwapState::Pending);

    assert_eq!(load_checksum_tmpfs_file(&mut vm), checksum);
}

#[test]
fn memory_contents_preserved_while_vmm_swap_enabled() {
    call_test_with_sudo("memory_contents_preserved_while_vmm_swap_enabled_impl");
}

#[ignore = "Only to be called by memory_contents_preserved_after_vmm_swap_out"]
#[test]
fn memory_contents_preserved_after_vmm_swap_out_impl() {
    let mut config = Config::new();
    config = config.extra_args(vec!["--swap".to_string(), ".".to_string()]);
    let mut vm = TestVm::new_sudo(config).unwrap();
    create_tmpfs_file_in_guest(&mut vm, 1024 * 1024);
    let checksum = load_checksum_tmpfs_file(&mut vm);

    assert_eq!(get_swap_state(&mut vm), SwapState::Ready);
    vm.swap_command("enable").unwrap();
    assert_eq!(get_swap_state(&mut vm), SwapState::Pending);
    vm.swap_command("trim").unwrap();
    wait_until_swap_state_change(
        &mut vm,
        SwapState::Pending,
        &[SwapState::TrimInProgress],
        SWAP_STATE_CHANGE_TIMEOUT,
    )
    .unwrap();
    vm.swap_command("out").unwrap();
    wait_until_swap_state_change(
        &mut vm,
        SwapState::Active,
        &[SwapState::SwapOutInProgress],
        SWAP_STATE_CHANGE_TIMEOUT,
    )
    .unwrap();

    assert_eq!(load_checksum_tmpfs_file(&mut vm), checksum);
}

#[test]
fn memory_contents_preserved_after_vmm_swap_out() {
    call_test_with_sudo("memory_contents_preserved_after_vmm_swap_out_impl");
}

#[ignore = "Only to be called by memory_contents_preserved_after_vmm_swap_disabled"]
#[test]
fn memory_contents_preserved_after_vmm_swap_disabled_impl() {
    let mut config = Config::new();
    config = config.extra_args(vec!["--swap".to_string(), ".".to_string()]);
    let mut vm = TestVm::new_sudo(config).unwrap();
    create_tmpfs_file_in_guest(&mut vm, 1024 * 1024);
    let checksum = load_checksum_tmpfs_file(&mut vm);

    assert_eq!(get_swap_state(&mut vm), SwapState::Ready);
    vm.swap_command("enable").unwrap();
    assert_eq!(get_swap_state(&mut vm), SwapState::Pending);
    vm.swap_command("trim").unwrap();
    wait_until_swap_state_change(
        &mut vm,
        SwapState::Pending,
        &[SwapState::TrimInProgress],
        SWAP_STATE_CHANGE_TIMEOUT,
    )
    .unwrap();
    vm.swap_command("out").unwrap();
    wait_until_swap_state_change(
        &mut vm,
        SwapState::Active,
        &[SwapState::SwapOutInProgress],
        SWAP_STATE_CHANGE_TIMEOUT,
    )
    .unwrap();
    vm.swap_command("disable").unwrap();
    wait_until_swap_state_change(
        &mut vm,
        SwapState::Ready,
        &[SwapState::SwapInInProgress],
        SWAP_STATE_CHANGE_TIMEOUT,
    )
    .unwrap();

    assert_eq!(load_checksum_tmpfs_file(&mut vm), checksum);
}

#[test]
fn memory_contents_preserved_after_vmm_swap_disabled() {
    call_test_with_sudo("memory_contents_preserved_after_vmm_swap_disabled_impl");
}
