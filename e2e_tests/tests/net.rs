// Copyright 2025 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Testing virtio-net.
#![cfg(any(target_os = "android", target_os = "linux"))]

use std::fs::File;
use std::path::Path;
use std::process::Command;
use std::process::Stdio;
use std::time::Duration;

use anyhow::anyhow;
use fixture::utils::retry_with_delay;
use fixture::vhost_user::CmdType;
use fixture::vhost_user::Config as VuConfig;
use fixture::vhost_user::VhostUserBackend;
use fixture::vm::Config as VmConfig;
use fixture::vm::TestVm;
use tempfile::NamedTempFile;
const VIRTIO_NET_F_MRG_RXBUF: usize = 15;
const NCAT_RETRIES: usize = 15;
const NCAT_RETRY_DELAY: Duration = Duration::from_millis(300);

pub fn create_vu_net_config(socket: &Path, host_net_name: String, mrg_rxbuf: bool) -> VuConfig {
    let socket_path = socket.to_str().unwrap();
    let mut args = vec![
        "net".to_string(),
        "--tap-name".to_string(),
        format!("{socket_path},{host_net_name}").to_string(),
    ];
    if mrg_rxbuf {
        args.push("--mrg-rxbuf".to_string());
    }
    VuConfig::new(CmdType::Device, "net").extra_args(args)
}

fn create_guest_with_virtio_net_backend(
    config: VmConfig,
    host_ip_with_mask: String,
    host_net_name: String,
    mrg_rxbuf: bool,
    vhost_user_mode: bool,
) -> anyhow::Result<(Option<VhostUserBackend>, TestVm)> {
    // Del crosvm_tap if exist
    Command::new("sudo")
        .args(["ip", "tuntap", "del", "mode", "tap", &host_net_name])
        .output()
        .unwrap_or_else(|_| panic!("Fail to del {host_net_name}"));
    // Enable crosvm_tap in backend and up
    Command::new("sudo")
        .args([
            "ip",
            "tuntap",
            "add",
            "mode",
            "tap",
            "user",
            "crosvm",
            &host_net_name,
        ])
        .output()
        .unwrap_or_else(|_| panic!("Fail to create {host_net_name}"));
    Command::new("sudo")
        .args([
            "ip",
            "addr",
            "add",
            &host_ip_with_mask,
            "dev",
            &host_net_name,
        ])
        .output()
        .unwrap_or_else(|_| panic!("Fail to set {host_net_name} address"));
    Command::new("sudo")
        .args(["ip", "link", "set", &host_net_name, "up"])
        .output()
        .unwrap_or_else(|_| panic!("Fail to up {host_net_name}"));

    let (vu, cfg) = if vhost_user_mode {
        // Start a vhost-user-net backend firstly
        let socket = NamedTempFile::new().unwrap();
        let vu_config = create_vu_net_config(socket.path(), host_net_name, mrg_rxbuf);
        let vu_device = VhostUserBackend::new_sudo(vu_config).unwrap();
        (
            Some(vu_device),
            config
                .extra_args(vec!["--mem".to_owned(), "512".to_owned()])
                .with_vhost_user("net", socket.path()),
        )
    } else {
        let mut extra_args = vec!["--mem".to_owned(), "512".to_owned(), "--net".to_owned()];
        if mrg_rxbuf {
            extra_args.push(format!("tap-name={host_net_name},mrg-rxbuf"))
        } else {
            extra_args.push(format!("tap-name={host_net_name}"))
        }
        (None, config.extra_args(extra_args))
    };

    let guest_vm = TestVm::new_sudo(cfg).expect("fail to create guest vm");
    if vhost_user_mode {
        Ok((vu, guest_vm))
    } else {
        Ok((None, guest_vm))
    }
}

/// Configure guest virtio-net device, return virtio name
fn network_configure_in_guest(
    vm: &mut TestVm,
    host_ip: String,
    guest_ip: String,
) -> anyhow::Result<String> {
    // mount sysfs to check details
    vm.exec_in_guest("mount -t sysfs sysfs /sys")
        .expect("fail to mount sysfs in vm");

    // Parse virtio device list and find out virtio-net id
    let result = vm
        .exec_in_guest("cat /sys/bus/virtio/devices/*/device")
        .expect("Can't get virtio devices id");

    let virtio_id_list: Vec<&str> = result.stdout.split("\n").collect();
    let virtio_net_id = virtio_id_list.iter().position(|&x| x == "0x0001");
    // The name of virtio-net driver is virtioX
    let virtio_name = if let Some(id) = virtio_net_id {
        format!("virtio{id}")
    } else {
        return Err(anyhow!("fail to find virtio net driver"));
    };

    // Find the ethernet interface name in guest
    let guest_dev = vm
        .exec_in_guest(&format!("ls /sys/bus/virtio/devices/{virtio_name}/net"))
        .expect("Can not find the name of virtio-net")
        .stdout
        .trim_end()
        .to_string();

    // set ip address in guest
    vm.exec_in_guest(&format!("ip addr add {guest_ip}/24 dev {guest_dev}"))
        .expect("fail to configure net device address");
    // up network device
    vm.exec_in_guest(&format!("ip link set {guest_dev} up"))
        .expect("fail to up net device");
    // route information add
    vm.exec_in_guest(&format!("ip route add default via {host_ip}"))
        .expect("fail to configure net device address");

    vm.exec_in_guest("ip route show")
        .expect("fail to configure net device address");
    Ok(virtio_name)
}

/// Check whether MRG_RXBUF feature bit is configured in guest driver
/// vm: guest test VM
/// virtio_name: the virtio driver name in guest (e.g. virtio0)
fn check_driver_negotiated_features_with_mrg_rxbuf(
    vm: &mut TestVm,
    virtio_name: String,
) -> anyhow::Result<bool> {
    let binding = vm
        .exec_in_guest(&format!(
            "cat /sys/bus/virtio/devices/{virtio_name}/features"
        ))
        .expect("Can not get the features of virtio-net");
    // Find the ethernet interface name in guest
    let features = binding.stdout.trim_end();

    Ok(features.chars().nth(VIRTIO_NET_F_MRG_RXBUF).unwrap() == '1')
}

fn test_net_connection(
    config: VmConfig,
    host_ip: String,
    host_net_name: String,
    guest_ip: String,
    mrg_rxbuf: bool,
    vhost_user_mode: bool,
) -> anyhow::Result<()> {
    let host_ip_with_mask = format!("{host_ip}/24");
    let (_vu_device, mut vm) = create_guest_with_virtio_net_backend(
        config,
        host_ip_with_mask,
        host_net_name.clone(),
        mrg_rxbuf,
        vhost_user_mode,
    )
    .expect("fail to create device and start vm");
    let virtio_name = network_configure_in_guest(&mut vm, host_ip.clone(), guest_ip.clone())?;

    assert_eq!(
        mrg_rxbuf,
        check_driver_negotiated_features_with_mrg_rxbuf(&mut vm, virtio_name)?
    );
    let packets_num = "5";
    let host_ping_guest_result = Command::new("ping")
        .args([&guest_ip, "-c", packets_num])
        .output()
        .expect("fail to ping guest")
        .stdout;

    assert!(String::from_utf8(host_ping_guest_result)
        .unwrap()
        .contains(&format!(
            "{packets_num} packets transmitted, {packets_num} received"
        )));
    let guest_ping_host_result = vm
        .exec_in_guest(&format!("ping {} -c {}", host_ip.clone(), packets_num))
        .expect("fail to ping host")
        .stdout;
    assert!(guest_ping_host_result.contains(&format!(
        "{packets_num} packets transmitted, {packets_num} received"
    )));
    Command::new("sudo")
        .args(["ip", "link", "set", &host_net_name.clone(), "down"])
        .output()
        .expect("fail to set device down");
    Ok(())
}

#[test]
fn virtio_net_ping_test() -> anyhow::Result<()> {
    let vm_config = VmConfig::new();
    test_net_connection(
        vm_config,
        "192.168.10.1".to_owned(),
        "crosvm_tap0".to_owned(),
        "192.168.10.2".to_owned(),
        false,
        false,
    )?;
    Ok(())
}

#[test]
fn virtio_net_ping_test_with_mrg_rxbuf() -> anyhow::Result<()> {
    let vm_config = VmConfig::new();
    test_net_connection(
        vm_config,
        "192.168.11.1".to_owned(),
        "crosvm_tap1".to_owned(),
        "192.168.11.2".to_owned(),
        true,
        false,
    )?;
    Ok(())
}

#[test]
fn vhost_user_net_ping_test() -> anyhow::Result<()> {
    let vm_config = VmConfig::new();
    test_net_connection(
        vm_config,
        "192.168.12.1".to_owned(),
        "crosvm_tap2".to_owned(),
        "192.168.12.2".to_owned(),
        false,
        true,
    )?;
    Ok(())
}

#[test]
fn vhost_user_net_ping_test_with_mrg_rxbuf() -> anyhow::Result<()> {
    let vm_config = VmConfig::new();
    test_net_connection(
        vm_config,
        "192.168.13.1".to_owned(),
        "crosvm_tap3".to_owned(),
        "192.168.13.2".to_owned(),
        true,
        true,
    )?;
    Ok(())
}

fn guest_to_host_ncat_test(vm: &mut TestVm, host_ip: String, port: String) -> anyhow::Result<()> {
    let listen_port = port;
    let listen_args = vec!["-l", &listen_port];
    //Create a recv file in host, then ncat listen a port and re-direct to this file
    let recv_file = File::create("/tmp/host_recv.txt")?;
    Command::new("ncat")
        .args(listen_args)
        .stdout(Stdio::from(recv_file))
        .spawn()
        .expect("fail to spawn");

    // create a random file in guest and get the md5sum value of this file
    vm.exec_in_guest("mount -t tmpfs tmpfs /tmp")
        .expect("fail to mount tmpfs in vm");

    vm.exec_in_guest("dd if=/dev/random of=/tmp/guest_send.txt bs=1M count=10")
        .expect("fail to generate a random file");

    let md5_guest = vm
        .exec_in_guest("md5sum /tmp/guest_send.txt | awk '{ print $1 }'")
        .expect("fail to check md5sum")
        .stdout;

    // Transfer this file to host via virtio-net and calculate its md5sum value
    vm.exec_in_guest(&format!(
        "ncat {host_ip} {listen_port} < /tmp/guest_send.txt"
    ))
    .expect("fail to send file");

    let res = Command::new("md5sum")
        .stdout(Stdio::piped())
        .args(["/tmp/host_recv.txt"])
        .output()?
        .stdout;
    let md5_host = String::from_utf8(res)?
        .split_whitespace()
        .next()
        .unwrap()
        .to_string();

    assert_eq!(md5_guest.trim_end(), md5_host);
    Ok(())
}

fn host_to_guest_ncat_test(vm: &mut TestVm, guest_ip: String, port: String) -> anyhow::Result<()> {
    vm.exec_in_guest("mount -t tmpfs tmpfs /tmp")
        .expect("fail to mount tmpfs in vm");

    //Create a send file in host
    Command::new("dd")
        .args([
            "if=/dev/random",
            "of=/tmp/host_send.txt",
            "bs=1M",
            "count=10",
        ])
        .output()
        .expect("fail to generate send file");
    let res = Command::new("md5sum")
        .stdout(Stdio::piped())
        .args(["/tmp/host_send.txt"])
        .output()?
        .stdout;
    let md5_host = String::from_utf8(res)?
        .split_whitespace()
        .next()
        .unwrap()
        .to_string();
    let guest_listen_cmd = format!("ncat -l {} > /tmp/guest_recv.txt", port.clone());
    let guest_cmd = vm.exec_in_guest_async(&guest_listen_cmd).unwrap();

    retry_with_delay(
        move || {
            let send_file = File::open("/tmp/host_send.txt")?;
            let out = Command::new("ncat")
                .args([&guest_ip, &port])
                .stdin(Stdio::from(send_file))
                .output();
            // if connection refused, it will still return Ok, then retry will exit.
            if out.as_ref().is_ok_and(|x| {
                String::from_utf8(x.stderr.clone()).unwrap() != "Ncat: Connection refused.\n"
            }) {
                out
            } else {
                Err(std::io::Error::other("Ncat: Connection refused"))
            }
        },
        NCAT_RETRIES,
        NCAT_RETRY_DELAY,
    )
    .unwrap();

    guest_cmd.wait_ok(vm).unwrap();
    let md5_guest = vm
        .exec_in_guest("md5sum /tmp/guest_recv.txt | awk '{ print $1 }'")
        .expect("fail to check md5sum")
        .stdout;
    assert_eq!(md5_guest.trim_end(), md5_host);
    Ok(())
}

fn test_ncat_guest_to_host(
    config: VmConfig,
    host_ip: String,
    host_net_name: String,
    guest_ip: String,
    mrg_rxbuf: bool,
    vhost_user_mode: bool,
) -> anyhow::Result<()> {
    let host_ip_with_mask = format!("{host_ip}/24");
    let (_vu_device, mut vm) = create_guest_with_virtio_net_backend(
        config,
        host_ip_with_mask,
        host_net_name.clone(),
        mrg_rxbuf,
        vhost_user_mode,
    )
    .expect("fail to create device and start vm");
    let virtio_name = network_configure_in_guest(&mut vm, host_ip.clone(), guest_ip.clone())?;

    assert_eq!(
        mrg_rxbuf,
        check_driver_negotiated_features_with_mrg_rxbuf(&mut vm, virtio_name)?
    );
    guest_to_host_ncat_test(&mut vm, host_ip.clone(), "1111".to_owned())?;
    Ok(())
}

fn test_ncat_host_to_guest(
    config: VmConfig,
    host_ip: String,
    host_net_name: String,
    guest_ip: String,
    mrg_rxbuf: bool,
    vhost_user_mode: bool,
) -> anyhow::Result<()> {
    let host_ip_with_mask = format!("{host_ip}/24");
    let (_vu_device, mut vm) = create_guest_with_virtio_net_backend(
        config,
        host_ip_with_mask,
        host_net_name.clone(),
        mrg_rxbuf,
        vhost_user_mode,
    )
    .expect("fail to create device and start vm");
    let virtio_name = network_configure_in_guest(&mut vm, host_ip.clone(), guest_ip.clone())?;

    assert_eq!(
        mrg_rxbuf,
        check_driver_negotiated_features_with_mrg_rxbuf(&mut vm, virtio_name)?
    );
    host_to_guest_ncat_test(&mut vm, guest_ip.clone(), "1234".to_owned())?;

    Ok(())
}

#[test]
fn vhost_user_net_ncat_test_with_mrg_rxbuf_guest2host() -> anyhow::Result<()> {
    let vm_config = VmConfig::new();
    test_ncat_guest_to_host(
        vm_config,
        "192.168.14.1".to_owned(),
        "crosvm_tap4".to_owned(),
        "192.168.14.2".to_owned(),
        true,
        true,
    )?;
    Ok(())
}

#[test]
fn vhost_user_net_ncat_test_with_mrg_rxbuf_host2guest() -> anyhow::Result<()> {
    let vm_config = VmConfig::new();
    test_ncat_host_to_guest(
        vm_config,
        "192.168.15.1".to_owned(),
        "crosvm_tap5".to_owned(),
        "192.168.15.2".to_owned(),
        true,
        true,
    )?;
    Ok(())
}
