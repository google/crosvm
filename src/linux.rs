// Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std;
use std::cmp::min;
use std::error;
use std::ffi::CStr;
use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{self, stdin, Read};
use std::mem;
use std::os::unix::io::{FromRawFd, RawFd};
use std::os::unix::net::{UnixDatagram, UnixStream};
use std::path::{Path, PathBuf};
use std::str;
use std::sync::{Arc, Barrier};
use std::thread;
use std::thread::JoinHandle;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use libc::{self, c_int};

use audio_streams::DummyStreamSource;
use byteorder::{ByteOrder, LittleEndian};
use devices::{self, PciDevice, VirtioPciDevice};
use io_jail::{self, Minijail};
use kvm::*;
use libcras::CrasClient;
use msg_socket::{MsgReceiver, MsgSender, MsgSocket, UnlinkMsgSocket};
use net_util::{Error as NetError, Tap};
use qcow::{self, ImageType, QcowFile};
use rand_ish::SimpleRng;
use sync::{Condvar, Mutex};
use sys_util;
use sys_util::*;
use vhost;
use vm_control::{VmRequest, VmResponse, VmRunMode};

use Config;

use arch::{self, LinuxArch, RunnableLinuxVm, VirtioDeviceStub, VmComponents};

#[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
use aarch64::AArch64 as Arch;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
use x86_64::X8664arch as Arch;

#[derive(Debug)]
pub enum Error {
    BalloonDeviceNew(devices::virtio::BalloonError),
    BlockDeviceNew(sys_util::Error),
    BlockSignal(sys_util::signal::Error),
    BuildingVm(Box<error::Error>),
    CloneEventFd(sys_util::Error),
    CreateEventFd(sys_util::Error),
    CreatePollContext(sys_util::Error),
    CreateSignalFd(sys_util::SignalFdError),
    CreateSocket(io::Error),
    CreateTapDevice(NetError),
    CreateTimerFd(sys_util::Error),
    DetectImageType(qcow::Error),
    DeviceJail(io_jail::Error),
    DevicePivotRoot(io_jail::Error),
    Disk(io::Error),
    DiskImageLock(sys_util::Error),
    InvalidFdPath,
    InvalidWaylandPath,
    NetDeviceNew(devices::virtio::NetError),
    NoVarEmpty,
    OpenAndroidFstab(PathBuf, io::Error),
    OpenKernel(PathBuf, io::Error),
    P9DeviceNew(devices::virtio::P9Error),
    PollContextAdd(sys_util::Error),
    PollContextDelete(sys_util::Error),
    QcowDeviceCreate(qcow::Error),
    ReadLowmemAvailable(io::Error),
    ReadLowmemMargin(io::Error),
    RegisterBalloon(arch::DeviceRegistrationError),
    RegisterBlock(arch::DeviceRegistrationError),
    RegisterGpu(arch::DeviceRegistrationError),
    RegisterNet(arch::DeviceRegistrationError),
    RegisterP9(arch::DeviceRegistrationError),
    RegisterRng(arch::DeviceRegistrationError),
    RegisterSignalHandler(sys_util::Error),
    RegisterWayland(arch::DeviceRegistrationError),
    ResetTimerFd(sys_util::Error),
    RngDeviceNew(devices::virtio::RngError),
    InputDeviceNew(devices::virtio::InputError),
    InputEventsOpen(std::io::Error),
    SettingGidMap(io_jail::Error),
    SettingUidMap(io_jail::Error),
    SignalFd(sys_util::SignalFdError),
    SpawnVcpu(io::Error),
    TimerFd(sys_util::Error),
    ValidateRawFd(sys_util::Error),
    VhostNetDeviceNew(devices::virtio::vhost::Error),
    VhostVsockDeviceNew(devices::virtio::vhost::Error),
    VirtioPciDev(sys_util::Error),
    WaylandDeviceNew(sys_util::Error),
    LoadKernel(Box<error::Error>),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::BalloonDeviceNew(e) => write!(f, "failed to create balloon: {:?}", e),
            Error::BlockDeviceNew(e) => write!(f, "failed to create block device: {:?}", e),
            Error::BlockSignal(e) => write!(f, "failed to block signal: {:?}", e),
            Error::BuildingVm(e) => write!(f, "The architecture failed to build the vm: {:?}", e),
            Error::CloneEventFd(e) => write!(f, "failed to clone eventfd: {:?}", e),
            Error::CreateEventFd(e) => write!(f, "failed to create eventfd: {:?}", e),
            Error::CreatePollContext(e) => write!(f, "failed to create poll context: {:?}", e),
            Error::CreateSignalFd(e) => write!(f, "failed to create signalfd: {:?}", e),
            Error::CreateSocket(e) => write!(f, "failed to create socket: {}", e),
            Error::CreateTapDevice(e) => write!(f, "failed to create tap device: {:?}", e),
            Error::CreateTimerFd(e) => write!(f, "failed to create timerfd: {}", e),
            Error::DetectImageType(e) => write!(f, "failed to detect disk image type: {:?}", e),
            Error::DeviceJail(e) => write!(f, "failed to jail device: {}", e),
            Error::DevicePivotRoot(e) => write!(f, "failed to pivot root device: {}", e),
            Error::Disk(e) => write!(f, "failed to load disk image: {}", e),
            Error::DiskImageLock(e) => write!(f, "failed to lock disk image: {:?}", e),
            Error::InvalidFdPath => write!(f, "failed parsing a /proc/self/fd/*"),
            Error::InvalidWaylandPath => {
                write!(f, "wayland socket path has no parent or file name")
            }
            Error::NetDeviceNew(e) => write!(f, "failed to set up virtio networking: {:?}", e),
            Error::NoVarEmpty => write!(f, "/var/empty doesn't exist, can't jail devices."),
            Error::OpenKernel(p, e) => write!(f, "failed to open kernel image {:?}: {}", p, e),
            Error::OpenAndroidFstab(ref p, ref e) => {
                write!(f, "failed to open android fstab file {:?}: {}", p, e)
            }
            Error::P9DeviceNew(e) => write!(f, "failed to create 9p device: {}", e),
            Error::PollContextAdd(e) => write!(f, "failed to add fd to poll context: {:?}", e),
            Error::PollContextDelete(e) => {
                write!(f, "failed to remove fd from poll context: {:?}", e)
            }
            Error::QcowDeviceCreate(e) => write!(f, "failed to read qcow formatted file {:?}", e),
            Error::ReadLowmemAvailable(e) => write!(
                f,
                "failed to read /sys/kernel/mm/chromeos-low_mem/available: {}",
                e
            ),
            Error::ReadLowmemMargin(e) => write!(
                f,
                "failed to read /sys/kernel/mm/chromeos-low_mem/margin: {}",
                e
            ),
            Error::RegisterBalloon(e) => write!(f, "error registering balloon device: {:?}", e),
            Error::RegisterBlock(e) => write!(f, "error registering block device: {:?}", e),
            Error::RegisterGpu(e) => write!(f, "error registering gpu device: {:?}", e),
            Error::RegisterNet(e) => write!(f, "error registering net device: {:?}", e),
            Error::RegisterP9(e) => write!(f, "error registering 9p device: {:?}", e),
            Error::RegisterRng(e) => write!(f, "error registering rng device: {:?}", e),
            Error::RegisterSignalHandler(e) => {
                write!(f, "error registering signal handler: {:?}", e)
            }
            Error::RegisterWayland(e) => write!(f, "error registering wayland device: {}", e),
            Error::ResetTimerFd(e) => write!(f, "failed to reset timerfd: {}", e),
            Error::RngDeviceNew(e) => write!(f, "failed to set up rng: {:?}", e),
            Error::InputDeviceNew(ref e) => write!(f, "failed to set up input device: {:?}", e),
            Error::InputEventsOpen(ref e) => write!(f, "failed to open event device: {:?}", e),
            Error::SettingGidMap(e) => write!(f, "error setting GID map: {}", e),
            Error::SettingUidMap(e) => write!(f, "error setting UID map: {}", e),
            Error::SignalFd(e) => write!(f, "failed to read signal fd: {:?}", e),
            Error::SpawnVcpu(e) => write!(f, "failed to spawn VCPU thread: {:?}", e),
            Error::TimerFd(e) => write!(f, "failed to read timer fd: {:?}", e),
            Error::ValidateRawFd(e) => write!(f, "failed to validate raw fd: {:?}", e),
            Error::VhostNetDeviceNew(e) => write!(f, "failed to set up vhost networking: {:?}", e),
            Error::VhostVsockDeviceNew(e) => {
                write!(f, "failed to set up virtual socket device: {:?}", e)
            }
            Error::VirtioPciDev(e) => write!(f, "failed to create virtio pci dev: {}", e),
            Error::WaylandDeviceNew(e) => write!(f, "failed to create wayland device: {:?}", e),
            Error::LoadKernel(e) => write!(f, "failed to load kernel: {}", e),
        }
    }
}

impl std::error::Error for Error {
    fn description(&self) -> &str {
        "Some device failure"
    }
}

type Result<T> = std::result::Result<T, Error>;

fn create_base_minijail(root: &Path, seccomp_policy: &Path) -> Result<Minijail> {
    // All child jails run in a new user namespace without any users mapped,
    // they run as nobody unless otherwise configured.
    let mut j = Minijail::new().map_err(Error::DeviceJail)?;
    j.namespace_pids();
    j.namespace_user();
    j.namespace_user_disable_setgroups();
    // Don't need any capabilities.
    j.use_caps(0);
    // Create a new mount namespace with an empty root FS.
    j.namespace_vfs();
    j.enter_pivot_root(root).map_err(Error::DevicePivotRoot)?;
    // Run in an empty network namespace.
    j.namespace_net();
    // Apply the block device seccomp policy.
    j.no_new_privs();
    // Use TSYNC only for the side effect of it using SECCOMP_RET_TRAP, which will correctly kill
    // the entire device process if a worker thread commits a seccomp violation.
    j.set_seccomp_filter_tsync();
    #[cfg(debug_assertions)]
    j.log_seccomp_filter_failures();
    j.parse_seccomp_filters(seccomp_policy)
        .map_err(Error::DeviceJail)?;
    j.use_seccomp_filter();
    // Don't do init setup.
    j.run_as_init();
    Ok(j)
}

fn create_virtio_devs(
    cfg: Config,
    mem: &GuestMemory,
    _exit_evt: &EventFd,
    wayland_device_socket: UnixDatagram,
    balloon_device_socket: UnixDatagram,
    disk_device_sockets: &mut Vec<UnixDatagram>,
) -> std::result::Result<Vec<(Box<PciDevice + 'static>, Option<Minijail>)>, Box<error::Error>> {
    static DEFAULT_PIVOT_ROOT: &str = "/var/empty";

    let mut devs = Vec::new();

    // An empty directory for jailed device's pivot root.
    let empty_root_path = Path::new(DEFAULT_PIVOT_ROOT);
    if cfg.multiprocess && !empty_root_path.exists() {
        return Err(Box::new(Error::NoVarEmpty));
    }

    for disk in &cfg.disks {
        let disk_device_socket = disk_device_sockets.remove(0);

        // Special case '/proc/self/fd/*' paths. The FD is already open, just use it.
        let mut raw_image: File = if disk.path.parent() == Some(Path::new("/proc/self/fd")) {
            // Safe because we will validate |raw_fd|.
            unsafe { File::from_raw_fd(raw_fd_from_path(&disk.path)?) }
        } else {
            OpenOptions::new()
                .read(true)
                .write(!disk.read_only)
                .open(&disk.path)
                .map_err(Error::Disk)?
        };
        // Lock the disk image to prevent other crosvm instances from using it.
        let lock_op = if disk.read_only {
            FlockOperation::LockShared
        } else {
            FlockOperation::LockExclusive
        };
        flock(&raw_image, lock_op, true).map_err(Error::DiskImageLock)?;

        let image_type = qcow::detect_image_type(&raw_image).map_err(Error::DetectImageType)?;
        let block_box: Box<devices::virtio::VirtioDevice> = match image_type {
            ImageType::Raw => {
                // Access as a raw block device.
                Box::new(
                    devices::virtio::Block::new(
                        raw_image,
                        disk.read_only,
                        Some(disk_device_socket),
                    )
                    .map_err(Error::BlockDeviceNew)?,
                )
            }
            ImageType::Qcow2 => {
                // Valid qcow header present
                let qcow_image = QcowFile::from(raw_image).map_err(Error::QcowDeviceCreate)?;
                Box::new(
                    devices::virtio::Block::new(
                        qcow_image,
                        disk.read_only,
                        Some(disk_device_socket),
                    )
                    .map_err(Error::BlockDeviceNew)?,
                )
            }
        };
        let jail = if cfg.multiprocess {
            let policy_path: PathBuf = cfg.seccomp_policy_dir.join("block_device.policy");
            Some(create_base_minijail(empty_root_path, &policy_path)?)
        } else {
            None
        };

        devs.push(VirtioDeviceStub {
            dev: block_box,
            jail,
        });
    }

    let rng_box = Box::new(devices::virtio::Rng::new().map_err(Error::RngDeviceNew)?);
    let rng_jail = if cfg.multiprocess {
        let policy_path: PathBuf = cfg.seccomp_policy_dir.join("rng_device.policy");
        Some(create_base_minijail(empty_root_path, &policy_path)?)
    } else {
        None
    };
    devs.push(VirtioDeviceStub {
        dev: rng_box,
        jail: rng_jail,
    });

    #[cfg(feature = "tpm")]
    {
        let tpm_box = Box::new(devices::virtio::Tpm::new());
        let tpm_jail = if cfg.multiprocess {
            let policy_path = cfg.seccomp_policy_dir.join("tpm_device.policy");
            Some(create_base_minijail(empty_root_path, &policy_path)?)
        } else {
            None
        };
        devs.push(VirtioDeviceStub {
            dev: tpm_box,
            jail: tpm_jail,
        });
    }

    if let Some(trackpad_spec) = cfg.virtio_trackpad {
        match create_input_socket(&trackpad_spec.path) {
            Ok(socket) => {
                let trackpad_box = Box::new(
                    devices::virtio::new_trackpad(
                        socket,
                        trackpad_spec.width,
                        trackpad_spec.height,
                    )
                    .map_err(Error::InputDeviceNew)?,
                );
                let trackpad_jail = if cfg.multiprocess {
                    let policy_path: PathBuf = cfg.seccomp_policy_dir.join("input_device.policy");
                    Some(create_base_minijail(empty_root_path, &policy_path)?)
                } else {
                    None
                };
                devs.push(VirtioDeviceStub {
                    dev: trackpad_box,
                    jail: trackpad_jail,
                });
            }
            Err(e) => {
                error!("failed configuring virtio trackpad: {:?}", e);
                return Err(e);
            }
        }
    }

    if let Some(mouse_socket) = cfg.virtio_mouse {
        match create_input_socket(&mouse_socket) {
            Ok(socket) => {
                let mouse_box =
                    Box::new(devices::virtio::new_mouse(socket).map_err(Error::InputDeviceNew)?);
                let mouse_jail = if cfg.multiprocess {
                    let policy_path: PathBuf = cfg.seccomp_policy_dir.join("input_device.policy");
                    Some(create_base_minijail(empty_root_path, &policy_path)?)
                } else {
                    None
                };
                devs.push(VirtioDeviceStub {
                    dev: mouse_box,
                    jail: mouse_jail,
                });
            }
            Err(e) => {
                error!("failed configuring virtio mouse: {:?}", e);
                return Err(e);
            }
        }
    }

    if let Some(keyboard_socket) = cfg.virtio_keyboard {
        match create_input_socket(&keyboard_socket) {
            Ok(socket) => {
                let keyboard_box =
                    Box::new(devices::virtio::new_keyboard(socket).map_err(Error::InputDeviceNew)?);
                let keyboard_jail = if cfg.multiprocess {
                    let policy_path: PathBuf = cfg.seccomp_policy_dir.join("input_device.policy");
                    Some(create_base_minijail(empty_root_path, &policy_path)?)
                } else {
                    None
                };
                devs.push(VirtioDeviceStub {
                    dev: keyboard_box,
                    jail: keyboard_jail,
                });
            }
            Err(e) => {
                error!("failed configuring virtio keyboard: {:?}", e);
                return Err(e);
            }
        }
    }

    for dev_path in cfg.virtio_input_evdevs {
        let dev_file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(dev_path)
            .map_err(|e| Box::new(e))?;
        let vinput_box =
            Box::new(devices::virtio::new_evdev(dev_file).map_err(Error::InputDeviceNew)?);
        let vinput_jail = if cfg.multiprocess {
            let policy_path: PathBuf = cfg.seccomp_policy_dir.join("input_device.policy");
            Some(create_base_minijail(empty_root_path, &policy_path)?)
        } else {
            None
        };
        devs.push(VirtioDeviceStub {
            dev: vinput_box,
            jail: vinput_jail,
        });
    }

    let balloon_box = Box::new(
        devices::virtio::Balloon::new(balloon_device_socket).map_err(Error::BalloonDeviceNew)?,
    );
    let balloon_jail = if cfg.multiprocess {
        let policy_path: PathBuf = cfg.seccomp_policy_dir.join("balloon_device.policy");
        Some(create_base_minijail(empty_root_path, &policy_path)?)
    } else {
        None
    };
    devs.push(VirtioDeviceStub {
        dev: balloon_box,
        jail: balloon_jail,
    });

    // We checked above that if the IP is defined, then the netmask is, too.
    if let Some(tap_fd) = cfg.tap_fd {
        // Safe because we ensure that we get a unique handle to the fd.
        let tap = unsafe {
            Tap::from_raw_fd(validate_raw_fd(tap_fd).map_err(Error::ValidateRawFd)?)
                .map_err(Error::CreateTapDevice)?
        };
        let net_box = Box::new(devices::virtio::Net::from(tap).map_err(Error::NetDeviceNew)?);

        let jail = if cfg.multiprocess {
            let policy_path: PathBuf = cfg.seccomp_policy_dir.join("net_device.policy");

            Some(create_base_minijail(empty_root_path, &policy_path)?)
        } else {
            None
        };

        devs.push(VirtioDeviceStub { dev: net_box, jail });
    } else if let Some(host_ip) = cfg.host_ip {
        if let Some(netmask) = cfg.netmask {
            if let Some(mac_address) = cfg.mac_address {
                let net_box: Box<devices::virtio::VirtioDevice> = if cfg.vhost_net {
                    Box::new(
                        devices::virtio::vhost::Net::<Tap, vhost::Net<Tap>>::new(
                            host_ip,
                            netmask,
                            mac_address,
                            &mem,
                        )
                        .map_err(Error::VhostNetDeviceNew)?,
                    )
                } else {
                    Box::new(
                        devices::virtio::Net::<Tap>::new(host_ip, netmask, mac_address)
                            .map_err(Error::NetDeviceNew)?,
                    )
                };

                let jail = if cfg.multiprocess {
                    let policy_path: PathBuf = if cfg.vhost_net {
                        cfg.seccomp_policy_dir.join("vhost_net_device.policy")
                    } else {
                        cfg.seccomp_policy_dir.join("net_device.policy")
                    };

                    Some(create_base_minijail(empty_root_path, &policy_path)?)
                } else {
                    None
                };

                devs.push(VirtioDeviceStub { dev: net_box, jail });
            }
        }
    }

    #[cfg(feature = "gpu")]
    let mut resource_bridge_wl_socket: Option<
        devices::virtio::resource_bridge::ResourceRequestSocket,
    > = None;
    #[cfg(feature = "gpu")]
    {
        if cfg.gpu {
            if let Some(wayland_socket_path) = cfg.wayland_socket_path.as_ref() {
                let (wl_socket, gpu_socket) =
                    devices::virtio::resource_bridge::pair().map_err(Error::CreateSocket)?;
                resource_bridge_wl_socket = Some(wl_socket);

                let jailed_wayland_path = Path::new("/wayland-0");

                let gpu_box = Box::new(devices::virtio::Gpu::new(
                    _exit_evt.try_clone().map_err(Error::CloneEventFd)?,
                    Some(gpu_socket),
                    if cfg.multiprocess {
                        &jailed_wayland_path
                    } else {
                        wayland_socket_path.as_path()
                    },
                ));

                let jail = if cfg.multiprocess {
                    let policy_path: PathBuf = cfg.seccomp_policy_dir.join("gpu_device.policy");
                    let mut jail = create_base_minijail(empty_root_path, &policy_path)?;

                    // Create a tmpfs in the device's root directory so that we can bind mount the
                    // dri directory into it.  The size=67108864 is size=64*1024*1024 or size=64MB.
                    jail.mount_with_data(
                        Path::new("none"),
                        Path::new("/"),
                        "tmpfs",
                        (libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC) as usize,
                        "size=67108864",
                    )
                    .unwrap();

                    // Device nodes required for DRM.
                    let sys_dev_char_path = Path::new("/sys/dev/char");
                    jail.mount_bind(sys_dev_char_path, sys_dev_char_path, false)
                        .unwrap();
                    let sys_devices_path = Path::new("/sys/devices");
                    jail.mount_bind(sys_devices_path, sys_devices_path, false)
                        .unwrap();
                    let drm_dri_path = Path::new("/dev/dri");
                    jail.mount_bind(drm_dri_path, drm_dri_path, false).unwrap();

                    // Libraries that are required when mesa drivers are dynamically loaded.
                    let lib_path = Path::new("/lib64");
                    jail.mount_bind(lib_path, lib_path, false).unwrap();
                    let usr_lib_path = Path::new("/usr/lib64");
                    jail.mount_bind(usr_lib_path, usr_lib_path, false).unwrap();

                    // Bind mount the wayland socket into jail's root. This is necessary since each
                    // new wayland context must open() the socket.
                    jail.mount_bind(wayland_socket_path.as_path(), jailed_wayland_path, true)
                        .unwrap();

                    // Set the uid/gid for the jailed process, and give a basic id map. This
                    // is required for the above bind mount to work.
                    let crosvm_user_group = CStr::from_bytes_with_nul(b"crosvm\0").unwrap();
                    let crosvm_uid = match get_user_id(&crosvm_user_group) {
                        Ok(u) => u,
                        Err(e) => {
                            warn!("falling back to current user id for gpu: {:?}", e);
                            geteuid()
                        }
                    };
                    let crosvm_gid = match get_group_id(&crosvm_user_group) {
                        Ok(u) => u,
                        Err(e) => {
                            warn!("falling back to current group id for gpu: {:?}", e);
                            getegid()
                        }
                    };
                    jail.change_uid(crosvm_uid);
                    jail.change_gid(crosvm_gid);
                    jail.uidmap(&format!("{0} {0} 1", crosvm_uid))
                        .map_err(Error::SettingUidMap)?;
                    jail.gidmap(&format!("{0} {0} 1", crosvm_gid))
                        .map_err(Error::SettingGidMap)?;

                    Some(jail)
                } else {
                    None
                };
                devs.push(VirtioDeviceStub { dev: gpu_box, jail });
            }
        }
    }

    if let Some(wayland_socket_path) = cfg.wayland_socket_path.as_ref() {
        let wayland_socket_dir = wayland_socket_path
            .parent()
            .ok_or(Error::InvalidWaylandPath)?;
        let wayland_socket_name = wayland_socket_path
            .file_name()
            .ok_or(Error::InvalidWaylandPath)?;
        let jailed_wayland_dir = Path::new("/wayland");
        let jailed_wayland_path = jailed_wayland_dir.join(wayland_socket_name);

        #[cfg(not(feature = "gpu"))]
        let resource_bridge_wl_socket = None;

        let wl_box = Box::new(
            devices::virtio::Wl::new(
                if cfg.multiprocess {
                    &jailed_wayland_path
                } else {
                    wayland_socket_path.as_path()
                },
                wayland_device_socket,
                resource_bridge_wl_socket,
            )
            .map_err(Error::WaylandDeviceNew)?,
        );

        let jail = if cfg.multiprocess {
            let policy_path: PathBuf = cfg.seccomp_policy_dir.join("wl_device.policy");
            let mut jail = create_base_minijail(empty_root_path, &policy_path)?;

            // Create a tmpfs in the device's root directory so that we can bind mount the wayland
            // socket directory into it. The size=67108864 is size=64*1024*1024 or size=64MB.
            jail.mount_with_data(
                Path::new("none"),
                Path::new("/"),
                "tmpfs",
                (libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC) as usize,
                "size=67108864",
            )
            .unwrap();

            // Bind mount the wayland socket's directory into jail's root. This is necessary since
            // each new wayland context must open() the socket. If the wayland socket is ever
            // destroyed and remade in the same host directory, new connections will be possible
            // without restarting the wayland device.
            jail.mount_bind(wayland_socket_dir, jailed_wayland_dir, true)
                .unwrap();

            // Set the uid/gid for the jailed process, and give a basic id map. This
            // is required for the above bind mount to work.
            let crosvm_user_group = CStr::from_bytes_with_nul(b"crosvm\0").unwrap();
            let crosvm_uid = match get_user_id(&crosvm_user_group) {
                Ok(u) => u,
                Err(e) => {
                    warn!("falling back to current user id for Wayland: {:?}", e);
                    geteuid()
                }
            };
            let crosvm_gid = match get_group_id(&crosvm_user_group) {
                Ok(u) => u,
                Err(e) => {
                    warn!("falling back to current group id for Wayland: {:?}", e);
                    getegid()
                }
            };
            jail.change_uid(crosvm_uid);
            jail.change_gid(crosvm_gid);
            jail.uidmap(&format!("{0} {0} 1", crosvm_uid))
                .map_err(Error::SettingUidMap)?;
            jail.gidmap(&format!("{0} {0} 1", crosvm_gid))
                .map_err(Error::SettingGidMap)?;

            Some(jail)
        } else {
            None
        };
        devs.push(VirtioDeviceStub { dev: wl_box, jail });
    }

    if let Some(cid) = cfg.cid {
        let vsock_box = Box::new(
            devices::virtio::vhost::Vsock::new(cid, &mem).map_err(Error::VhostVsockDeviceNew)?,
        );

        let jail = if cfg.multiprocess {
            let policy_path: PathBuf = cfg.seccomp_policy_dir.join("vhost_vsock_device.policy");

            Some(create_base_minijail(empty_root_path, &policy_path)?)
        } else {
            None
        };

        devs.push(VirtioDeviceStub {
            dev: vsock_box,
            jail,
        });
    }

    let chronos_user_group = CStr::from_bytes_with_nul(b"chronos\0").unwrap();
    let chronos_uid = match get_user_id(&chronos_user_group) {
        Ok(u) => u,
        Err(e) => {
            warn!("falling back to current user id for 9p: {:?}", e);
            geteuid()
        }
    };
    let chronos_gid = match get_group_id(&chronos_user_group) {
        Ok(u) => u,
        Err(e) => {
            warn!("falling back to current group id for 9p: {:?}", e);
            getegid()
        }
    };

    for &(ref src, ref tag) in &cfg.shared_dirs {
        let (jail, root) = if cfg.multiprocess {
            let policy_path: PathBuf = cfg.seccomp_policy_dir.join("9p_device.policy");
            let mut jail = create_base_minijail(empty_root_path, &policy_path)?;

            //  The shared directory becomes the root of the device's file system.
            let root = Path::new("/");
            jail.mount_bind(&src, root, true).unwrap();

            // Set the uid/gid for the jailed process, and give a basic id map. This
            // is required for the above bind mount to work.
            jail.change_uid(chronos_uid);
            jail.change_gid(chronos_gid);
            jail.uidmap(&format!("{0} {0} 1", chronos_uid))
                .map_err(Error::SettingUidMap)?;
            jail.gidmap(&format!("{0} {0} 1", chronos_gid))
                .map_err(Error::SettingGidMap)?;

            (Some(jail), root)
        } else {
            // There's no bind mount so we tell the server to treat the source directory as the
            // root.  The double deref here converts |src| from a &PathBuf into a &Path.
            (None, &**src)
        };

        let p9_box = Box::new(devices::virtio::P9::new(root, tag).map_err(Error::P9DeviceNew)?);

        devs.push(VirtioDeviceStub { dev: p9_box, jail });
    }

    let mut pci_devices: Vec<(Box<PciDevice + 'static>, Option<Minijail>)> = Vec::new();
    for stub in devs {
        let pci_dev =
            Box::new(VirtioPciDevice::new((*mem).clone(), stub.dev).map_err(Error::VirtioPciDev)?);
        pci_devices.push((pci_dev, stub.jail));
    }

    if cfg.cras_audio {
        let cras_audio_box = Box::new(devices::Ac97Dev::new(
            (*mem).clone(),
            Box::new(CrasClient::new()?),
        ));
        let cras_audio_jail = if cfg.multiprocess {
            let policy_path: PathBuf = cfg.seccomp_policy_dir.join("cras_audio_device.policy");
            Some(create_base_minijail(empty_root_path, &policy_path)?)
        } else {
            None
        };
        pci_devices.push((cras_audio_box, cras_audio_jail));
    }

    if cfg.null_audio {
        let null_audio_box = Box::new(devices::Ac97Dev::new(
            (*mem).clone(),
            Box::new(DummyStreamSource::new()),
        ));
        let null_audio_jail = if cfg.multiprocess {
            let policy_path: PathBuf = cfg.seccomp_policy_dir.join("null_audio_device.policy");
            Some(create_base_minijail(empty_root_path, &policy_path)?)
        } else {
            None
        };
        pci_devices.push((null_audio_box, null_audio_jail));
    }

    Ok(pci_devices)
}

fn raw_fd_from_path(path: &PathBuf) -> std::result::Result<RawFd, Box<Error>> {
    if !path.is_file() {
        return Err(Box::new(Error::InvalidFdPath));
    }
    let raw_fd = path
        .file_name()
        .and_then(|fd_osstr| fd_osstr.to_str())
        .and_then(|fd_str| fd_str.parse::<c_int>().ok())
        .ok_or(Error::InvalidFdPath)?;
    validate_raw_fd(raw_fd).map_err(|e| Box::new(Error::ValidateRawFd(e)))
}

fn create_input_socket(path: &PathBuf) -> std::result::Result<UnixStream, Box<Error>> {
    if path.parent() == Some(Path::new("/proc/self/fd")) {
        // Safe because we will validate |raw_fd|.
        unsafe { Ok(UnixStream::from_raw_fd(raw_fd_from_path(path)?)) }
    } else {
        match UnixStream::connect(path) {
            Ok(us) => return Ok(us),
            Err(e) => {
                return Err(Box::new(Error::InputEventsOpen(e)));
            }
        }
    }
}

fn setup_vcpu_signal_handler() -> Result<()> {
    unsafe {
        extern "C" fn handle_signal() {}
        // Our signal handler does nothing and is trivially async signal safe.
        register_signal_handler(SIGRTMIN() + 0, handle_signal)
            .map_err(Error::RegisterSignalHandler)?;
    }
    block_signal(SIGRTMIN() + 0).map_err(Error::BlockSignal)?;
    Ok(())
}

#[derive(Default)]
struct VcpuRunMode {
    mtx: Mutex<VmRunMode>,
    cvar: Condvar,
}

impl VcpuRunMode {
    fn set_and_notify(&self, new_mode: VmRunMode) {
        *self.mtx.lock() = new_mode;
        self.cvar.notify_all();
    }
}

fn run_vcpu(
    vcpu: Vcpu,
    cpu_id: u32,
    start_barrier: Arc<Barrier>,
    io_bus: devices::Bus,
    mmio_bus: devices::Bus,
    exit_evt: EventFd,
    requires_kvmclock_ctrl: bool,
    run_mode_arc: Arc<VcpuRunMode>,
) -> Result<JoinHandle<()>> {
    thread::Builder::new()
        .name(format!("crosvm_vcpu{}", cpu_id))
        .spawn(move || {
            let mut sig_ok = true;
            match get_blocked_signals() {
                Ok(mut v) => {
                    v.retain(|&x| x != SIGRTMIN() + 0);
                    if let Err(e) = vcpu.set_signal_mask(&v) {
                        error!(
                            "Failed to set the KVM_SIGNAL_MASK for vcpu {} : {:?}",
                            cpu_id, e
                        );
                        sig_ok = false;
                    }
                }
                Err(e) => {
                    error!(
                        "Failed to retrieve signal mask for vcpu {} : {:?}",
                        cpu_id, e
                    );
                    sig_ok = false;
                }
            };

            start_barrier.wait();

            if sig_ok {
                'vcpu_loop: loop {
                    let mut interrupted_by_signal = false;
                    match vcpu.run() {
                        Ok(VcpuExit::IoIn { port, mut size }) => {
                            let mut data = [0; 8];
                            if size > data.len() {
                                error!("unsupported IoIn size of {} bytes", size);
                                size = data.len();
                            }
                            io_bus.read(port as u64, &mut data[..size]);
                            if let Err(e) = vcpu.set_data(&data[..size]) {
                                error!("failed to set return data for IoIn: {:?}", e);
                            }
                        }
                        Ok(VcpuExit::IoOut {
                            port,
                            mut size,
                            data,
                        }) => {
                            if size > data.len() {
                                error!("unsupported IoOut size of {} bytes", size);
                                size = data.len();
                            }
                            io_bus.write(port as u64, &data[..size]);
                        }
                        Ok(VcpuExit::MmioRead { address, size }) => {
                            let mut data = [0; 8];
                            mmio_bus.read(address, &mut data[..size]);
                            // Setting data for mmio can not fail.
                            let _ = vcpu.set_data(&data[..size]);
                        }
                        Ok(VcpuExit::MmioWrite {
                            address,
                            size,
                            data,
                        }) => {
                            mmio_bus.write(address, &data[..size]);
                        }
                        Ok(VcpuExit::Hlt) => break,
                        Ok(VcpuExit::Shutdown) => break,
                        Ok(VcpuExit::SystemEvent(_, _)) => break,
                        Ok(r) => warn!("unexpected vcpu exit: {:?}", r),
                        Err(e) => match e.errno() {
                            libc::EINTR => interrupted_by_signal = true,
                            libc::EAGAIN => {}
                            _ => {
                                error!("vcpu hit unknown error: {:?}", e);
                                break;
                            }
                        },
                    }

                    if interrupted_by_signal {
                        // Try to clear the signal that we use to kick VCPU if it is pending before
                        // attempting to handle pause requests.
                        if let Err(e) = clear_signal(SIGRTMIN() + 0) {
                            error!("failed to clear pending signal: {:?}", e);
                            break;
                        }
                        let mut run_mode_lock = run_mode_arc.mtx.lock();
                        loop {
                            match *run_mode_lock {
                                VmRunMode::Running => break,
                                VmRunMode::Suspending => {
                                    // On KVM implementations that use a paravirtualized clock (e.g.
                                    // x86), a flag must be set to indicate to the guest kernel that
                                    // a VCPU was suspended. The guest kernel will use this flag to
                                    // prevent the soft lockup detection from triggering when this
                                    // VCPU resumes, which could happen days later in realtime.
                                    if requires_kvmclock_ctrl {
                                        if let Err(e) = vcpu.kvmclock_ctrl() {
                                            error!("failed to signal to kvm that vcpu {} is being suspended: {:?}", cpu_id, e);
                                        }
                                    }
                                }
                                VmRunMode::Exiting => break 'vcpu_loop,
                            }
                            // Give ownership of our exclusive lock to the condition variable that
                            // will block. When the condition variable is notified, `wait` will
                            // unblock and return a new exclusive lock.
                            run_mode_lock = run_mode_arc.cvar.wait(run_mode_lock);
                        }
                    }
                }
            }
            exit_evt
                .write(1)
                .expect("failed to signal vcpu exit eventfd");
        })
        .map_err(Error::SpawnVcpu)
}

// Reads the contents of a file and converts them into a u64.
fn file_to_u64<P: AsRef<Path>>(path: P) -> io::Result<u64> {
    let mut file = File::open(path)?;

    let mut buf = [0u8; 32];
    let count = file.read(&mut buf)?;

    let content =
        str::from_utf8(&buf[..count]).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    content
        .trim()
        .parse()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

pub fn run_config(cfg: Config) -> Result<()> {
    if cfg.multiprocess {
        // Printing something to the syslog before entering minijail so that libc's syslogger has a
        // chance to open files necessary for its operation, like `/etc/localtime`. After jailing,
        // access to those files will not be possible.
        info!("crosvm entering multiprocess mode");
    }

    // Masking signals is inherently dangerous, since this can persist across clones/execs. Do this
    // before any jailed devices have been spawned, so that we can catch any of them that fail very
    // quickly.
    let sigchld_fd = SignalFd::new(libc::SIGCHLD).map_err(Error::CreateSignalFd)?;

    let components = VmComponents {
        memory_mb: (cfg.memory.unwrap_or(256) << 20) as u64,
        vcpu_count: cfg.vcpu_count.unwrap_or(1),
        kernel_image: File::open(cfg.kernel_path.as_path())
            .map_err(|e| Error::OpenKernel(cfg.kernel_path.clone(), e))?,
        android_fstab: cfg
            .android_fstab
            .as_ref()
            .map(|x| {
                File::open(x.as_path()).map_err(|e| Error::OpenAndroidFstab(x.to_path_buf(), e))
            })
            .map_or(Ok(None), |v| v.map(Some))?,
        extra_kernel_params: cfg.params.clone(),
        wayland_dmabuf: cfg.wayland_dmabuf,
    };

    let mut control_sockets = Vec::new();
    if let Some(ref path_string) = cfg.socket_path {
        let path = Path::new(path_string);
        let dgram = UnixDatagram::bind(path).map_err(Error::CreateSocket)?;
        control_sockets.push(UnlinkMsgSocket::<VmResponse, VmRequest>::new(
            UnlinkUnixDatagram(dgram),
        ));
    };
    let (wayland_host_socket, wayland_device_socket) =
        UnixDatagram::pair().map_err(Error::CreateSocket)?;
    control_sockets.push(UnlinkMsgSocket::<VmResponse, VmRequest>::new(
        UnlinkUnixDatagram(wayland_host_socket),
    ));
    // Balloon gets a special socket so balloon requests can be forwarded from the main process.
    let (balloon_host_socket, balloon_device_socket) =
        UnixDatagram::pair().map_err(Error::CreateSocket)?;

    // Create one control socket per disk.
    let mut disk_device_sockets = Vec::new();
    let mut disk_host_sockets = Vec::new();
    let disk_count = cfg.disks.len();
    for _ in 0..disk_count {
        let (disk_host_socket, disk_device_socket) =
            UnixDatagram::pair().map_err(Error::CreateSocket)?;
        disk_device_sockets.push(disk_device_socket);
        let disk_host_socket = MsgSocket::<VmRequest, VmResponse>::new(disk_host_socket);
        disk_host_sockets.push(disk_host_socket);
    }

    let linux = Arch::build_vm(components, cfg.split_irqchip, |m, e| {
        create_virtio_devs(
            cfg,
            m,
            e,
            wayland_device_socket,
            balloon_device_socket,
            &mut disk_device_sockets,
        )
    })
    .map_err(Error::BuildingVm)?;
    run_control(
        linux,
        control_sockets,
        balloon_host_socket,
        &disk_host_sockets,
        sigchld_fd,
    )
}

fn run_control(
    mut linux: RunnableLinuxVm,
    control_sockets: Vec<UnlinkMsgSocket<VmResponse, VmRequest>>,
    balloon_host_socket: UnixDatagram,
    disk_host_sockets: &[MsgSocket<VmRequest, VmResponse>],
    sigchld_fd: SignalFd,
) -> Result<()> {
    // Paths to get the currently available memory and the low memory threshold.
    const LOWMEM_MARGIN: &str = "/sys/kernel/mm/chromeos-low_mem/margin";
    const LOWMEM_AVAILABLE: &str = "/sys/kernel/mm/chromeos-low_mem/available";

    // The amount of additional memory to claim back from the VM whenever the system is
    // low on memory.
    const ONE_GB: u64 = (1 << 30);

    let max_balloon_memory = match linux.vm.get_memory().memory_size() {
        // If the VM has at least 1.5 GB, the balloon driver can consume all but the last 1 GB.
        n if n >= (ONE_GB / 2) * 3 => n - ONE_GB,
        // Otherwise, if the VM has at least 500MB the balloon driver will consume at most
        // half of it.
        n if n >= (ONE_GB / 2) => n / 2,
        // Otherwise, the VM is too small for us to take memory away from it.
        _ => 0,
    };
    let mut current_balloon_memory: u64 = 0;
    let balloon_memory_increment: u64 = max_balloon_memory / 16;

    #[derive(PollToken)]
    enum Token {
        Exit,
        Stdin,
        ChildSignal,
        CheckAvailableMemory,
        LowMemory,
        LowmemTimer,
        VmControl { index: usize },
    }

    let stdin_handle = stdin();
    let stdin_lock = stdin_handle.lock();
    stdin_lock
        .set_raw_mode()
        .expect("failed to set terminal raw mode");

    let poll_ctx = PollContext::new().map_err(Error::CreatePollContext)?;
    poll_ctx
        .add(&linux.exit_evt, Token::Exit)
        .map_err(Error::PollContextAdd)?;
    if let Err(e) = poll_ctx.add(&stdin_handle, Token::Stdin) {
        warn!("failed to add stdin to poll context: {:?}", e);
    }
    poll_ctx
        .add(&sigchld_fd, Token::ChildSignal)
        .map_err(Error::PollContextAdd)?;
    for (index, socket) in control_sockets.iter().enumerate() {
        poll_ctx
            .add(socket.as_ref(), Token::VmControl { index })
            .map_err(Error::PollContextAdd)?;
    }

    // Watch for low memory notifications and take memory back from the VM.
    let low_mem = File::open("/dev/chromeos-low-mem").ok();
    if let Some(ref low_mem) = low_mem {
        poll_ctx
            .add(low_mem, Token::LowMemory)
            .map_err(Error::PollContextAdd)?;
    } else {
        warn!("Unable to open low mem indicator, maybe not a chrome os kernel");
    }

    // Used to rate limit balloon requests.
    let mut lowmem_timer = TimerFd::new().map_err(Error::CreateTimerFd)?;
    poll_ctx
        .add(&lowmem_timer, Token::LowmemTimer)
        .map_err(Error::PollContextAdd)?;

    // Used to check whether it's ok to start giving memory back to the VM.
    let mut freemem_timer = TimerFd::new().map_err(Error::CreateTimerFd)?;
    poll_ctx
        .add(&freemem_timer, Token::CheckAvailableMemory)
        .map_err(Error::PollContextAdd)?;

    // Used to add jitter to timer values so that we don't have a thundering herd problem when
    // multiple VMs are running.
    let mut simple_rng = SimpleRng::new(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time went backwards")
            .subsec_nanos() as u64,
    );

    let mut vcpu_handles = Vec::with_capacity(linux.vcpus.len());
    let vcpu_thread_barrier = Arc::new(Barrier::new(linux.vcpus.len() + 1));
    let run_mode_arc = Arc::new(VcpuRunMode::default());
    setup_vcpu_signal_handler()?;
    for (cpu_id, vcpu) in linux.vcpus.into_iter().enumerate() {
        let handle = run_vcpu(
            vcpu,
            cpu_id as u32,
            vcpu_thread_barrier.clone(),
            linux.io_bus.clone(),
            linux.mmio_bus.clone(),
            linux.exit_evt.try_clone().map_err(Error::CloneEventFd)?,
            linux.vm.check_extension(Cap::KvmclockCtrl),
            run_mode_arc.clone(),
        )?;
        vcpu_handles.push(handle);
    }
    vcpu_thread_barrier.wait();

    'poll: loop {
        let events = {
            match poll_ctx.wait() {
                Ok(v) => v,
                Err(e) => {
                    error!("failed to poll: {:?}", e);
                    break;
                }
            }
        };
        for event in events.iter_readable() {
            match event.token() {
                Token::Exit => {
                    info!("vcpu requested shutdown");
                    break 'poll;
                }
                Token::Stdin => {
                    let mut out = [0u8; 64];
                    match stdin_lock.read_raw(&mut out[..]) {
                        Ok(0) => {
                            // Zero-length read indicates EOF. Remove from pollables.
                            let _ = poll_ctx.delete(&stdin_handle);
                        }
                        Err(e) => {
                            warn!("error while reading stdin: {:?}", e);
                            let _ = poll_ctx.delete(&stdin_handle);
                        }
                        Ok(count) => {
                            linux
                                .stdio_serial
                                .lock()
                                .queue_input_bytes(&out[..count])
                                .expect("failed to queue bytes into serial port");
                        }
                    }
                }
                Token::ChildSignal => {
                    // Print all available siginfo structs, then exit the loop.
                    while let Some(siginfo) = sigchld_fd.read().map_err(Error::SignalFd)? {
                        let pid = siginfo.ssi_pid;
                        let pid_label = match linux.pid_debug_label_map.get(&pid) {
                            Some(label) => format!("{} (pid {})", label, pid),
                            None => format!("pid {}", pid),
                        };
                        error!(
                            "child {} died: signo {}, status {}, code {}",
                            pid_label, siginfo.ssi_signo, siginfo.ssi_status, siginfo.ssi_code
                        );
                    }
                    break 'poll;
                }
                Token::CheckAvailableMemory => {
                    // Acknowledge the timer.
                    freemem_timer.wait().map_err(Error::TimerFd)?;
                    if current_balloon_memory == 0 {
                        // Nothing to see here.
                        if let Err(e) = freemem_timer.clear() {
                            warn!("unable to clear available memory check timer: {}", e);
                        }
                        continue;
                    }

                    // Otherwise see if we can free up some memory.
                    let margin = file_to_u64(LOWMEM_MARGIN).map_err(Error::ReadLowmemMargin)?;
                    let available =
                        file_to_u64(LOWMEM_AVAILABLE).map_err(Error::ReadLowmemAvailable)?;

                    // `available` and `margin` are specified in MB while `balloon_memory_increment` is in
                    // bytes.  So to correctly compare them we need to turn the increment value into MB.
                    if available >= margin + 2 * (balloon_memory_increment >> 20) {
                        current_balloon_memory =
                            if current_balloon_memory >= balloon_memory_increment {
                                current_balloon_memory - balloon_memory_increment
                            } else {
                                0
                            };
                        let mut buf = [0u8; mem::size_of::<u64>()];
                        LittleEndian::write_u64(&mut buf, current_balloon_memory);
                        if let Err(e) = balloon_host_socket.send(&buf) {
                            warn!("failed to send memory value to balloon device: {}", e);
                        }
                    }
                }
                Token::LowMemory => {
                    if let Some(ref low_mem) = low_mem {
                        let old_balloon_memory = current_balloon_memory;
                        current_balloon_memory = min(
                            current_balloon_memory + balloon_memory_increment,
                            max_balloon_memory,
                        );
                        if current_balloon_memory != old_balloon_memory {
                            let mut buf = [0u8; mem::size_of::<u64>()];
                            LittleEndian::write_u64(&mut buf, current_balloon_memory);
                            if let Err(e) = balloon_host_socket.send(&buf) {
                                warn!("failed to send memory value to balloon device: {}", e);
                            }
                        }

                        // Stop polling the lowmem device until the timer fires.
                        poll_ctx.delete(low_mem).map_err(Error::PollContextDelete)?;

                        // Add some jitter to the timer so that if there are multiple VMs running
                        // they don't all start ballooning at exactly the same time.
                        let lowmem_dur = Duration::from_millis(1000 + simple_rng.rng() % 200);
                        lowmem_timer
                            .reset(lowmem_dur, None)
                            .map_err(Error::ResetTimerFd)?;

                        // Also start a timer to check when we can start giving memory back.  Do the
                        // first check after a minute (with jitter) and subsequent checks after
                        // every 30 seconds (with jitter).
                        let freemem_dur = Duration::from_secs(60 + simple_rng.rng() % 12);
                        let freemem_int = Duration::from_secs(30 + simple_rng.rng() % 6);
                        freemem_timer
                            .reset(freemem_dur, Some(freemem_int))
                            .map_err(Error::ResetTimerFd)?;
                    }
                }
                Token::LowmemTimer => {
                    // Acknowledge the timer.
                    lowmem_timer.wait().map_err(Error::TimerFd)?;

                    if let Some(ref low_mem) = low_mem {
                        // Start polling the lowmem device again.
                        poll_ctx
                            .add(low_mem, Token::LowMemory)
                            .map_err(Error::PollContextAdd)?;
                    }
                }
                Token::VmControl { index } => {
                    if let Some(socket) = control_sockets.get(index) {
                        match socket.recv() {
                            Ok(request) => {
                                let mut run_mode_opt = None;
                                let response = request.execute(
                                    &mut linux.vm,
                                    &mut linux.resources,
                                    &mut run_mode_opt,
                                    &balloon_host_socket,
                                    disk_host_sockets,
                                );
                                if let Err(e) = socket.send(&response) {
                                    error!("failed to send VmResponse: {:?}", e);
                                }
                                if let Some(run_mode) = run_mode_opt {
                                    info!("control socket changed run mode to {:?}", run_mode);
                                    match run_mode {
                                        VmRunMode::Exiting => {
                                            break 'poll;
                                        }
                                        other => {
                                            run_mode_arc.set_and_notify(other);
                                            for handle in &vcpu_handles {
                                                let _ = handle.kill(SIGRTMIN() + 0);
                                            }
                                        }
                                    }
                                }
                            }
                            Err(e) => error!("failed to recv VmRequest: {:?}", e),
                        }
                    }
                }
            }
        }
        for event in events.iter_hungup() {
            // It's possible more data is readable and buffered while the socket is hungup, so
            // don't delete the socket from the poll context until we're sure all the data is
            // read.
            if !event.readable() {
                match event.token() {
                    Token::Exit => {}
                    Token::Stdin => {
                        let _ = poll_ctx.delete(&stdin_handle);
                    }
                    Token::ChildSignal => {}
                    Token::CheckAvailableMemory => {}
                    Token::LowMemory => {}
                    Token::LowmemTimer => {}
                    Token::VmControl { index } => {
                        if let Some(socket) = control_sockets.get(index) {
                            let _ = poll_ctx.delete(socket.as_ref());
                        }
                    }
                }
            }
        }
    }

    // VCPU threads MUST see the VmRunMode flag, otherwise they may re-enter the VM.
    run_mode_arc.set_and_notify(VmRunMode::Exiting);
    for handle in vcpu_handles {
        match handle.kill(SIGRTMIN() + 0) {
            Ok(_) => {
                if let Err(e) = handle.join() {
                    error!("failed to join vcpu thread: {:?}", e);
                }
            }
            Err(e) => error!("failed to kill vcpu thread: {:?}", e),
        }
    }

    stdin_lock
        .set_canon_mode()
        .expect("failed to restore canonical mode for terminal");

    Ok(())
}
