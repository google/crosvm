// Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::collections::BTreeMap;
use std::convert::TryFrom;
use std::fs::{File, OpenOptions};
use std::net::Ipv4Addr;
use std::ops::RangeInclusive;
use std::os::unix::net::UnixListener;
use std::os::unix::{net::UnixStream, prelude::OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::str;
use std::sync::Arc;

use crate::{
    Config, DiskOption, TouchDeviceOption, VhostUserFsOption, VhostUserOption, VhostUserWlOption,
    VvuOption,
};
use anyhow::{anyhow, bail, Context, Result};
use arch::{self, VirtioDeviceStub};
use base::*;
use devices::serial_device::{SerialParameters, SerialType};
use devices::vfio::{VfioCommonSetup, VfioCommonTrait};
use devices::virtio::ipc_memory_mapper::{create_ipc_mapper, CreateIpcMapperRet};
use devices::virtio::memory_mapper::{BasicMemoryMapper, MemoryMapperTrait};
#[cfg(feature = "audio_cras")]
use devices::virtio::snd::cras_backend::Parameters as CrasSndParameters;
use devices::virtio::vfio_wrapper::VfioWrapper;
use devices::virtio::vhost::user::proxy::VirtioVhostUser;
#[cfg(feature = "audio")]
use devices::virtio::vhost::user::vmm::Snd as VhostUserSnd;
use devices::virtio::vhost::user::vmm::{
    Block as VhostUserBlock, Console as VhostUserConsole, Fs as VhostUserFs,
    Mac80211Hwsim as VhostUserMac80211Hwsim, Net as VhostUserNet, Vsock as VhostUserVsock,
    Wl as VhostUserWl,
};
use devices::virtio::vhost::vsock::VhostVsockConfig;
#[cfg(any(feature = "video-decoder", feature = "video-encoder"))]
use devices::virtio::VideoBackendType;
use devices::virtio::{self, BalloonMode, Console, VirtioDevice};
use devices::IommuDevType;
#[cfg(feature = "tpm")]
use devices::SoftwareTpm;
use devices::{
    self, BusDeviceObj, PciAddress, PciDevice, VfioDevice, VfioPciDevice, VfioPlatformDevice,
};
use hypervisor::Vm;
use minijail::{self, Minijail};
use net_util::{MacAddress, Tap, TapT};
use resources::{Alloc, MmioType, SystemAllocator};
use sync::Mutex;
use vm_memory::GuestAddress;

use super::jail_helpers::*;

pub enum TaggedControlTube {
    Fs(Tube),
    Vm(Tube),
    VmMemory(Tube),
    VmIrq(Tube),
    VmMsync(Tube),
}

impl AsRef<Tube> for TaggedControlTube {
    fn as_ref(&self) -> &Tube {
        use self::TaggedControlTube::*;
        match &self {
            Fs(tube) | Vm(tube) | VmMemory(tube) | VmIrq(tube) | VmMsync(tube) => tube,
        }
    }
}

impl AsRawDescriptor for TaggedControlTube {
    fn as_raw_descriptor(&self) -> RawDescriptor {
        self.as_ref().as_raw_descriptor()
    }
}

pub trait IntoUnixStream {
    fn into_unix_stream(self) -> Result<UnixStream>;
}

impl<'a> IntoUnixStream for &'a Path {
    fn into_unix_stream(self) -> Result<UnixStream> {
        if let Some(fd) = safe_descriptor_from_path(self).context("failed to open event device")? {
            Ok(fd.into())
        } else {
            UnixStream::connect(self).context("failed to open event device")
        }
    }
}

impl<'a> IntoUnixStream for &'a PathBuf {
    fn into_unix_stream(self) -> Result<UnixStream> {
        self.as_path().into_unix_stream()
    }
}

impl IntoUnixStream for UnixStream {
    fn into_unix_stream(self) -> Result<UnixStream> {
        Ok(self)
    }
}

pub type DeviceResult<T = VirtioDeviceStub> = Result<T>;

pub fn create_block_device(
    cfg: &Config,
    disk: &DiskOption,
    disk_device_tube: Tube,
) -> DeviceResult {
    let mut options = OpenOptions::new();
    options.read(true).write(!disk.read_only);

    #[cfg(unix)]
    if disk.o_direct {
        options.custom_flags(libc::O_DIRECT);
    }

    let raw_image: File = open_file(&disk.path, &options)
        .with_context(|| format!("failed to load disk image {}", disk.path.display()))?;
    // Lock the disk image to prevent other crosvm instances from using it.
    let lock_op = if disk.read_only {
        FlockOperation::LockShared
    } else {
        FlockOperation::LockExclusive
    };
    flock(&raw_image, lock_op, true).context("failed to lock disk image")?;

    info!("Trying to attach block device: {}", disk.path.display());
    let dev = if disk::async_ok(&raw_image).context("failed to check disk async_ok")? {
        let async_file = disk::create_async_disk_file(raw_image)
            .context("failed to create async virtual disk")?;
        Box::new(
            virtio::BlockAsync::new(
                virtio::base_features(cfg.protected_vm),
                async_file,
                disk.read_only,
                disk.sparse,
                disk.block_size,
                disk.id,
                Some(disk_device_tube),
            )
            .context("failed to create block device")?,
        ) as Box<dyn VirtioDevice>
    } else {
        let disk_file = disk::create_disk_file(raw_image, disk::MAX_NESTING_DEPTH, &disk.path)
            .context("failed to create virtual disk")?;
        Box::new(
            virtio::Block::new(
                virtio::base_features(cfg.protected_vm),
                disk_file,
                disk.read_only,
                disk.sparse,
                disk.block_size,
                disk.id,
                Some(disk_device_tube),
            )
            .context("failed to create block device")?,
        ) as Box<dyn VirtioDevice>
    };

    Ok(VirtioDeviceStub {
        dev,
        jail: simple_jail(&cfg.jail_config, "block_device")?,
    })
}

pub fn create_vhost_user_block_device(cfg: &Config, opt: &VhostUserOption) -> DeviceResult {
    let dev = VhostUserBlock::new(virtio::base_features(cfg.protected_vm), &opt.socket)
        .context("failed to set up vhost-user block device")?;

    Ok(VirtioDeviceStub {
        dev: Box::new(dev),
        // no sandbox here because virtqueue handling is exported to a different process.
        jail: None,
    })
}

pub fn create_vhost_user_console_device(cfg: &Config, opt: &VhostUserOption) -> DeviceResult {
    let dev = VhostUserConsole::new(virtio::base_features(cfg.protected_vm), &opt.socket)
        .context("failed to set up vhost-user console device")?;

    Ok(VirtioDeviceStub {
        dev: Box::new(dev),
        // no sandbox here because virtqueue handling is exported to a different process.
        jail: None,
    })
}

pub fn create_vhost_user_fs_device(cfg: &Config, option: &VhostUserFsOption) -> DeviceResult {
    let dev = VhostUserFs::new(
        virtio::base_features(cfg.protected_vm),
        &option.socket,
        &option.tag,
    )
    .context("failed to set up vhost-user fs device")?;

    Ok(VirtioDeviceStub {
        dev: Box::new(dev),
        // no sandbox here because virtqueue handling is exported to a different process.
        jail: None,
    })
}

pub fn create_vhost_user_mac80211_hwsim_device(
    cfg: &Config,
    opt: &VhostUserOption,
) -> DeviceResult {
    let dev = VhostUserMac80211Hwsim::new(virtio::base_features(cfg.protected_vm), &opt.socket)
        .context("failed to set up vhost-user mac80211_hwsim device")?;

    Ok(VirtioDeviceStub {
        dev: Box::new(dev),
        // no sandbox here because virtqueue handling is exported to a different process.
        jail: None,
    })
}

#[cfg(feature = "audio")]
pub fn create_vhost_user_snd_device(cfg: &Config, option: &VhostUserOption) -> DeviceResult {
    let dev = VhostUserSnd::new(virtio::base_features(cfg.protected_vm), &option.socket)
        .context("failed to set up vhost-user snd device")?;

    Ok(VirtioDeviceStub {
        dev: Box::new(dev),
        // no sandbox here because virtqueue handling is exported to a different process.
        jail: None,
    })
}

pub fn create_vvu_proxy_device(
    cfg: &Config,
    opt: &VvuOption,
    tube: Tube,
    max_sibling_mem_size: u64,
) -> DeviceResult {
    let listener = UnixListener::bind(&opt.socket).map_err(|e| {
        error!("failed to bind listener for vvu proxy device: {}", e);
        e
    })?;

    let dev = VirtioVhostUser::new(
        virtio::base_features(cfg.protected_vm),
        listener,
        tube,
        opt.addr,
        opt.uuid,
        max_sibling_mem_size,
    )
    .context("failed to create VVU proxy device")?;

    Ok(VirtioDeviceStub {
        dev: Box::new(dev),
        jail: simple_jail(&cfg.jail_config, "vvu_proxy_device")?,
    })
}

pub fn create_rng_device(cfg: &Config) -> DeviceResult {
    let dev = virtio::Rng::new(virtio::base_features(cfg.protected_vm))
        .context("failed to set up rng")?;

    Ok(VirtioDeviceStub {
        dev: Box::new(dev),
        jail: simple_jail(&cfg.jail_config, "rng_device")?,
    })
}

#[cfg(feature = "audio_cras")]
pub fn create_cras_snd_device(cfg: &Config, cras_snd: CrasSndParameters) -> DeviceResult {
    let dev = virtio::snd::cras_backend::VirtioSndCras::new(
        virtio::base_features(cfg.protected_vm),
        cras_snd,
    )
    .context("failed to create cras sound device")?;

    let jail = match simple_jail(&cfg.jail_config, "cras_snd_device")? {
        Some(mut jail) => {
            // Create a tmpfs in the device's root directory for cras_snd_device.
            // The size is 20*1024, or 20 KB.
            jail.mount_with_data(
                Path::new("none"),
                Path::new("/"),
                "tmpfs",
                (libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC) as usize,
                "size=20480",
            )?;

            let run_cras_path = Path::new("/run/cras");
            jail.mount_bind(run_cras_path, run_cras_path, true)?;

            add_current_user_to_jail(&mut jail)?;

            Some(jail)
        }
        None => None,
    };

    Ok(VirtioDeviceStub {
        dev: Box::new(dev),
        jail,
    })
}

#[cfg(feature = "tpm")]
pub fn create_software_tpm_device(cfg: &Config) -> DeviceResult {
    use std::ffi::CString;
    use std::fs;
    use std::process;

    let tpm_storage: PathBuf;
    let mut tpm_jail = simple_jail(&cfg.jail_config, "tpm_device")?;

    match &mut tpm_jail {
        Some(jail) => {
            // Create a tmpfs in the device's root directory for tpm
            // simulator storage. The size is 20*1024, or 20 KB.
            jail.mount_with_data(
                Path::new("none"),
                Path::new("/"),
                "tmpfs",
                (libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC) as usize,
                "size=20480",
            )?;

            let crosvm_ids = add_current_user_to_jail(jail)?;

            let pid = process::id();
            let tpm_pid_dir = format!("/run/vm/tpm.{}", pid);
            tpm_storage = Path::new(&tpm_pid_dir).to_owned();
            fs::create_dir_all(&tpm_storage).with_context(|| {
                format!("failed to create tpm storage dir {}", tpm_storage.display())
            })?;
            let tpm_pid_dir_c = CString::new(tpm_pid_dir).expect("no nul bytes");
            chown(&tpm_pid_dir_c, crosvm_ids.uid, crosvm_ids.gid)
                .context("failed to chown tpm storage")?;

            jail.mount_bind(&tpm_storage, &tpm_storage, true)?;
        }
        None => {
            // Path used inside cros_sdk which does not have /run/vm.
            tpm_storage = Path::new("/tmp/tpm-simulator").to_owned();
        }
    }

    let backend = SoftwareTpm::new(tpm_storage).context("failed to create SoftwareTpm")?;
    let dev = virtio::Tpm::new(Arc::new(Mutex::new(backend)));

    Ok(VirtioDeviceStub {
        dev: Box::new(dev),
        jail: tpm_jail,
    })
}

pub fn create_single_touch_device(
    cfg: &Config,
    single_touch_spec: &TouchDeviceOption,
    idx: u32,
) -> DeviceResult {
    let socket = single_touch_spec
        .get_path()
        .into_unix_stream()
        .map_err(|e| {
            error!("failed configuring virtio single touch: {:?}", e);
            e
        })?;

    let (width, height) = single_touch_spec.get_size();
    let dev = virtio::new_single_touch(
        idx,
        socket,
        width,
        height,
        virtio::base_features(cfg.protected_vm),
    )
    .context("failed to set up input device")?;
    Ok(VirtioDeviceStub {
        dev: Box::new(dev),
        jail: simple_jail(&cfg.jail_config, "input_device")?,
    })
}

pub fn create_multi_touch_device(
    cfg: &Config,
    multi_touch_spec: &TouchDeviceOption,
    idx: u32,
) -> DeviceResult {
    let socket = multi_touch_spec
        .get_path()
        .into_unix_stream()
        .map_err(|e| {
            error!("failed configuring virtio multi touch: {:?}", e);
            e
        })?;

    let (width, height) = multi_touch_spec.get_size();
    let dev = virtio::new_multi_touch(
        idx,
        socket,
        width,
        height,
        virtio::base_features(cfg.protected_vm),
    )
    .context("failed to set up input device")?;

    Ok(VirtioDeviceStub {
        dev: Box::new(dev),
        jail: simple_jail(&cfg.jail_config, "input_device")?,
    })
}

pub fn create_trackpad_device(
    cfg: &Config,
    trackpad_spec: &TouchDeviceOption,
    idx: u32,
) -> DeviceResult {
    let socket = trackpad_spec.get_path().into_unix_stream().map_err(|e| {
        error!("failed configuring virtio trackpad: {:#}", e);
        e
    })?;

    let (width, height) = trackpad_spec.get_size();
    let dev = virtio::new_trackpad(
        idx,
        socket,
        width,
        height,
        virtio::base_features(cfg.protected_vm),
    )
    .context("failed to set up input device")?;

    Ok(VirtioDeviceStub {
        dev: Box::new(dev),
        jail: simple_jail(&cfg.jail_config, "input_device")?,
    })
}

pub fn create_mouse_device<T: IntoUnixStream>(
    cfg: &Config,
    mouse_socket: T,
    idx: u32,
) -> DeviceResult {
    let socket = mouse_socket.into_unix_stream().map_err(|e| {
        error!("failed configuring virtio mouse: {:#}", e);
        e
    })?;

    let dev = virtio::new_mouse(idx, socket, virtio::base_features(cfg.protected_vm))
        .context("failed to set up input device")?;

    Ok(VirtioDeviceStub {
        dev: Box::new(dev),
        jail: simple_jail(&cfg.jail_config, "input_device")?,
    })
}

pub fn create_keyboard_device<T: IntoUnixStream>(
    cfg: &Config,
    keyboard_socket: T,
    idx: u32,
) -> DeviceResult {
    let socket = keyboard_socket.into_unix_stream().map_err(|e| {
        error!("failed configuring virtio keyboard: {:#}", e);
        e
    })?;

    let dev = virtio::new_keyboard(idx, socket, virtio::base_features(cfg.protected_vm))
        .context("failed to set up input device")?;

    Ok(VirtioDeviceStub {
        dev: Box::new(dev),
        jail: simple_jail(&cfg.jail_config, "input_device")?,
    })
}

pub fn create_switches_device<T: IntoUnixStream>(
    cfg: &Config,
    switches_socket: T,
    idx: u32,
) -> DeviceResult {
    let socket = switches_socket.into_unix_stream().map_err(|e| {
        error!("failed configuring virtio switches: {:#}", e);
        e
    })?;

    let dev = virtio::new_switches(idx, socket, virtio::base_features(cfg.protected_vm))
        .context("failed to set up input device")?;

    Ok(VirtioDeviceStub {
        dev: Box::new(dev),
        jail: simple_jail(&cfg.jail_config, "input_device")?,
    })
}

pub fn create_vinput_device(cfg: &Config, dev_path: &Path) -> DeviceResult {
    let dev_file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(dev_path)
        .with_context(|| format!("failed to open vinput device {}", dev_path.display()))?;

    let dev = virtio::new_evdev(dev_file, virtio::base_features(cfg.protected_vm))
        .context("failed to set up input device")?;

    Ok(VirtioDeviceStub {
        dev: Box::new(dev),
        jail: simple_jail(&cfg.jail_config, "input_device")?,
    })
}

pub fn create_balloon_device(
    cfg: &Config,
    tube: Tube,
    inflate_tube: Option<Tube>,
    init_balloon_size: u64,
) -> DeviceResult {
    let dev = virtio::Balloon::new(
        virtio::base_features(cfg.protected_vm),
        tube,
        inflate_tube,
        init_balloon_size,
        if cfg.strict_balloon {
            BalloonMode::Strict
        } else {
            BalloonMode::Relaxed
        },
    )
    .context("failed to create balloon")?;

    Ok(VirtioDeviceStub {
        dev: Box::new(dev),
        jail: simple_jail(&cfg.jail_config, "balloon_device")?,
    })
}

/// Generic method for creating a network device. `create_device` is a closure that takes the virtio
/// features and number of queue pairs as parameters, and is responsible for creating the device
/// itself.
pub fn create_net_device<F, T>(cfg: &Config, policy: &str, create_device: F) -> DeviceResult
where
    F: Fn(u64, u16) -> Result<T>,
    T: VirtioDevice + 'static,
{
    let mut vq_pairs = cfg.net_vq_pairs.unwrap_or(1);
    let vcpu_count = cfg.vcpu_count.unwrap_or(1);
    if vcpu_count < vq_pairs as usize {
        warn!("the number of net vq pairs must not exceed the vcpu count, falling back to single queue mode");
        vq_pairs = 1;
    }
    let features = virtio::base_features(cfg.protected_vm);

    let dev = create_device(features, vq_pairs)?;

    Ok(VirtioDeviceStub {
        dev: Box::new(dev) as Box<dyn VirtioDevice>,
        jail: simple_jail(&cfg.jail_config, policy)?,
    })
}

/// Returns a network device created from a new TAP interface configured with `host_ip`, `netmask`,
/// and `mac_address`.
pub fn create_net_device_from_config(
    cfg: &Config,
    host_ip: Ipv4Addr,
    netmask: Ipv4Addr,
    mac_address: MacAddress,
) -> DeviceResult {
    let policy = if cfg.vhost_net {
        "vhost_net_device"
    } else {
        "net_device"
    };

    if cfg.vhost_net {
        create_net_device(cfg, policy, |features, _vq_pairs| {
            virtio::vhost::Net::<Tap, vhost::Net<Tap>>::new(
                &cfg.vhost_net_device_path,
                features,
                host_ip,
                netmask,
                mac_address,
            )
            .context("failed to set up vhost networking")
        })
    } else {
        create_net_device(cfg, policy, |features, vq_pairs| {
            virtio::Net::<Tap>::new(features, host_ip, netmask, mac_address, vq_pairs)
                .context("failed to create virtio network device")
        })
    }
}

/// Returns a network device from a file descriptor to a configured TAP interface.
pub fn create_tap_net_device_from_fd(cfg: &Config, tap_fd: RawDescriptor) -> DeviceResult {
    create_net_device(cfg, "net_device", |features, vq_pairs| {
        // Safe because we ensure that we get a unique handle to the fd.
        let tap = unsafe {
            Tap::from_raw_descriptor(
                validate_raw_descriptor(tap_fd).context("failed to validate tap descriptor")?,
            )
            .context("failed to create tap device")?
        };

        virtio::Net::from(features, tap, vq_pairs).context("failed to create tap net device")
    })
}

/// Returns a network device created by opening the persistent, configured TAP interface `tap_name`.
pub fn create_tap_net_device_from_name(cfg: &Config, tap_name: &[u8]) -> DeviceResult {
    create_net_device(cfg, "net_device", |features, vq_pairs| {
        virtio::Net::<Tap>::new_from_name(features, tap_name, vq_pairs)
            .context("failed to create configured virtio network device")
    })
}

pub fn create_vhost_user_net_device(cfg: &Config, opt: &VhostUserOption) -> DeviceResult {
    let dev = VhostUserNet::new(virtio::base_features(cfg.protected_vm), &opt.socket)
        .context("failed to set up vhost-user net device")?;

    Ok(VirtioDeviceStub {
        dev: Box::new(dev),
        // no sandbox here because virtqueue handling is exported to a different process.
        jail: None,
    })
}

pub fn create_vhost_user_vsock_device(cfg: &Config, opt: &VhostUserOption) -> DeviceResult {
    let dev = VhostUserVsock::new(virtio::base_features(cfg.protected_vm), &opt.socket)
        .context("failed to set up vhost-user vsock device")?;

    Ok(VirtioDeviceStub {
        dev: Box::new(dev),
        // no sandbox here because virtqueue handling is exported to a different process.
        jail: None,
    })
}

pub fn create_vhost_user_wl_device(cfg: &Config, opt: &VhostUserWlOption) -> DeviceResult {
    // The crosvm wl device expects us to connect the tube before it will accept a vhost-user
    // connection.
    let dev = VhostUserWl::new(virtio::base_features(cfg.protected_vm), &opt.socket)
        .context("failed to set up vhost-user wl device")?;

    Ok(VirtioDeviceStub {
        dev: Box::new(dev),
        // no sandbox here because virtqueue handling is exported to a different process.
        jail: None,
    })
}

pub fn create_wayland_device(
    cfg: &Config,
    control_tube: Tube,
    resource_bridge: Option<Tube>,
) -> DeviceResult {
    let wayland_socket_dirs = cfg
        .wayland_socket_paths
        .iter()
        .map(|(_name, path)| path.parent())
        .collect::<Option<Vec<_>>>()
        .ok_or_else(|| anyhow!("wayland socket path has no parent or file name"))?;

    let features = virtio::base_features(cfg.protected_vm);
    let dev = virtio::Wl::new(
        features,
        cfg.wayland_socket_paths.clone(),
        control_tube,
        resource_bridge,
    )
    .context("failed to create wayland device")?;

    let jail = match simple_jail(&cfg.jail_config, "wl_device")? {
        Some(mut jail) => {
            // Create a tmpfs in the device's root directory so that we can bind mount the wayland
            // socket directory into it. The size=67108864 is size=64*1024*1024 or size=64MB.
            jail.mount_with_data(
                Path::new("none"),
                Path::new("/"),
                "tmpfs",
                (libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC) as usize,
                "size=67108864",
            )?;

            // Bind mount the wayland socket's directory into jail's root. This is necessary since
            // each new wayland context must open() the socket. If the wayland socket is ever
            // destroyed and remade in the same host directory, new connections will be possible
            // without restarting the wayland device.
            for dir in &wayland_socket_dirs {
                jail.mount_bind(dir, dir, true)?;
            }
            add_current_user_to_jail(&mut jail)?;

            Some(jail)
        }
        None => None,
    };

    Ok(VirtioDeviceStub {
        dev: Box::new(dev),
        jail,
    })
}

#[cfg(any(feature = "video-decoder", feature = "video-encoder"))]
pub fn create_video_device(
    backend: VideoBackendType,
    cfg: &Config,
    typ: devices::virtio::VideoDeviceType,
    resource_bridge: Tube,
) -> DeviceResult {
    let jail = match simple_jail(&cfg.jail_config, "video_device")? {
        Some(mut jail) => {
            match typ {
                #[cfg(feature = "video-decoder")]
                devices::virtio::VideoDeviceType::Decoder => add_current_user_to_jail(&mut jail)?,
                #[cfg(feature = "video-encoder")]
                devices::virtio::VideoDeviceType::Encoder => add_current_user_to_jail(&mut jail)?,
            };

            // Create a tmpfs in the device's root directory so that we can bind mount files.
            jail.mount_with_data(
                Path::new("none"),
                Path::new("/"),
                "tmpfs",
                (libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC) as usize,
                "size=67108864",
            )?;

            #[cfg(feature = "libvda")]
            // Render node for libvda.
            if backend == VideoBackendType::Libvda || backend == VideoBackendType::LibvdaVd {
                // follow the implementation at:
                // https://chromium.googlesource.com/chromiumos/platform/minigbm/+/c06cc9cccb3cf3c7f9d2aec706c27c34cd6162a0/cros_gralloc/cros_gralloc_driver.cc#90
                const DRM_NUM_NODES: u32 = 63;
                const DRM_RENDER_NODE_START: u32 = 128;
                for offset in 0..DRM_NUM_NODES {
                    let path_str = format!("/dev/dri/renderD{}", DRM_RENDER_NODE_START + offset);
                    let dev_dri_path = Path::new(&path_str);
                    if !dev_dri_path.exists() {
                        break;
                    }
                    jail.mount_bind(dev_dri_path, dev_dri_path, false)?;
                }
            }

            #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
            {
                // Device nodes used by libdrm through minigbm in libvda on AMD devices.
                let sys_dev_char_path = Path::new("/sys/dev/char");
                jail.mount_bind(sys_dev_char_path, sys_dev_char_path, false)?;
                let sys_devices_path = Path::new("/sys/devices");
                jail.mount_bind(sys_devices_path, sys_devices_path, false)?;

                // Required for loading dri libraries loaded by minigbm on AMD devices.
                jail_mount_bind_if_exists(&mut jail, &["/usr/lib64"])?;
            }

            // Device nodes required by libchrome which establishes Mojo connection in libvda.
            let dev_urandom_path = Path::new("/dev/urandom");
            jail.mount_bind(dev_urandom_path, dev_urandom_path, false)?;
            let system_bus_socket_path = Path::new("/run/dbus/system_bus_socket");
            jail.mount_bind(system_bus_socket_path, system_bus_socket_path, true)?;

            Some(jail)
        }
        None => None,
    };

    Ok(VirtioDeviceStub {
        dev: Box::new(devices::virtio::VideoDevice::new(
            virtio::base_features(cfg.protected_vm),
            typ,
            backend,
            Some(resource_bridge),
        )),
        jail,
    })
}

#[cfg(any(feature = "video-decoder", feature = "video-encoder"))]
pub fn register_video_device(
    backend: VideoBackendType,
    devs: &mut Vec<VirtioDeviceStub>,
    video_tube: Tube,
    cfg: &Config,
    typ: devices::virtio::VideoDeviceType,
) -> Result<()> {
    devs.push(create_video_device(backend, cfg, typ, video_tube)?);
    Ok(())
}

pub fn create_vhost_vsock_device(cfg: &Config, vhost_config: &VhostVsockConfig) -> DeviceResult {
    let features = virtio::base_features(cfg.protected_vm);

    let dev = virtio::vhost::Vsock::new(features, vhost_config)
        .context("failed to set up virtual socket device")?;

    Ok(VirtioDeviceStub {
        dev: Box::new(dev),
        jail: simple_jail(&cfg.jail_config, "vhost_vsock_device")?,
    })
}

pub fn create_fs_device(
    cfg: &Config,
    uid_map: &str,
    gid_map: &str,
    src: &Path,
    tag: &str,
    fs_cfg: virtio::fs::passthrough::Config,
    device_tube: Tube,
) -> DeviceResult {
    let max_open_files =
        base::get_max_open_files().context("failed to get max number of open files")?;
    let j = if let Some(jail_config) = &cfg.jail_config {
        let seccomp_policy = jail_config.seccomp_policy_dir.join("fs_device");
        let config = SandboxConfig {
            limit_caps: false,
            uid_map: Some(uid_map),
            gid_map: Some(gid_map),
            log_failures: jail_config.seccomp_log_failures,
            seccomp_policy: &seccomp_policy,
            // We want bind mounts from the parent namespaces to propagate into the fs device's
            // namespace.
            remount_mode: Some(libc::MS_SLAVE),
        };
        create_base_minijail(src, Some(max_open_files), Some(&config))?
    } else {
        create_base_minijail(src, Some(max_open_files), None)?
    };

    let features = virtio::base_features(cfg.protected_vm);
    // TODO(chirantan): Use more than one worker once the kernel driver has been fixed to not panic
    // when num_queues > 1.
    let dev = virtio::fs::Fs::new(features, tag, 1, fs_cfg, device_tube)
        .context("failed to create fs device")?;

    Ok(VirtioDeviceStub {
        dev: Box::new(dev),
        jail: Some(j),
    })
}

pub fn create_9p_device(
    cfg: &Config,
    uid_map: &str,
    gid_map: &str,
    src: &Path,
    tag: &str,
    mut p9_cfg: p9::Config,
) -> DeviceResult {
    let max_open_files =
        base::get_max_open_files().context("failed to get max number of open files")?;
    let (jail, root) = if let Some(jail_config) = &cfg.jail_config {
        let seccomp_policy = jail_config.seccomp_policy_dir.join("9p_device");
        let config = SandboxConfig {
            limit_caps: false,
            uid_map: Some(uid_map),
            gid_map: Some(gid_map),
            log_failures: jail_config.seccomp_log_failures,
            seccomp_policy: &seccomp_policy,
            // We want bind mounts from the parent namespaces to propagate into the 9p server's
            // namespace.
            remount_mode: Some(libc::MS_SLAVE),
        };

        let jail = create_base_minijail(src, Some(max_open_files), Some(&config))?;

        //  The shared directory becomes the root of the device's file system.
        let root = Path::new("/");
        (Some(jail), root)
    } else {
        // There's no mount namespace so we tell the server to treat the source directory as the
        // root.
        (None, src)
    };

    let features = virtio::base_features(cfg.protected_vm);
    p9_cfg.root = root.into();
    let dev = virtio::P9::new(features, tag, p9_cfg).context("failed to create 9p device")?;

    Ok(VirtioDeviceStub {
        dev: Box::new(dev),
        jail,
    })
}

pub fn create_pmem_device(
    cfg: &Config,
    vm: &mut impl Vm,
    resources: &mut SystemAllocator,
    disk: &DiskOption,
    index: usize,
    pmem_device_tube: Tube,
) -> DeviceResult {
    let fd = open_file(
        &disk.path,
        OpenOptions::new().read(true).write(!disk.read_only),
    )
    .with_context(|| format!("failed to load disk image {}", disk.path.display()))?;

    let (disk_size, arena_size) = {
        let metadata = std::fs::metadata(&disk.path).with_context(|| {
            format!("failed to get disk image {} metadata", disk.path.display())
        })?;
        let disk_len = metadata.len();
        // Linux requires pmem region sizes to be 2 MiB aligned. Linux will fill any partial page
        // at the end of an mmap'd file and won't write back beyond the actual file length, but if
        // we just align the size of the file to 2 MiB then access beyond the last page of the
        // mapped file will generate SIGBUS. So use a memory mapping arena that will provide
        // padding up to 2 MiB.
        let alignment = 2 * 1024 * 1024;
        let align_adjust = if disk_len % alignment != 0 {
            alignment - (disk_len % alignment)
        } else {
            0
        };
        (
            disk_len,
            disk_len
                .checked_add(align_adjust)
                .ok_or_else(|| anyhow!("pmem device image too big"))?,
        )
    };

    let protection = {
        if disk.read_only {
            Protection::read()
        } else {
            Protection::read_write()
        }
    };

    let arena = {
        // Conversion from u64 to usize may fail on 32bit system.
        let arena_size = usize::try_from(arena_size).context("pmem device image too big")?;
        let disk_size = usize::try_from(disk_size).context("pmem device image too big")?;

        let mut arena =
            MemoryMappingArena::new(arena_size).context("failed to reserve pmem memory")?;
        arena
            .add_fd_offset_protection(0, disk_size, &fd, 0, protection)
            .context("failed to reserve pmem memory")?;

        // If the disk is not a multiple of the page size, the OS will fill the remaining part
        // of the page with zeroes. However, the anonymous mapping added below must start on a
        // page boundary, so round up the size before calculating the offset of the anon region.
        let disk_size = round_up_to_page_size(disk_size);

        if arena_size > disk_size {
            // Add an anonymous region with the same protection as the disk mapping if the arena
            // size was aligned.
            arena
                .add_anon_protection(disk_size, arena_size - disk_size, protection)
                .context("failed to reserve pmem padding")?;
        }
        arena
    };

    let mapping_address = resources
        .mmio_allocator(MmioType::High)
        .reverse_allocate_with_align(
            arena_size,
            Alloc::PmemDevice(index),
            format!("pmem_disk_image_{}", index),
            // Linux kernel requires pmem namespaces to be 128 MiB aligned.
            128 * 1024 * 1024, /* 128 MiB */
        )
        .context("failed to allocate memory for pmem device")?;

    let slot = vm
        .add_memory_region(
            GuestAddress(mapping_address),
            Box::new(arena),
            /* read_only = */ disk.read_only,
            /* log_dirty_pages = */ false,
        )
        .context("failed to add pmem device memory")?;

    let dev = virtio::Pmem::new(
        virtio::base_features(cfg.protected_vm),
        fd,
        GuestAddress(mapping_address),
        slot,
        arena_size,
        Some(pmem_device_tube),
    )
    .context("failed to create pmem device")?;

    Ok(VirtioDeviceStub {
        dev: Box::new(dev) as Box<dyn VirtioDevice>,
        jail: simple_jail(&cfg.jail_config, "pmem_device")?,
    })
}

pub fn create_iommu_device(
    cfg: &Config,
    phys_max_addr: u64,
    endpoints: BTreeMap<u32, Arc<Mutex<Box<dyn MemoryMapperTrait>>>>,
    hp_endpoints_ranges: Vec<RangeInclusive<u32>>,
    translate_response_senders: Option<BTreeMap<u32, Tube>>,
    translate_request_rx: Option<Tube>,
    iommu_device_tube: Tube,
) -> DeviceResult {
    let dev = virtio::Iommu::new(
        virtio::base_features(cfg.protected_vm),
        endpoints,
        phys_max_addr,
        hp_endpoints_ranges,
        translate_response_senders,
        translate_request_rx,
        Some(iommu_device_tube),
    )
    .context("failed to create IOMMU device")?;

    Ok(VirtioDeviceStub {
        dev: Box::new(dev),
        jail: simple_jail(&cfg.jail_config, "iommu_device")?,
    })
}

fn add_bind_mounts(param: &SerialParameters, jail: &mut Minijail) -> Result<(), minijail::Error> {
    if let Some(path) = &param.path {
        if let SerialType::SystemSerialType = param.type_ {
            if let Some(parent) = path.as_path().parent() {
                if parent.exists() {
                    info!("Bind mounting dir {}", parent.display());
                    jail.mount_bind(parent, parent, true)?;
                }
            }
        }
    }
    Ok(())
}

pub fn create_console_device(cfg: &Config, param: &SerialParameters) -> DeviceResult {
    let mut keep_rds = Vec::new();
    let evt = Event::new().context("failed to create event")?;
    let dev = param
        .create_serial_device::<Console>(cfg.protected_vm, &evt, &mut keep_rds)
        .context("failed to create console device")?;

    let jail = match simple_jail(&cfg.jail_config, "serial")? {
        Some(mut jail) => {
            // Create a tmpfs in the device's root directory so that we can bind mount the
            // log socket directory into it.
            // The size=67108864 is size=64*1024*1024 or size=64MB.
            jail.mount_with_data(
                Path::new("none"),
                Path::new("/"),
                "tmpfs",
                (libc::MS_NODEV | libc::MS_NOEXEC | libc::MS_NOSUID) as usize,
                "size=67108864",
            )?;
            add_current_user_to_jail(&mut jail)?;
            let res = add_bind_mounts(param, &mut jail);
            if res.is_err() {
                error!("failed to add bind mounts for console device");
            }
            Some(jail)
        }
        None => None,
    };

    Ok(VirtioDeviceStub {
        dev: Box::new(dev),
        jail, // TODO(dverkamp): use a separate policy for console?
    })
}

#[cfg(feature = "audio")]
pub fn create_sound_device(path: &Path, cfg: &Config) -> DeviceResult {
    let dev = virtio::new_sound(path, virtio::base_features(cfg.protected_vm))
        .context("failed to create sound device")?;

    Ok(VirtioDeviceStub {
        dev: Box::new(dev),
        jail: simple_jail(&cfg.jail_config, "vios_audio_device")?,
    })
}

pub fn create_vfio_device(
    cfg: &Config,
    vm: &impl Vm,
    resources: &mut SystemAllocator,
    control_tubes: &mut Vec<TaggedControlTube>,
    vfio_path: &Path,
    bus_num: Option<u8>,
    guest_address: Option<PciAddress>,
    iommu_endpoints: &mut BTreeMap<u32, Arc<Mutex<Box<dyn MemoryMapperTrait>>>>,
    coiommu_endpoints: Option<&mut Vec<u16>>,
    iommu_dev: IommuDevType,
) -> DeviceResult<(Box<VfioPciDevice>, Option<Minijail>)> {
    let vfio_container = VfioCommonSetup::vfio_get_container(iommu_dev, Some(vfio_path))
        .context("failed to get vfio container")?;

    // create MSI, MSI-X, and Mem request sockets for each vfio device
    let (vfio_host_tube_msi, vfio_device_tube_msi) =
        Tube::pair().context("failed to create tube")?;
    control_tubes.push(TaggedControlTube::VmIrq(vfio_host_tube_msi));

    let (vfio_host_tube_msix, vfio_device_tube_msix) =
        Tube::pair().context("failed to create tube")?;
    control_tubes.push(TaggedControlTube::VmIrq(vfio_host_tube_msix));

    let (vfio_host_tube_mem, vfio_device_tube_mem) =
        Tube::pair().context("failed to create tube")?;
    control_tubes.push(TaggedControlTube::VmMemory(vfio_host_tube_mem));

    let hotplug = bus_num.is_some();
    let vfio_device_tube_vm = if hotplug {
        let (vfio_host_tube_vm, device_tube_vm) = Tube::pair().context("failed to create tube")?;
        control_tubes.push(TaggedControlTube::Vm(vfio_host_tube_vm));
        Some(device_tube_vm)
    } else {
        None
    };

    let vfio_device = VfioDevice::new_passthrough(
        &vfio_path,
        vm,
        vfio_container.clone(),
        iommu_dev != IommuDevType::NoIommu,
    )
    .context("failed to create vfio device")?;
    let mut vfio_pci_device = Box::new(VfioPciDevice::new(
        #[cfg(feature = "direct")]
        vfio_path,
        vfio_device,
        bus_num,
        guest_address,
        vfio_device_tube_msi,
        vfio_device_tube_msix,
        vfio_device_tube_mem,
        vfio_device_tube_vm,
    ));
    // early reservation for pass-through PCI devices.
    let endpoint_addr = vfio_pci_device
        .allocate_address(resources)
        .context("failed to allocate resources early for vfio pci dev")?;

    match iommu_dev {
        IommuDevType::NoIommu => {}
        IommuDevType::VirtioIommu => {
            iommu_endpoints.insert(
                endpoint_addr.to_u32(),
                Arc::new(Mutex::new(Box::new(VfioWrapper::new(
                    vfio_container,
                    vm.get_memory().clone(),
                )))),
            );
        }
        IommuDevType::CoIommu => {
            if let Some(endpoints) = coiommu_endpoints {
                endpoints.push(endpoint_addr.to_u32() as u16);
            } else {
                bail!("Missed coiommu_endpoints vector to store the endpoint addr");
            }
        }
    }

    if hotplug {
        Ok((vfio_pci_device, None))
    } else {
        Ok((
            vfio_pci_device,
            simple_jail(&cfg.jail_config, "vfio_device")?,
        ))
    }
}

pub fn create_vfio_platform_device(
    cfg: &Config,
    vm: &impl Vm,
    _resources: &mut SystemAllocator,
    control_tubes: &mut Vec<TaggedControlTube>,
    vfio_path: &Path,
    _endpoints: &mut BTreeMap<u32, Arc<Mutex<Box<dyn MemoryMapperTrait>>>>,
    iommu_dev: IommuDevType,
) -> DeviceResult<(VfioPlatformDevice, Option<Minijail>)> {
    let vfio_container = VfioCommonSetup::vfio_get_container(iommu_dev, Some(vfio_path))
        .context("Failed to create vfio device")?;

    let (vfio_host_tube_mem, vfio_device_tube_mem) =
        Tube::pair().context("failed to create tube")?;
    control_tubes.push(TaggedControlTube::VmMemory(vfio_host_tube_mem));

    let vfio_device = VfioDevice::new_passthrough(
        &vfio_path,
        vm,
        vfio_container,
        iommu_dev != IommuDevType::NoIommu,
    )
    .context("Failed to create vfio device")?;
    let vfio_plat_dev = VfioPlatformDevice::new(vfio_device, vfio_device_tube_mem);

    Ok((
        vfio_plat_dev,
        simple_jail(&cfg.jail_config, "vfio_platform_device")?,
    ))
}

/// Setup for devices with VIRTIO_F_ACCESS_PLATFORM
pub fn setup_virtio_access_platform(
    resources: &mut SystemAllocator,
    iommu_attached_endpoints: &mut BTreeMap<u32, Arc<Mutex<Box<dyn MemoryMapperTrait>>>>,
    devices: &mut [(Box<dyn BusDeviceObj>, Option<Minijail>)],
) -> DeviceResult<(Option<BTreeMap<u32, Tube>>, Option<Tube>)> {
    let mut translate_response_senders: Option<
        BTreeMap<
            u32, // endpoint id
            Tube,
        >,
    > = None;
    let mut tube_pair: Option<(Tube, Tube)> = None;

    for dev in devices.iter_mut() {
        if let Some(pci_dev) = dev.0.as_pci_device_mut() {
            if pci_dev.supports_iommu() {
                let endpoint_id = pci_dev
                    .allocate_address(resources)
                    .context("failed to allocate resources for pci dev")?
                    .to_u32();
                let mapper: Arc<Mutex<Box<dyn MemoryMapperTrait>>> =
                    Arc::new(Mutex::new(Box::new(BasicMemoryMapper::new(u64::MAX))));
                let (request_tx, _request_rx) =
                    tube_pair.get_or_insert_with(|| Tube::pair().unwrap());
                let CreateIpcMapperRet {
                    mapper: ipc_mapper,
                    response_tx,
                } = create_ipc_mapper(
                    endpoint_id,
                    #[allow(deprecated)]
                    request_tx.try_clone()?,
                );
                translate_response_senders
                    .get_or_insert_with(BTreeMap::new)
                    .insert(endpoint_id, response_tx);
                iommu_attached_endpoints.insert(endpoint_id, mapper);
                pci_dev.set_iommu(ipc_mapper)?;
            }
        }
    }

    Ok((
        translate_response_senders,
        tube_pair.map(|(_request_tx, request_rx)| request_rx),
    ))
}
