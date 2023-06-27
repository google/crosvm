// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::collections::BTreeMap;
use std::convert::TryFrom;
use std::fs::OpenOptions;
use std::ops::RangeInclusive;
use std::os::unix::net::UnixListener;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::path::PathBuf;
use std::str;
use std::sync::Arc;

use anyhow::anyhow;
use anyhow::bail;
use anyhow::Context;
use anyhow::Result;
use arch::VirtioDeviceStub;
use base::ReadNotifier;
use base::*;
use devices::serial_device::SerialHardware;
use devices::serial_device::SerialParameters;
use devices::serial_device::SerialType;
use devices::vfio::VfioCommonSetup;
use devices::vfio::VfioCommonTrait;
use devices::virtio;
use devices::virtio::block::DiskOption;
use devices::virtio::console::asynchronous::AsyncConsole;
#[cfg(any(feature = "video-decoder", feature = "video-encoder"))]
use devices::virtio::device_constants::video::VideoBackendType;
use devices::virtio::device_constants::video::VideoDeviceType;
use devices::virtio::ipc_memory_mapper::create_ipc_mapper;
use devices::virtio::ipc_memory_mapper::CreateIpcMapperRet;
use devices::virtio::memory_mapper::BasicMemoryMapper;
use devices::virtio::memory_mapper::MemoryMapperTrait;
#[cfg(feature = "audio")]
use devices::virtio::snd::parameters::Parameters as SndParameters;
use devices::virtio::vfio_wrapper::VfioWrapper;
use devices::virtio::vhost::user::proxy::VirtioVhostUser;
use devices::virtio::vhost::user::vmm::VhostUserVirtioDevice;
use devices::virtio::vhost::user::NetBackend;
use devices::virtio::vhost::user::VhostUserDevice;
use devices::virtio::vhost::user::VhostUserVsockDevice;
use devices::virtio::vsock::VsockConfig;
#[cfg(feature = "balloon")]
use devices::virtio::BalloonMode;
use devices::virtio::Console;
use devices::virtio::NetError;
use devices::virtio::NetParameters;
use devices::virtio::NetParametersMode;
use devices::virtio::VirtioDevice;
use devices::virtio::VirtioDeviceType;
use devices::BusDeviceObj;
use devices::IommuDevType;
use devices::PciAddress;
use devices::PciDevice;
#[cfg(feature = "tpm")]
use devices::SoftwareTpm;
use devices::VfioDevice;
use devices::VfioDeviceType;
use devices::VfioPciDevice;
use devices::VfioPlatformDevice;
#[cfg(all(feature = "vtpm", target_arch = "x86_64"))]
use devices::VtpmProxy;
use hypervisor::ProtectionType;
use hypervisor::Vm;
use jail::*;
use minijail::Minijail;
use net_util::sys::unix::Tap;
use net_util::MacAddress;
use net_util::TapTCommon;
use resources::Alloc;
use resources::AllocOptions;
use resources::SystemAllocator;
use sync::Mutex;
use vm_control::api::VmMemoryClient;
use vm_memory::GuestAddress;

use crate::crosvm::config::TouchDeviceOption;
use crate::crosvm::config::VhostUserFsOption;
use crate::crosvm::config::VhostUserOption;
use crate::crosvm::config::VvuOption;

pub enum TaggedControlTube {
    Fs(Tube),
    Vm(Tube),
    VmMsync(Tube),
}

impl AsRef<Tube> for TaggedControlTube {
    fn as_ref(&self) -> &Tube {
        use self::TaggedControlTube::*;
        match &self {
            Fs(tube) | Vm(tube) | VmMsync(tube) => tube,
        }
    }
}

impl AsRawDescriptor for TaggedControlTube {
    fn as_raw_descriptor(&self) -> RawDescriptor {
        self.as_ref().as_raw_descriptor()
    }
}

impl ReadNotifier for TaggedControlTube {
    fn get_read_notifier(&self) -> &dyn AsRawDescriptor {
        self.as_ref().get_read_notifier()
    }
}

#[derive(serde::Serialize, serde::Deserialize)]
pub struct VmMemoryTube {
    pub tube: Tube,
    /// See devices::virtio::VirtioDevice.expose_shared_memory_region_with_viommu
    pub expose_with_viommu: bool,
}

impl AsRef<Tube> for VmMemoryTube {
    fn as_ref(&self) -> &Tube {
        &self.tube
    }
}

impl AsRawDescriptor for VmMemoryTube {
    fn as_raw_descriptor(&self) -> RawDescriptor {
        self.as_ref().as_raw_descriptor()
    }
}

impl ReadNotifier for VmMemoryTube {
    fn get_read_notifier(&self) -> &dyn AsRawDescriptor {
        self.as_ref().get_read_notifier()
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

/// A trait for spawning virtio device instances and jails from their configuration structure.
///
/// Implementors become able to create virtio devices and jails following their own configuration.
/// This trait also provides a few convenience methods for e.g. creating a virtio device and jail
/// at once.
pub trait VirtioDeviceBuilder: Sized {
    /// Base name of the device, as it will appear in logs.
    const NAME: &'static str;

    /// Create a regular virtio device from the configuration and `protection_type` setting.
    fn create_virtio_device(
        self,
        protection_type: ProtectionType,
    ) -> anyhow::Result<Box<dyn VirtioDevice>>;

    /// Create a device suitable for being run as a vhost-user instance.
    ///
    /// It is ok to leave this method unimplemented if the device is not intended to be used with
    /// vhost-user.
    fn create_vhost_user_device(
        self,
        _keep_rds: &mut Vec<RawDescriptor>,
    ) -> anyhow::Result<Box<dyn VhostUserDevice>> {
        unimplemented!()
    }

    /// Create a jail that is suitable to run a device.
    ///
    /// The default implementation creates a simple jail with a seccomp policy derived from the
    /// base name of the device.
    fn create_jail(
        &self,
        jail_config: &Option<JailConfig>,
        virtio_transport: VirtioDeviceType,
    ) -> anyhow::Result<Option<Minijail>> {
        simple_jail(
            jail_config,
            &virtio_transport.seccomp_policy_file(Self::NAME),
        )
    }

    /// Helper method to return a `VirtioDeviceStub` filled using `create_virtio_device` and
    /// `create_jail`.
    ///
    /// This helper should cover the needs of most devices when run as regular virtio devices.
    fn create_virtio_device_and_jail(
        self,
        protection_type: ProtectionType,
        jail_config: &Option<JailConfig>,
    ) -> DeviceResult {
        let jail = self.create_jail(jail_config, VirtioDeviceType::Regular)?;
        let dev = self.create_virtio_device(protection_type)?;
        Ok(VirtioDeviceStub { dev, jail })
    }
}

/// A one-shot configuration structure for implementing `VirtioDeviceBuilder`. We cannot do it on
/// `DiskOption` directly because disk devices can be passed an optional control tube.
pub struct DiskConfig<'a> {
    /// Options for disk creation.
    disk: &'a DiskOption,
    /// Optional control tube for the device.
    device_tube: Option<Tube>,
}

impl<'a> DiskConfig<'a> {
    pub fn new(disk: &'a DiskOption, device_tube: Option<Tube>) -> Self {
        Self { disk, device_tube }
    }
}

impl<'a> VirtioDeviceBuilder for DiskConfig<'a> {
    const NAME: &'static str = "block";

    fn create_virtio_device(
        self,
        protection_type: ProtectionType,
    ) -> anyhow::Result<Box<dyn VirtioDevice>> {
        info!(
            "Trying to attach block device: {}",
            self.disk.path.display(),
        );
        let disk_image = self.disk.open()?;
        let base_features = virtio::base_features(protection_type);
        Ok(Box::new(
            virtio::BlockAsync::new(
                base_features,
                disk_image,
                self.disk.read_only,
                self.disk.sparse,
                self.disk.packed_queue,
                self.disk.block_size,
                self.disk.multiple_workers,
                self.disk.id,
                self.device_tube,
                None,
                self.disk.async_executor,
                None,
            )
            .context("failed to create block device")?,
        ))
    }

    fn create_vhost_user_device(
        self,
        keep_rds: &mut Vec<RawDescriptor>,
    ) -> anyhow::Result<Box<dyn VhostUserDevice>> {
        let disk = self.disk;
        let disk_image = disk.open()?;
        let base_features = virtio::base_features(ProtectionType::Unprotected);

        let block = Box::new(
            virtio::BlockAsync::new(
                base_features,
                disk_image,
                disk.read_only,
                disk.sparse,
                disk.packed_queue,
                disk.block_size,
                false,
                disk.id,
                self.device_tube,
                None,
                disk.async_executor,
                None,
            )
            .context("failed to create block device")?,
        );
        keep_rds.extend(block.keep_rds());

        Ok(block)
    }
}

fn vhost_user_connection(path: &Path) -> Result<UnixStream> {
    UnixStream::connect(path).with_context(|| {
        format!(
            "failed to connect to vhost-user socket path {}",
            path.display()
        )
    })
}

pub fn create_vhost_user_block_device(
    protection_type: ProtectionType,
    opt: &VhostUserOption,
) -> DeviceResult {
    let dev = VhostUserVirtioDevice::new_block(
        virtio::base_features(protection_type),
        vhost_user_connection(&opt.socket)?,
    )
    .context("failed to set up vhost-user block device")?;

    Ok(VirtioDeviceStub {
        dev: Box::new(dev),
        // no sandbox here because virtqueue handling is exported to a different process.
        jail: None,
    })
}

pub fn create_vhost_user_console_device(
    protection_type: ProtectionType,
    opt: &VhostUserOption,
) -> DeviceResult {
    let dev = VhostUserVirtioDevice::new_console(
        virtio::base_features(protection_type),
        vhost_user_connection(&opt.socket)?,
    )
    .context("failed to set up vhost-user console device")?;

    Ok(VirtioDeviceStub {
        dev: Box::new(dev),
        // no sandbox here because virtqueue handling is exported to a different process.
        jail: None,
    })
}

pub fn create_vhost_user_fs_device(
    protection_type: ProtectionType,
    option: &VhostUserFsOption,
) -> DeviceResult {
    let dev = VhostUserVirtioDevice::new_fs(
        virtio::base_features(protection_type),
        vhost_user_connection(&option.socket)?,
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
    protection_type: ProtectionType,
    opt: &VhostUserOption,
) -> DeviceResult {
    let dev = VhostUserVirtioDevice::new_mac80211_hwsim(
        virtio::base_features(protection_type),
        vhost_user_connection(&opt.socket)?,
    )
    .context("failed to set up vhost-user mac80211_hwsim device")?;

    Ok(VirtioDeviceStub {
        dev: Box::new(dev),
        // no sandbox here because virtqueue handling is exported to a different process.
        jail: None,
    })
}

pub fn create_vhost_user_snd_device(
    protection_type: ProtectionType,
    option: &VhostUserOption,
) -> DeviceResult {
    let dev = VhostUserVirtioDevice::new_snd(
        virtio::base_features(protection_type),
        vhost_user_connection(&option.socket)?,
    )
    .context("failed to set up vhost-user snd device")?;

    Ok(VirtioDeviceStub {
        dev: Box::new(dev),
        // no sandbox here because virtqueue handling is exported to a different process.
        jail: None,
    })
}

pub fn create_vhost_user_gpu_device(
    protection_type: ProtectionType,
    opt: &VhostUserOption,
) -> DeviceResult {
    // The crosvm gpu device expects us to connect the tube before it will accept a vhost-user
    // connection.
    let dev = VhostUserVirtioDevice::new_gpu(
        virtio::base_features(protection_type),
        vhost_user_connection(&opt.socket)?,
    )
    .context("failed to set up vhost-user gpu device")?;

    Ok(VirtioDeviceStub {
        dev: Box::new(dev),
        // no sandbox here because virtqueue handling is exported to a different process.
        jail: None,
    })
}

pub fn create_vvu_proxy_device(
    protection_type: ProtectionType,
    jail_config: &Option<JailConfig>,
    opt: &VvuOption,
    tube: Tube,
    max_sibling_mem_size: u64,
) -> DeviceResult {
    let listener =
        UnixListener::bind(&opt.socket).context("failed to bind listener for vvu proxy device")?;

    let dev = VirtioVhostUser::new(
        virtio::base_features(protection_type),
        listener,
        VmMemoryClient::new(tube),
        opt.addr,
        opt.uuid,
        max_sibling_mem_size,
    )
    .context("failed to create VVU proxy device")?;

    Ok(VirtioDeviceStub {
        dev: Box::new(dev),
        jail: simple_jail(jail_config, "vvu_proxy_device")?,
    })
}

pub fn create_rng_device(
    protection_type: ProtectionType,
    jail_config: &Option<JailConfig>,
) -> DeviceResult {
    let dev =
        virtio::Rng::new(virtio::base_features(protection_type)).context("failed to set up rng")?;

    Ok(VirtioDeviceStub {
        dev: Box::new(dev),
        jail: simple_jail(jail_config, "rng_device")?,
    })
}

#[cfg(feature = "audio")]
pub fn create_virtio_snd_device(
    protection_type: ProtectionType,
    jail_config: &Option<JailConfig>,
    snd_params: SndParameters,
) -> DeviceResult {
    let backend = snd_params.backend;
    let dev = virtio::snd::common_backend::VirtioSnd::new(
        virtio::base_features(protection_type),
        snd_params,
    )
    .context("failed to create cras sound device")?;

    use virtio::snd::parameters::StreamSourceBackend as Backend;

    let policy = match backend {
        Backend::NULL | Backend::FILE => "snd_null_device",
        #[cfg(feature = "audio_cras")]
        Backend::Sys(virtio::snd::sys::StreamSourceBackend::CRAS) => "snd_cras_device",
        #[cfg(not(feature = "audio_cras"))]
        _ => unreachable!(),
    };

    let jail = if let Some(jail_config) = jail_config {
        let mut config = SandboxConfig::new(jail_config, policy);
        #[cfg(feature = "audio_cras")]
        if backend == Backend::Sys(virtio::snd::sys::StreamSourceBackend::CRAS) {
            config.bind_mounts = true;
        }
        // TODO(b/267574679): running as current_user may not be required for snd device.
        config.run_as = RunAsUser::CurrentUser;
        #[allow(unused_mut)]
        let mut jail =
            create_sandbox_minijail(&jail_config.pivot_root, MAX_OPEN_FILES_DEFAULT, &config)?;
        #[cfg(feature = "audio_cras")]
        if backend == Backend::Sys(virtio::snd::sys::StreamSourceBackend::CRAS) {
            let run_cras_path = Path::new("/run/cras");
            jail.mount_bind(run_cras_path, run_cras_path, true)?;
        }
        Some(jail)
    } else {
        None
    };

    Ok(VirtioDeviceStub {
        dev: Box::new(dev),
        jail,
    })
}

#[cfg(feature = "tpm")]
pub fn create_software_tpm_device(
    protection_type: ProtectionType,
    jail_config: &Option<JailConfig>,
) -> DeviceResult {
    use std::ffi::CString;
    use std::fs;
    use std::process;

    let (jail, tpm_storage) = if let Some(jail_config) = jail_config {
        let mut config = SandboxConfig::new(jail_config, "tpm_device");
        config.bind_mounts = true;
        let mut jail =
            create_sandbox_minijail(&jail_config.pivot_root, MAX_OPEN_FILES_DEFAULT, &config)?;

        let pid = process::id();
        let crosvm_uid = geteuid();
        let crosvm_gid = getegid();
        let tpm_pid_dir = format!("/run/vm/tpm.{}", pid);
        let tpm_storage = PathBuf::from(&tpm_pid_dir);
        fs::create_dir_all(&tpm_storage).with_context(|| {
            format!("failed to create tpm storage dir {}", tpm_storage.display())
        })?;
        let tpm_pid_dir_c = CString::new(tpm_pid_dir).expect("no nul bytes");
        chown(&tpm_pid_dir_c, crosvm_uid, crosvm_gid).context("failed to chown tpm storage")?;

        jail.mount_bind(&tpm_storage, &tpm_storage, true)?;

        (Some(jail), tpm_storage)
    } else {
        // Path used inside cros_sdk which does not have /run/vm.
        (None, PathBuf::from("/tmp/tpm-simulator"))
    };

    let backend = SoftwareTpm::new(tpm_storage).context("failed to create SoftwareTpm")?;
    let dev = virtio::Tpm::new(Box::new(backend), virtio::base_features(protection_type));

    Ok(VirtioDeviceStub {
        dev: Box::new(dev),
        jail,
    })
}

#[cfg(all(feature = "vtpm", target_arch = "x86_64"))]
pub fn create_vtpm_proxy_device(
    protection_type: ProtectionType,
    jail_config: &Option<JailConfig>,
) -> DeviceResult {
    let jail = if let Some(jail_config) = jail_config {
        let mut config = SandboxConfig::new(jail_config, "vtpm_proxy_device");
        config.bind_mounts = true;
        let mut jail =
            create_sandbox_minijail(&jail_config.pivot_root, MAX_OPEN_FILES_DEFAULT, &config)?;
        let system_bus_socket_path = Path::new("/run/dbus/system_bus_socket");
        jail.mount_bind(system_bus_socket_path, system_bus_socket_path, true)?;
        Some(jail)
    } else {
        None
    };

    let backend = VtpmProxy::new();
    let dev = virtio::Tpm::new(Box::new(backend), virtio::base_features(protection_type));

    Ok(VirtioDeviceStub {
        dev: Box::new(dev),
        jail,
    })
}

pub fn create_single_touch_device(
    protection_type: ProtectionType,
    jail_config: &Option<JailConfig>,
    single_touch_spec: &TouchDeviceOption,
    idx: u32,
) -> DeviceResult {
    let socket = single_touch_spec
        .get_path()
        .into_unix_stream()
        .context("failed configuring virtio single touch")?;

    let (width, height) = single_touch_spec.get_size();
    let dev = virtio::input::new_single_touch(
        idx,
        socket,
        width,
        height,
        virtio::base_features(protection_type),
    )
    .context("failed to set up input device")?;
    Ok(VirtioDeviceStub {
        dev: Box::new(dev),
        jail: simple_jail(jail_config, "input_device")?,
    })
}

pub fn create_multi_touch_device(
    protection_type: ProtectionType,
    jail_config: &Option<JailConfig>,
    multi_touch_spec: &TouchDeviceOption,
    idx: u32,
) -> DeviceResult {
    let socket = multi_touch_spec
        .get_path()
        .into_unix_stream()
        .context("failed configuring virtio multi touch")?;

    let (width, height) = multi_touch_spec.get_size();
    let dev = virtio::input::new_multi_touch(
        idx,
        socket,
        width,
        height,
        virtio::base_features(protection_type),
    )
    .context("failed to set up input device")?;

    Ok(VirtioDeviceStub {
        dev: Box::new(dev),
        jail: simple_jail(jail_config, "input_device")?,
    })
}

pub fn create_trackpad_device(
    protection_type: ProtectionType,
    jail_config: &Option<JailConfig>,
    trackpad_spec: &TouchDeviceOption,
    idx: u32,
) -> DeviceResult {
    let socket = trackpad_spec
        .get_path()
        .into_unix_stream()
        .context("failed configuring virtio trackpad")?;

    let (width, height) = trackpad_spec.get_size();
    let dev = virtio::input::new_trackpad(
        idx,
        socket,
        width,
        height,
        virtio::base_features(protection_type),
    )
    .context("failed to set up input device")?;

    Ok(VirtioDeviceStub {
        dev: Box::new(dev),
        jail: simple_jail(jail_config, "input_device")?,
    })
}

pub fn create_mouse_device<T: IntoUnixStream>(
    protection_type: ProtectionType,
    jail_config: &Option<JailConfig>,
    mouse_socket: T,
    idx: u32,
) -> DeviceResult {
    let socket = mouse_socket
        .into_unix_stream()
        .context("failed configuring virtio mouse")?;

    let dev = virtio::input::new_mouse(idx, socket, virtio::base_features(protection_type))
        .context("failed to set up input device")?;

    Ok(VirtioDeviceStub {
        dev: Box::new(dev),
        jail: simple_jail(jail_config, "input_device")?,
    })
}

pub fn create_keyboard_device<T: IntoUnixStream>(
    protection_type: ProtectionType,
    jail_config: &Option<JailConfig>,
    keyboard_socket: T,
    idx: u32,
) -> DeviceResult {
    let socket = keyboard_socket
        .into_unix_stream()
        .context("failed configuring virtio keyboard")?;

    let dev = virtio::input::new_keyboard(idx, socket, virtio::base_features(protection_type))
        .context("failed to set up input device")?;

    Ok(VirtioDeviceStub {
        dev: Box::new(dev),
        jail: simple_jail(jail_config, "input_device")?,
    })
}

pub fn create_switches_device<T: IntoUnixStream>(
    protection_type: ProtectionType,
    jail_config: &Option<JailConfig>,
    switches_socket: T,
    idx: u32,
) -> DeviceResult {
    let socket = switches_socket
        .into_unix_stream()
        .context("failed configuring virtio switches")?;

    let dev = virtio::input::new_switches(idx, socket, virtio::base_features(protection_type))
        .context("failed to set up input device")?;

    Ok(VirtioDeviceStub {
        dev: Box::new(dev),
        jail: simple_jail(jail_config, "input_device")?,
    })
}

pub fn create_rotary_device<T: IntoUnixStream>(
    protection_type: ProtectionType,
    jail_config: &Option<JailConfig>,
    rotary_socket: T,
    idx: u32,
) -> DeviceResult {
    let socket = rotary_socket
        .into_unix_stream()
        .context("failed configuring virtio rotary")?;

    let dev = virtio::input::new_rotary(idx, socket, virtio::base_features(protection_type))
        .context("failed to set up input device")?;

    Ok(VirtioDeviceStub {
        dev: Box::new(dev),
        jail: simple_jail(jail_config, "input_device")?,
    })
}

pub fn create_vinput_device(
    protection_type: ProtectionType,
    jail_config: &Option<JailConfig>,
    dev_path: &Path,
) -> DeviceResult {
    let dev_file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(dev_path)
        .with_context(|| format!("failed to open vinput device {}", dev_path.display()))?;

    let dev = virtio::input::new_evdev(dev_file, virtio::base_features(protection_type))
        .context("failed to set up input device")?;

    Ok(VirtioDeviceStub {
        dev: Box::new(dev),
        jail: simple_jail(jail_config, "input_device")?,
    })
}

#[cfg(feature = "balloon")]
pub fn create_balloon_device(
    protection_type: ProtectionType,
    jail_config: &Option<JailConfig>,
    mode: BalloonMode,
    tube: Tube,
    inflate_tube: Option<Tube>,
    init_balloon_size: u64,
    enabled_features: u64,
    #[cfg(feature = "registered_events")] registered_evt_q: Option<SendTube>,
    ws_num_bins: u8,
) -> DeviceResult {
    let dev = virtio::Balloon::new(
        virtio::base_features(protection_type),
        tube,
        inflate_tube,
        init_balloon_size,
        mode,
        enabled_features,
        #[cfg(feature = "registered_events")]
        registered_evt_q,
        ws_num_bins,
    )
    .context("failed to create balloon")?;

    Ok(VirtioDeviceStub {
        dev: Box::new(dev),
        jail: simple_jail(jail_config, "balloon_device")?,
    })
}

impl VirtioDeviceBuilder for &NetParameters {
    const NAME: &'static str = "net";

    fn create_virtio_device(
        self,
        protection_type: ProtectionType,
    ) -> anyhow::Result<Box<dyn VirtioDevice>> {
        let vq_pairs = self.vq_pairs.unwrap_or(1);
        let multi_vq = vq_pairs > 1 && self.vhost_net.is_none();

        let features = virtio::base_features(protection_type);
        let (tap, mac) = create_tap_for_net_device(&self.mode, multi_vq)?;

        Ok(if let Some(vhost_net) = &self.vhost_net {
            Box::new(
                virtio::vhost::Net::<_, vhost::Net<_>>::new(
                    &vhost_net.device,
                    features,
                    tap,
                    mac,
                    self.packed_queue,
                )
                .context("failed to set up virtio-vhost networking")?,
            ) as Box<dyn VirtioDevice>
        } else {
            Box::new(
                virtio::Net::new(features, tap, vq_pairs, mac, self.packed_queue)
                    .context("failed to set up virtio networking")?,
            ) as Box<dyn VirtioDevice>
        })
    }

    fn create_jail(
        &self,
        jail_config: &Option<JailConfig>,
        virtio_transport: VirtioDeviceType,
    ) -> anyhow::Result<Option<Minijail>> {
        let policy = if self.vhost_net.is_some() {
            "vhost_net"
        } else {
            "net"
        };

        simple_jail(jail_config, &virtio_transport.seccomp_policy_file(policy))
    }

    fn create_vhost_user_device(
        self,
        keep_rds: &mut Vec<RawDescriptor>,
    ) -> anyhow::Result<Box<dyn VhostUserDevice>> {
        let vq_pairs = self.vq_pairs.unwrap_or(1);
        let multi_vq = vq_pairs > 1 && self.vhost_net.is_none();
        let (tap, _mac) = create_tap_for_net_device(&self.mode, multi_vq)?;

        let backend = NetBackend::new(tap)?;

        keep_rds.extend(backend.as_raw_descriptors());

        Ok(Box::new(backend))
    }
}

/// Create a new tap interface based on NetParametersMode.
fn create_tap_for_net_device(
    mode: &NetParametersMode,
    multi_vq: bool,
) -> DeviceResult<(Tap, Option<MacAddress>)> {
    match mode {
        NetParametersMode::TapName { tap_name, mac } => {
            let tap = Tap::new_with_name(tap_name.as_bytes(), true, multi_vq)
                .map_err(NetError::TapOpen)?;
            Ok((tap, *mac))
        }
        NetParametersMode::TapFd { tap_fd, mac } => {
            // Safe because we ensure that we get a unique handle to the fd.
            let tap = unsafe {
                Tap::from_raw_descriptor(
                    validate_raw_descriptor(*tap_fd)
                        .context("failed to validate tap descriptor")?,
                )
                .context("failed to create tap device")?
            };
            Ok((tap, *mac))
        }
        NetParametersMode::RawConfig {
            host_ip,
            netmask,
            mac,
        } => {
            let tap = Tap::new(true, multi_vq).map_err(NetError::TapOpen)?;
            tap.set_ip_addr(*host_ip).map_err(NetError::TapSetIp)?;
            tap.set_netmask(*netmask).map_err(NetError::TapSetNetmask)?;
            tap.set_mac_address(*mac)
                .map_err(NetError::TapSetMacAddress)?;
            tap.enable().map_err(NetError::TapEnable)?;
            Ok((tap, None))
        }
    }
}

pub fn create_vhost_user_net_device(
    protection_type: ProtectionType,
    opt: &VhostUserOption,
) -> DeviceResult {
    let dev = VhostUserVirtioDevice::new_net(
        virtio::base_features(protection_type),
        vhost_user_connection(&opt.socket)?,
    )
    .context("failed to set up vhost-user net device")?;

    Ok(VirtioDeviceStub {
        dev: Box::new(dev),
        // no sandbox here because virtqueue handling is exported to a different process.
        jail: None,
    })
}

pub fn create_vhost_user_vsock_device(
    protection_type: ProtectionType,
    opt: &VhostUserOption,
) -> DeviceResult {
    let dev = VhostUserVirtioDevice::new_vsock(
        virtio::base_features(protection_type),
        vhost_user_connection(&opt.socket)?,
    )
    .context("failed to set up vhost-user vsock device")?;

    Ok(VirtioDeviceStub {
        dev: Box::new(dev),
        // no sandbox here because virtqueue handling is exported to a different process.
        jail: None,
    })
}

pub fn create_vhost_user_wl_device(
    protection_type: ProtectionType,
    opt: &VhostUserOption,
) -> DeviceResult {
    // The crosvm wl device expects us to connect the tube before it will accept a vhost-user
    // connection.
    let dev = VhostUserVirtioDevice::new_wl(
        virtio::base_features(protection_type),
        vhost_user_connection(&opt.socket)?,
    )
    .context("failed to set up vhost-user wl device")?;

    Ok(VirtioDeviceStub {
        dev: Box::new(dev),
        // no sandbox here because virtqueue handling is exported to a different process.
        jail: None,
    })
}

pub fn create_wayland_device(
    protection_type: ProtectionType,
    jail_config: &Option<JailConfig>,
    wayland_socket_paths: &BTreeMap<String, PathBuf>,
    resource_bridge: Option<Tube>,
) -> DeviceResult {
    let wayland_socket_dirs = wayland_socket_paths
        .iter()
        .map(|(_name, path)| path.parent())
        .collect::<Option<Vec<_>>>()
        .ok_or_else(|| anyhow!("wayland socket path has no parent or file name"))?;

    let features = virtio::base_features(protection_type);
    let dev = virtio::Wl::new(features, wayland_socket_paths.clone(), resource_bridge)
        .context("failed to create wayland device")?;

    let jail = if let Some(jail_config) = jail_config {
        let mut config = SandboxConfig::new(jail_config, "wl_device");
        config.bind_mounts = true;
        let mut jail = create_gpu_minijail(
            &jail_config.pivot_root,
            &config,
            /* render_node_only= */ false,
        )?;
        // Bind mount the wayland socket's directory into jail's root. This is necessary since
        // each new wayland context must open() the socket. If the wayland socket is ever
        // destroyed and remade in the same host directory, new connections will be possible
        // without restarting the wayland device.
        for dir in &wayland_socket_dirs {
            jail.mount(dir, dir, "", (libc::MS_BIND | libc::MS_REC) as usize)?;
        }

        Some(jail)
    } else {
        None
    };

    Ok(VirtioDeviceStub {
        dev: Box::new(dev),
        jail,
    })
}

#[cfg(any(feature = "video-decoder", feature = "video-encoder"))]
pub fn create_video_device(
    backend: VideoBackendType,
    protection_type: ProtectionType,
    jail_config: &Option<JailConfig>,
    typ: VideoDeviceType,
    resource_bridge: Tube,
) -> DeviceResult {
    let jail = if let Some(jail_config) = jail_config {
        match typ {
            #[cfg(feature = "video-decoder")]
            VideoDeviceType::Decoder => {}
            #[cfg(feature = "video-encoder")]
            VideoDeviceType::Encoder => {}
            #[cfg(any(not(feature = "video-decoder"), not(feature = "video-encoder")))]
            // `typ` is always a VideoDeviceType enabled
            device_type => unreachable!("Not compiled with {:?} enabled", device_type),
        };
        let mut config = SandboxConfig::new(jail_config, "video_device");
        config.bind_mounts = true;
        let mut jail =
            create_sandbox_minijail(&jail_config.pivot_root, MAX_OPEN_FILES_DEFAULT, &config)?;

        let need_drm_device = match backend {
            #[cfg(any(feature = "libvda", feature = "libvda-stub"))]
            VideoBackendType::Libvda => true,
            #[cfg(any(feature = "libvda", feature = "libvda-stub"))]
            VideoBackendType::LibvdaVd => true,
            #[cfg(feature = "vaapi")]
            VideoBackendType::Vaapi => true,
            #[cfg(feature = "ffmpeg")]
            VideoBackendType::Ffmpeg => false,
        };

        if need_drm_device {
            jail_mount_bind_drm(&mut jail, /* render_node_only= */ true)?;
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
    } else {
        None
    };

    Ok(VirtioDeviceStub {
        dev: Box::new(devices::virtio::VideoDevice::new(
            virtio::base_features(protection_type),
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
    protection_type: ProtectionType,
    jail_config: &Option<JailConfig>,
    typ: VideoDeviceType,
) -> Result<()> {
    devs.push(create_video_device(
        backend,
        protection_type,
        jail_config,
        typ,
        video_tube,
    )?);
    Ok(())
}

pub fn create_vhost_user_video_device(
    protection_type: ProtectionType,
    opt: &VhostUserOption,
    device_type: VideoDeviceType,
) -> DeviceResult {
    let dev = VhostUserVirtioDevice::new_video(
        virtio::base_features(protection_type),
        vhost_user_connection(&opt.socket)?,
        device_type,
    )
    .context("failed to set up vhost-user video device")?;

    Ok(VirtioDeviceStub {
        dev: Box::new(dev),
        // no sandbox here because virtqueue handling is exported to a different process.
        jail: None,
    })
}

impl VirtioDeviceBuilder for &VsockConfig {
    const NAME: &'static str = "vhost_vsock";

    fn create_virtio_device(
        self,
        protection_type: ProtectionType,
    ) -> anyhow::Result<Box<dyn VirtioDevice>> {
        let features = virtio::base_features(protection_type);

        let dev = virtio::vhost::Vsock::new(features, self)
            .context("failed to set up virtual socket device")?;

        Ok(Box::new(dev))
    }

    fn create_vhost_user_device(
        self,
        keep_rds: &mut Vec<RawDescriptor>,
    ) -> anyhow::Result<Box<dyn VhostUserDevice>> {
        let vsock_device = VhostUserVsockDevice::new(self.cid, &self.vhost_device)?;

        keep_rds.push(vsock_device.as_raw_descriptor());

        Ok(Box::new(vsock_device))
    }
}

#[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
pub fn create_vhost_scmi_device(
    protected_vm: ProtectionType,
    jail_config: &Option<JailConfig>,
    vhost_scmi_dev_path: PathBuf,
) -> DeviceResult {
    let features = virtio::base_features(protected_vm);

    let dev = virtio::vhost::Scmi::new(&vhost_scmi_dev_path, features)
        .context("failed to set up vhost scmi device")?;

    Ok(VirtioDeviceStub {
        dev: Box::new(dev),
        jail: simple_jail(jail_config, "vhost_scmi_device")?,
    })
}

pub fn create_fs_device(
    protection_type: ProtectionType,
    jail_config: &Option<JailConfig>,
    ugid: (Option<u32>, Option<u32>),
    uid_map: &str,
    gid_map: &str,
    src: &Path,
    tag: &str,
    fs_cfg: virtio::fs::Config,
    device_tube: Tube,
) -> DeviceResult {
    let max_open_files =
        base::get_max_open_files().context("failed to get max number of open files")?;
    let j = if let Some(jail_config) = jail_config {
        let mut config = SandboxConfig::new(jail_config, "fs_device");
        config.limit_caps = false;
        config.ugid_map = Some((uid_map, gid_map));
        // We want bind mounts from the parent namespaces to propagate into the fs device's
        // namespace.
        config.remount_mode = Some(libc::MS_SLAVE);
        config.run_as = if ugid == (None, None) {
            RunAsUser::Unspecified
        } else {
            RunAsUser::Specified(ugid.0.unwrap_or(0), ugid.1.unwrap_or(0))
        };
        create_sandbox_minijail(src, max_open_files, &config)?
    } else {
        create_base_minijail(src, max_open_files)?
    };

    let features = virtio::base_features(protection_type);
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
    protection_type: ProtectionType,
    jail_config: &Option<JailConfig>,
    ugid: (Option<u32>, Option<u32>),
    uid_map: &str,
    gid_map: &str,
    src: &Path,
    tag: &str,
    mut p9_cfg: p9::Config,
) -> DeviceResult {
    let max_open_files =
        base::get_max_open_files().context("failed to get max number of open files")?;
    let (jail, root) = if let Some(jail_config) = jail_config {
        let mut config = SandboxConfig::new(jail_config, "9p_device");
        config.limit_caps = false;
        config.ugid_map = Some((uid_map, gid_map));
        // We want bind mounts from the parent namespaces to propagate into the 9p server's
        // namespace.
        config.remount_mode = Some(libc::MS_SLAVE);
        config.run_as = if ugid == (None, None) {
            RunAsUser::Unspecified
        } else {
            RunAsUser::Specified(ugid.0.unwrap_or(0), ugid.1.unwrap_or(0))
        };
        let jail = create_sandbox_minijail(src, max_open_files, &config)?;

        //  The shared directory becomes the root of the device's file system.
        let root = Path::new("/");
        (Some(jail), root)
    } else {
        // There's no mount namespace so we tell the server to treat the source directory as the
        // root.
        (None, src)
    };

    let features = virtio::base_features(protection_type);
    p9_cfg.root = root.into();
    let dev = virtio::P9::new(features, tag, p9_cfg).context("failed to create 9p device")?;

    Ok(VirtioDeviceStub {
        dev: Box::new(dev),
        jail,
    })
}

pub fn create_pmem_device(
    protection_type: ProtectionType,
    jail_config: &Option<JailConfig>,
    vm: &mut impl Vm,
    resources: &mut SystemAllocator,
    disk: &DiskOption,
    index: usize,
    pmem_device_tube: Tube,
) -> DeviceResult {
    let fd = open_file_or_duplicate(
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
        .allocate_mmio(
            arena_size,
            Alloc::PmemDevice(index),
            format!("pmem_disk_image_{}", index),
            AllocOptions::new()
                .top_down(true)
                .prefetchable(true)
                // Linux kernel requires pmem namespaces to be 128 MiB aligned.
                .align(128 * 1024 * 1024), /* 128 MiB */
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
        virtio::base_features(protection_type),
        fd,
        GuestAddress(mapping_address),
        slot,
        arena_size,
        Some(pmem_device_tube),
    )
    .context("failed to create pmem device")?;

    Ok(VirtioDeviceStub {
        dev: Box::new(dev) as Box<dyn VirtioDevice>,
        jail: simple_jail(jail_config, "pmem_device")?,
    })
}

pub fn create_iommu_device(
    protection_type: ProtectionType,
    jail_config: &Option<JailConfig>,
    iova_max_addr: u64,
    endpoints: BTreeMap<u32, Arc<Mutex<Box<dyn MemoryMapperTrait>>>>,
    hp_endpoints_ranges: Vec<RangeInclusive<u32>>,
    translate_response_senders: Option<BTreeMap<u32, Tube>>,
    translate_request_rx: Option<Tube>,
    iommu_device_tube: Tube,
) -> DeviceResult {
    let dev = virtio::Iommu::new(
        virtio::base_features(protection_type),
        endpoints,
        iova_max_addr,
        hp_endpoints_ranges,
        translate_response_senders,
        translate_request_rx,
        Some(iommu_device_tube),
    )
    .context("failed to create IOMMU device")?;

    Ok(VirtioDeviceStub {
        dev: Box::new(dev),
        jail: simple_jail(jail_config, "iommu_device")?,
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

/// For creating console virtio devices.
impl VirtioDeviceBuilder for &SerialParameters {
    const NAME: &'static str = "serial";

    fn create_virtio_device(
        self,
        protection_type: ProtectionType,
    ) -> anyhow::Result<Box<dyn VirtioDevice>> {
        let mut keep_rds = Vec::new();
        let evt = Event::new().context("failed to create event")?;

        if self.hardware == SerialHardware::LegacyVirtioConsole {
            Ok(Box::new(
                self.create_serial_device::<Console>(protection_type, &evt, &mut keep_rds)
                    .context("failed to create console device")?,
            ))
        } else {
            Ok(Box::new(
                self.create_serial_device::<AsyncConsole>(protection_type, &evt, &mut keep_rds)
                    .context("failed to create console device")?,
            ))
        }
    }

    fn create_vhost_user_device(
        self,
        keep_rds: &mut Vec<RawDescriptor>,
    ) -> anyhow::Result<Box<dyn VhostUserDevice>> {
        Ok(Box::new(virtio::vhost::user::create_vu_console_device(
            self, keep_rds,
        )?))
    }

    fn create_jail(
        &self,
        jail_config: &Option<JailConfig>,
        virtio_transport: VirtioDeviceType,
    ) -> anyhow::Result<Option<Minijail>> {
        if let Some(jail_config) = jail_config {
            let policy = virtio_transport.seccomp_policy_file("serial");
            let mut config = SandboxConfig::new(jail_config, &policy);
            config.bind_mounts = true;
            let mut jail =
                create_sandbox_minijail(&jail_config.pivot_root, MAX_OPEN_FILES_DEFAULT, &config)?;
            add_bind_mounts(self, &mut jail)
                .context("failed to add bind mounts for console device")?;
            Ok(Some(jail))
        } else {
            Ok(None)
        }
    }
}

#[cfg(feature = "audio")]
pub fn create_sound_device(
    path: &Path,
    protection_type: ProtectionType,
    jail_config: &Option<JailConfig>,
) -> DeviceResult {
    let dev = virtio::new_sound(path, virtio::base_features(protection_type))
        .context("failed to create sound device")?;

    Ok(VirtioDeviceStub {
        dev: Box::new(dev),
        jail: simple_jail(jail_config, "vios_audio_device")?,
    })
}

#[allow(clippy::large_enum_variant)]
pub enum VfioDeviceVariant {
    Pci(VfioPciDevice),
    Platform(VfioPlatformDevice),
}

pub fn create_vfio_device(
    jail_config: &Option<JailConfig>,
    vm: &impl Vm,
    resources: &mut SystemAllocator,
    irq_control_tubes: &mut Vec<Tube>,
    vm_memory_control_tubes: &mut Vec<VmMemoryTube>,
    control_tubes: &mut Vec<TaggedControlTube>,
    vfio_path: &Path,
    hotplug: bool,
    hotplug_bus: Option<u8>,
    guest_address: Option<PciAddress>,
    coiommu_endpoints: Option<&mut Vec<u16>>,
    iommu_dev: IommuDevType,
) -> DeviceResult<(VfioDeviceVariant, Option<Minijail>, Option<VfioWrapper>)> {
    let vfio_container = VfioCommonSetup::vfio_get_container(iommu_dev, Some(vfio_path))
        .context("failed to get vfio container")?;

    let (vfio_host_tube_mem, vfio_device_tube_mem) =
        Tube::pair().context("failed to create tube")?;
    vm_memory_control_tubes.push(VmMemoryTube {
        tube: vfio_host_tube_mem,
        expose_with_viommu: false,
    });

    let (vfio_host_tube_vm, vfio_device_tube_vm) = Tube::pair().context("failed to create tube")?;
    control_tubes.push(TaggedControlTube::Vm(vfio_host_tube_vm));

    let vfio_device = VfioDevice::new_passthrough(
        &vfio_path,
        vm,
        vfio_container.clone(),
        iommu_dev != IommuDevType::NoIommu,
    )
    .context("failed to create vfio device")?;

    match vfio_device.device_type() {
        VfioDeviceType::Pci => {
            let (vfio_host_tube_msi, vfio_device_tube_msi) =
                Tube::pair().context("failed to create tube")?;
            irq_control_tubes.push(vfio_host_tube_msi);

            let (vfio_host_tube_msix, vfio_device_tube_msix) =
                Tube::pair().context("failed to create tube")?;
            irq_control_tubes.push(vfio_host_tube_msix);

            let mut vfio_pci_device = VfioPciDevice::new(
                vfio_path,
                vfio_device,
                hotplug,
                hotplug_bus,
                guest_address,
                vfio_device_tube_msi,
                vfio_device_tube_msix,
                VmMemoryClient::new(vfio_device_tube_mem),
                vfio_device_tube_vm,
            )?;
            // early reservation for pass-through PCI devices.
            let endpoint_addr = vfio_pci_device
                .allocate_address(resources)
                .context("failed to allocate resources early for vfio pci dev")?;

            let viommu_mapper = match iommu_dev {
                IommuDevType::NoIommu => None,
                IommuDevType::VirtioIommu => {
                    Some(VfioWrapper::new(vfio_container, vm.get_memory().clone()))
                }
                IommuDevType::CoIommu => {
                    if let Some(endpoints) = coiommu_endpoints {
                        endpoints.push(endpoint_addr.to_u32() as u16);
                    } else {
                        bail!("Missed coiommu_endpoints vector to store the endpoint addr");
                    }
                    None
                }
            };

            if hotplug {
                Ok((VfioDeviceVariant::Pci(vfio_pci_device), None, viommu_mapper))
            } else {
                Ok((
                    VfioDeviceVariant::Pci(vfio_pci_device),
                    simple_jail(jail_config, "vfio_device")?,
                    viommu_mapper,
                ))
            }
        }
        VfioDeviceType::Platform => {
            if guest_address.is_some() {
                bail!("guest-address is not supported for VFIO platform devices");
            }

            if hotplug {
                bail!("hotplug is not supported for VFIO platform devices");
            }

            let vfio_plat_dev =
                VfioPlatformDevice::new(vfio_device, VmMemoryClient::new(vfio_device_tube_mem));

            Ok((
                VfioDeviceVariant::Platform(vfio_plat_dev),
                simple_jail(jail_config, "vfio_platform_device")?,
                None,
            ))
        }
    }
}

/// Setup for devices with virtio-iommu
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
