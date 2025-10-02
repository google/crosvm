// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::convert::TryFrom;
use std::fs::File;
use std::fs::OpenOptions;
use std::io::ErrorKind;
use std::ops::RangeInclusive;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::path::PathBuf;
use std::str;
use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;

use anyhow::anyhow;
use anyhow::bail;
use anyhow::Context;
use anyhow::Result;
use arch::VirtioDeviceStub;
use base::linux::MemfdSeals;
use base::sys::SharedMemoryLinux;
use base::ReadNotifier;
use base::*;
use devices::serial_device::SerialParameters;
use devices::serial_device::SerialType;
use devices::vfio::VfioContainerManager;
use devices::virtio;
use devices::virtio::block::DiskOption;
#[cfg(any(feature = "video-decoder", feature = "video-encoder"))]
use devices::virtio::device_constants::video::VideoBackendType;
#[cfg(any(feature = "video-decoder", feature = "video-encoder"))]
use devices::virtio::device_constants::video::VideoDeviceType;
use devices::virtio::ipc_memory_mapper::create_ipc_mapper;
use devices::virtio::ipc_memory_mapper::CreateIpcMapperRet;
use devices::virtio::memory_mapper::BasicMemoryMapper;
use devices::virtio::memory_mapper::MemoryMapperTrait;
#[cfg(feature = "pvclock")]
use devices::virtio::pvclock::PvClock;
use devices::virtio::scsi::ScsiOption;
#[cfg(feature = "audio")]
use devices::virtio::snd::parameters::Parameters as SndParameters;
use devices::virtio::vfio_wrapper::VfioWrapper;
#[cfg(feature = "net")]
use devices::virtio::vhost_user_backend::NetBackend;
use devices::virtio::vhost_user_backend::VhostUserDeviceBuilder;
use devices::virtio::vhost_user_backend::VhostUserVsockDevice;
use devices::virtio::vsock::VsockConfig;
use devices::virtio::Console;
use devices::virtio::MemSlotConfig;
#[cfg(feature = "net")]
use devices::virtio::NetError;
#[cfg(feature = "net")]
use devices::virtio::NetParameters;
#[cfg(feature = "net")]
use devices::virtio::NetParametersMode;
use devices::virtio::PmemConfig;
use devices::virtio::VhostUserFrontend;
use devices::virtio::VirtioDevice;
use devices::virtio::VirtioDeviceType;
use devices::BusDeviceObj;
use devices::IommuDevType;
use devices::PciAddress;
use devices::PciDevice;
use devices::VfioDevice;
use devices::VfioDeviceType;
use devices::VfioPciDevice;
use devices::VfioPlatformDevice;
#[cfg(feature = "vtpm")]
use devices::VtpmProxy;
use hypervisor::MemCacheType;
use hypervisor::ProtectionType;
use hypervisor::Vm;
use jail::*;
use minijail::Minijail;
#[cfg(feature = "net")]
use net_util::sys::linux::Tap;
#[cfg(feature = "net")]
use net_util::MacAddress;
#[cfg(feature = "net")]
use net_util::TapTCommon;
use resources::Alloc;
use resources::AllocOptions;
use resources::SystemAllocator;
use sync::Mutex;
use vm_control::api::VmMemoryClient;
use vm_memory::GuestAddress;

use crate::crosvm::config::PmemOption;
use crate::crosvm::config::VhostUserFrontendOption;
use crate::crosvm::sys::config::PmemExt2Option;

/// All the tube types collected and passed to `run_control`.
///
/// This mainly exists to simplify the device setup plumbing. We collect the tubes of all the
/// devices into one list using this enum and then separate them out in `run_control` to be handled
/// individually.
#[remain::sorted]
pub enum AnyControlTube {
    DeviceControlTube(DeviceControlTube),
    /// Receives `IrqHandlerRequest`.
    IrqTube(Tube),
    TaggedControlTube(TaggedControlTube),
    VmMemoryTube(VmMemoryTube),
}

impl From<DeviceControlTube> for AnyControlTube {
    fn from(value: DeviceControlTube) -> Self {
        AnyControlTube::DeviceControlTube(value)
    }
}

impl From<TaggedControlTube> for AnyControlTube {
    fn from(value: TaggedControlTube) -> Self {
        AnyControlTube::TaggedControlTube(value)
    }
}

impl From<VmMemoryTube> for AnyControlTube {
    fn from(value: VmMemoryTube) -> Self {
        AnyControlTube::VmMemoryTube(value)
    }
}

/// Tubes that initiate requests to devices.
#[remain::sorted]
pub enum DeviceControlTube {
    // See `BalloonTube`.
    #[cfg(feature = "balloon")]
    Balloon(Tube),
    // Sends `DiskControlCommand`.
    Disk(Tube),
    // Sends `GpuControlCommand`.
    #[cfg(feature = "gpu")]
    Gpu(Tube),
    // Sends `PvClockCommand`.
    #[cfg(feature = "pvclock")]
    PvClock(Tube),
    #[cfg(feature = "audio")]
    Snd(Tube),
}

/// Tubes that service requests from devices.
///
/// Only includes those that happen to be handled together in the main `WaitContext` loop.
pub enum TaggedControlTube {
    /// Receives `FsMappingRequest`.
    Fs(Tube),
    /// Receives `VmRequest`.
    Vm(Tube),
    /// Receives `VmMemoryMappingRequest`.
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

/// Tubes that service `VmMemoryRequest` requests from devices.
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

impl IntoUnixStream for &Path {
    fn into_unix_stream(self) -> Result<UnixStream> {
        if let Some(fd) = safe_descriptor_from_path(self)
            .with_context(|| format!("failed to open event device '{}'", self.display()))?
        {
            Ok(fd.into())
        } else {
            UnixStream::connect(self)
                .with_context(|| format!("failed to open event device '{}'", self.display()))
        }
    }
}

impl IntoUnixStream for &PathBuf {
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
    ) -> anyhow::Result<Box<dyn VhostUserDeviceBuilder>> {
        unimplemented!()
    }

    /// Create a jail that is suitable to run a device.
    ///
    /// The default implementation creates a simple jail with a seccomp policy derived from the
    /// base name of the device.
    fn create_jail(
        &self,
        jail_config: Option<&JailConfig>,
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
        jail_config: Option<&JailConfig>,
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

impl VirtioDeviceBuilder for DiskConfig<'_> {
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
                self.disk,
                self.device_tube,
                None,
                None,
            )
            .context("failed to create block device")?,
        ))
    }

    fn create_vhost_user_device(
        self,
        keep_rds: &mut Vec<RawDescriptor>,
    ) -> anyhow::Result<Box<dyn VhostUserDeviceBuilder>> {
        let disk = self.disk;
        let disk_image = disk.open()?;
        let base_features = virtio::base_features(ProtectionType::Unprotected);

        let block = Box::new(
            virtio::BlockAsync::new(
                base_features,
                disk_image,
                disk,
                self.device_tube,
                None,
                None,
            )
            .context("failed to create block device")?,
        );
        keep_rds.extend(block.keep_rds());

        Ok(block)
    }
}

pub struct ScsiConfig<'a>(pub &'a [ScsiOption]);

impl<'a> VirtioDeviceBuilder for &'a ScsiConfig<'a> {
    const NAME: &'static str = "scsi";

    fn create_virtio_device(
        self,
        protection_type: ProtectionType,
    ) -> anyhow::Result<Box<dyn VirtioDevice>> {
        let base_features = virtio::base_features(protection_type);
        let disks = self
            .0
            .iter()
            .map(|op| {
                info!("Trying to attach a scsi device: {}", op.path.display());
                let file = op.open()?;
                Ok(virtio::ScsiDiskConfig {
                    file,
                    block_size: op.block_size,
                    read_only: op.read_only,
                })
            })
            .collect::<anyhow::Result<_>>()?;
        let controller = virtio::ScsiController::new(base_features, disks)
            .context("failed to create a scsi controller")?;
        Ok(Box::new(controller))
    }
}

fn vhost_user_connection(
    path: &Path,
    connect_timeout_ms: Option<u64>,
) -> Result<vmm_vhost::Connection<vmm_vhost::FrontendReq>> {
    let deadline = connect_timeout_ms.map(|t| Instant::now() + Duration::from_millis(t));
    let mut first = true;
    loop {
        match UnixStream::connect(path) {
            Ok(sock) => {
                let connection = sock
                    .try_into()
                    .context("failed to construct Connection from UnixStream")?;
                return Ok(connection);
            }
            Err(e) => {
                // ConnectionRefused => Might be a stale file the backend hasn't deleted yet.
                // NotFound => Might be the backend hasn't bound the socket yet.
                if e.kind() == ErrorKind::ConnectionRefused || e.kind() == ErrorKind::NotFound {
                    if let Some(deadline) = deadline {
                        if first {
                            first = false;
                            warn!(
                                "vhost-user socket path {} not available. retrying up to {} ms",
                                path.display(),
                                connect_timeout_ms.unwrap()
                            );
                        }
                        if Instant::now() > deadline {
                            anyhow::bail!(
                                "timeout waiting for vhost-user socket path {}: final error: {e:#}",
                                path.display()
                            );
                        }
                        std::thread::sleep(Duration::from_millis(1));
                        continue;
                    }
                }
                return Err(e).with_context(|| {
                    format!(
                        "failed to connect to vhost-user socket path {}",
                        path.display()
                    )
                });
            }
        }
    }
}

pub fn create_vhost_user_frontend(
    protection_type: ProtectionType,
    opt: &VhostUserFrontendOption,
    connect_timeout_ms: Option<u64>,
    vm_evt_wrtube: base::SendTube,
) -> DeviceResult {
    let connection = if let Some(socket_fd) = safe_descriptor_from_path(&opt.socket)? {
        socket_fd
            .try_into()
            .context("failed to create vhost-user connection from fd")?
    } else {
        vhost_user_connection(&opt.socket, connect_timeout_ms)?
    };
    let dev = VhostUserFrontend::new(
        opt.type_,
        virtio::base_features(protection_type),
        connection,
        vm_evt_wrtube,
        opt.max_queue_size,
        opt.pci_address,
    )
    .context("failed to set up vhost-user frontend")?;

    Ok(VirtioDeviceStub {
        dev: Box::new(dev),
        // no sandbox here because virtqueue handling is exported to a different process.
        jail: None,
    })
}

pub fn create_rng_device(
    protection_type: ProtectionType,
    jail_config: Option<&JailConfig>,
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
    jail_config: Option<&JailConfig>,
    snd_params: SndParameters,
    snd_device_tube: Tube,
) -> DeviceResult {
    let backend = snd_params.backend;
    let dev = virtio::snd::common_backend::VirtioSnd::new(
        virtio::base_features(protection_type),
        snd_params,
        snd_device_tube,
    )
    .context("failed to create cras sound device")?;

    use virtio::snd::parameters::StreamSourceBackend as Backend;

    let policy = match backend {
        Backend::NULL | Backend::FILE => "snd_null_device",
        #[cfg(feature = "audio_aaudio")]
        Backend::Sys(virtio::snd::sys::StreamSourceBackend::AAUDIO) => "snd_aaudio_device",
        #[cfg(feature = "audio_cras")]
        Backend::Sys(virtio::snd::sys::StreamSourceBackend::CRAS) => "snd_cras_device",
        #[cfg(not(any(feature = "audio_cras", feature = "audio_aaudio")))]
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

#[cfg(feature = "vtpm")]
pub fn create_vtpm_proxy_device(
    protection_type: ProtectionType,
    jail_config: Option<&JailConfig>,
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

pub fn create_single_touch_device<T: IntoUnixStream>(
    protection_type: ProtectionType,
    jail_config: Option<&JailConfig>,
    single_touch_socket: T,
    width: u32,
    height: u32,
    name: Option<&str>,
    idx: u32,
) -> DeviceResult {
    let socket = single_touch_socket
        .into_unix_stream()
        .context("failed configuring virtio single touch")?;

    let dev = virtio::input::new_single_touch(
        idx,
        socket,
        width,
        height,
        name,
        virtio::base_features(protection_type),
    )
    .context("failed to set up input device")?;
    Ok(VirtioDeviceStub {
        dev: Box::new(dev),
        jail: simple_jail(jail_config, "input_device")?,
    })
}

pub fn create_multi_touch_device<T: IntoUnixStream>(
    protection_type: ProtectionType,
    jail_config: Option<&JailConfig>,
    multi_touch_socket: T,
    width: u32,
    height: u32,
    name: Option<&str>,
    idx: u32,
) -> DeviceResult {
    let socket = multi_touch_socket
        .into_unix_stream()
        .context("failed configuring virtio multi touch")?;

    let dev = virtio::input::new_multi_touch(
        idx,
        socket,
        width,
        height,
        name,
        virtio::base_features(protection_type),
    )
    .context("failed to set up input device")?;

    Ok(VirtioDeviceStub {
        dev: Box::new(dev),
        jail: simple_jail(jail_config, "input_device")?,
    })
}

pub fn create_trackpad_device<T: IntoUnixStream>(
    protection_type: ProtectionType,
    jail_config: Option<&JailConfig>,
    trackpad_socket: T,
    width: u32,
    height: u32,
    name: Option<&str>,
    idx: u32,
) -> DeviceResult {
    let socket = trackpad_socket
        .into_unix_stream()
        .context("failed configuring virtio trackpad")?;

    let dev = virtio::input::new_trackpad(
        idx,
        socket,
        width,
        height,
        name,
        virtio::base_features(protection_type),
    )
    .context("failed to set up input device")?;

    Ok(VirtioDeviceStub {
        dev: Box::new(dev),
        jail: simple_jail(jail_config, "input_device")?,
    })
}

pub fn create_multitouch_trackpad_device<T: IntoUnixStream>(
    protection_type: ProtectionType,
    jail_config: Option<&JailConfig>,
    trackpad_socket: T,
    width: u32,
    height: u32,
    name: Option<&str>,
    idx: u32,
) -> DeviceResult {
    let socket = trackpad_socket
        .into_unix_stream()
        .context("failed configuring virtio trackpad")?;

    let dev = virtio::input::new_multitouch_trackpad(
        idx,
        socket,
        width,
        height,
        name,
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
    jail_config: Option<&JailConfig>,
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
    jail_config: Option<&JailConfig>,
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
    jail_config: Option<&JailConfig>,
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
    jail_config: Option<&JailConfig>,
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
    jail_config: Option<&JailConfig>,
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

pub fn create_custom_device<T: IntoUnixStream>(
    protection_type: ProtectionType,
    jail_config: Option<&JailConfig>,
    custom_device_socket: T,
    idx: u32,
    input_config_path: PathBuf,
) -> DeviceResult {
    let socket = custom_device_socket
        .into_unix_stream()
        .context("failed configuring custom virtio input device")?;

    let dev = virtio::input::new_custom(
        idx,
        socket,
        input_config_path,
        virtio::base_features(protection_type),
    )
    .context("failed to set up input device")?;

    Ok(VirtioDeviceStub {
        dev: Box::new(dev),
        jail: simple_jail(jail_config, "input_device")?,
    })
}

#[cfg(feature = "balloon")]
pub fn create_balloon_device(
    protection_type: ProtectionType,
    jail_config: Option<&JailConfig>,
    tube: Tube,
    inflate_tube: Option<Tube>,
    init_balloon_size: u64,
    vm_memory_client: VmMemoryClient,
    enabled_features: u64,
    #[cfg(feature = "registered_events")] registered_evt_q: Option<SendTube>,
    ws_num_bins: u8,
) -> DeviceResult {
    let dev = virtio::Balloon::new(
        virtio::base_features(protection_type),
        tube,
        vm_memory_client,
        inflate_tube,
        init_balloon_size,
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

#[cfg(feature = "pvclock")]
pub fn create_pvclock_device(
    protection_type: ProtectionType,
    jail_config: Option<&JailConfig>,
    tsc_frequency: u64,
    suspend_tube: Tube,
) -> DeviceResult {
    let dev = PvClock::new(
        virtio::base_features(protection_type),
        tsc_frequency,
        suspend_tube,
    );

    Ok(VirtioDeviceStub {
        dev: Box::new(dev),
        jail: simple_jail(jail_config, "pvclock_device")?,
    })
}

#[cfg(feature = "net")]
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
                    self.pci_address,
                    self.mrg_rxbuf,
                )
                .context("failed to set up virtio-vhost networking")?,
            ) as Box<dyn VirtioDevice>
        } else {
            Box::new(
                virtio::Net::new(
                    features,
                    tap,
                    vq_pairs,
                    mac,
                    self.packed_queue,
                    self.pci_address,
                    self.mrg_rxbuf,
                )
                .context("failed to set up virtio networking")?,
            ) as Box<dyn VirtioDevice>
        })
    }

    fn create_jail(
        &self,
        jail_config: Option<&JailConfig>,
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
    ) -> anyhow::Result<Box<dyn VhostUserDeviceBuilder>> {
        let vq_pairs = self.vq_pairs.unwrap_or(1);
        let multi_vq = vq_pairs > 1 && self.vhost_net.is_none();
        let (tap, _mac) = create_tap_for_net_device(&self.mode, multi_vq)?;

        let backend = NetBackend::new(tap, self.mrg_rxbuf)?;

        keep_rds.extend(backend.as_raw_descriptors());

        Ok(Box::new(backend))
    }
}

/// Create a new tap interface based on NetParametersMode.
#[cfg(feature = "net")]
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
            // SAFETY:
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

pub fn create_wayland_device(
    protection_type: ProtectionType,
    jail_config: Option<&JailConfig>,
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
            /* snapshot_scratch_path= */ None,
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
fn create_video_device_jail(
    backend: VideoBackendType,
    jail_config: &JailConfig,
    typ: VideoDeviceType,
) -> Result<Minijail> {
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

    #[cfg(target_arch = "x86_64")]
    {
        // Device nodes used by libdrm through minigbm in libvda on AMD devices.
        let sys_dev_char_path = Path::new("/sys/dev/char");
        jail.mount_bind(sys_dev_char_path, sys_dev_char_path, false)?;
        let sys_devices_path = Path::new("/sys/devices");
        jail.mount_bind(sys_devices_path, sys_devices_path, false)?;

        // Required for loading dri or vulkan libraries loaded by minigbm on AMD devices.
        jail_mount_bind_if_exists(&mut jail, &["/usr/lib64", "/usr/lib", "/usr/share/vulkan"])?;
    }

    // Device nodes required by libchrome which establishes Mojo connection in libvda.
    let dev_urandom_path = Path::new("/dev/urandom");
    jail.mount_bind(dev_urandom_path, dev_urandom_path, false)?;
    let system_bus_socket_path = Path::new("/run/dbus/system_bus_socket");
    jail.mount_bind(system_bus_socket_path, system_bus_socket_path, true)?;

    Ok(jail)
}

#[cfg(any(feature = "video-decoder", feature = "video-encoder"))]
pub fn create_video_device(
    backend: VideoBackendType,
    protection_type: ProtectionType,
    jail_config: Option<&JailConfig>,
    typ: VideoDeviceType,
    resource_bridge: Tube,
) -> DeviceResult {
    let jail = if let Some(jail_config) = jail_config {
        Some(create_video_device_jail(backend, jail_config, typ)?)
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
    jail_config: Option<&JailConfig>,
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

#[cfg(feature = "media")]
pub fn create_simple_media_device(protection_type: ProtectionType) -> DeviceResult {
    use devices::virtio::media::create_virtio_media_simple_capture_device;

    let features = virtio::base_features(protection_type);
    let dev = create_virtio_media_simple_capture_device(features);

    Ok(VirtioDeviceStub { dev, jail: None })
}

#[cfg(any(target_os = "android", target_os = "linux"))]
#[cfg(feature = "media")]
pub fn create_v4l2_device<P: AsRef<Path>>(
    protection_type: ProtectionType,
    path: P,
) -> DeviceResult {
    use devices::virtio::media::create_virtio_media_v4l2_proxy_device;

    let features = virtio::base_features(protection_type);
    let dev = create_virtio_media_v4l2_proxy_device(features, path)?;

    Ok(VirtioDeviceStub { dev, jail: None })
}

#[cfg(all(feature = "media", feature = "video-decoder"))]
pub fn create_virtio_media_adapter(
    protection_type: ProtectionType,
    jail_config: Option<&JailConfig>,
    tube: Tube,
    backend: VideoBackendType,
) -> DeviceResult {
    use devices::virtio::media::create_virtio_media_decoder_adapter_device;

    let jail = if let Some(jail_config) = jail_config {
        Some(create_video_device_jail(
            backend,
            jail_config,
            VideoDeviceType::Decoder,
        )?)
    } else {
        None
    };

    let features = virtio::base_features(protection_type);
    let dev = create_virtio_media_decoder_adapter_device(features, tube, backend)?;

    Ok(VirtioDeviceStub { dev, jail })
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
    ) -> anyhow::Result<Box<dyn VhostUserDeviceBuilder>> {
        if self.max_queue_sizes.is_some() {
            bail!("vhost-user vsock doesn't support max-queue-sizes option");
        }

        let vsock_device = VhostUserVsockDevice::new(self.cid, &self.vhost_device)?;

        keep_rds.push(vsock_device.as_raw_descriptor());

        Ok(Box::new(vsock_device))
    }
}

#[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
pub fn create_vhost_scmi_device(
    protected_vm: ProtectionType,
    jail_config: Option<&JailConfig>,
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
    jail_config: Option<&JailConfig>,
    ugid: (Option<u32>, Option<u32>),
    uid_map: &str,
    gid_map: &str,
    src: &Path,
    tag: &str,
    fs_cfg: virtio::fs::Config,
    device_tube: Tube,
) -> DeviceResult {
    let max_open_files = base::linux::max_open_files()
        .context("failed to get max number of open files")?
        .rlim_max;
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
    jail_config: Option<&JailConfig>,
    ugid: (Option<u32>, Option<u32>),
    uid_map: &str,
    gid_map: &str,
    src: &Path,
    tag: &str,
    mut p9_cfg: p9::Config,
) -> DeviceResult {
    let max_open_files = base::linux::max_open_files()
        .context("failed to get max number of open files")?
        .rlim_max;
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
    jail_config: Option<&JailConfig>,
    vm: &mut impl Vm,
    resources: &mut SystemAllocator,
    pmem: &PmemOption,
    index: usize,
    pmem_device_tube: Tube,
) -> DeviceResult {
    let (fd, disk_size) = match pmem.vma_size {
        None => {
            let disk_image =
                open_file_or_duplicate(&pmem.path, OpenOptions::new().read(true).write(!pmem.ro))
                    .with_context(|| format!("failed to load disk image {}", pmem.path.display()))?;
            let metadata = std::fs::metadata(&pmem.path).with_context(|| {
                format!("failed to get disk image {} metadata", pmem.path.display())
            })?;
            (disk_image, metadata.len())
        }
        Some(size) => {
            let anon_file =
                create_anonymous_file(&pmem.path, size).context("failed to create anon file")?;
            (anon_file, size)
        }
    };

    // Linux requires pmem region sizes to be 2 MiB aligned. Linux will fill any partial page
    // at the end of an mmap'd file and won't write back beyond the actual file length, but if
    // we just align the size of the file to 2 MiB then access beyond the last page of the
    // mapped file will generate SIGBUS. So use a memory mapping arena that will provide
    // padding up to 2 MiB.
    let alignment = 2 * 1024 * 1024;
    let arena_size = disk_size
        .checked_next_multiple_of(alignment)
        .ok_or_else(|| anyhow!("pmem device image too big"))?;

    let protection = {
        if pmem.ro {
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

    let mapping_address = GuestAddress(
        resources
            .allocate_mmio(
                arena_size,
                Alloc::PmemDevice(index),
                format!("pmem_disk_image_{}", index),
                AllocOptions::new()
                // Allocate from the bottom up rather than top down to avoid exceeding PHYSMEM_END
                // with kaslr.
                // TODO: b/375506171: Find a proper fix.
                .top_down(false)
                .prefetchable(true)
                // Linux kernel requires pmem namespaces to be 128 MiB aligned.
                // cf. https://github.com/pmem/ndctl/issues/76
                .align(128 * 1024 * 1024), /* 128 MiB */
            )
            .context("failed to allocate memory for pmem device")?,
    );

    let mem_slot = MemSlotConfig::MemSlot {
        idx: vm
            .add_memory_region(
                mapping_address,
                Box::new(arena),
                /* read_only = */ pmem.ro,
                /* log_dirty_pages = */ false,
                MemCacheType::CacheCoherent,
            )
            .context("failed to add pmem device memory")?,
    };

    let dev = virtio::Pmem::new(
        virtio::base_features(protection_type),
        PmemConfig {
            disk_image: Some(fd),
            mapping_address,
            mem_slot,
            mapping_size: arena_size,
            pmem_device_tube,
            swap_interval: pmem.swap_interval,
            mapping_writable: !pmem.ro,
        },
    )
    .context("failed to create pmem device")?;

    Ok(VirtioDeviceStub {
        dev: Box::new(dev) as Box<dyn VirtioDevice>,
        jail: simple_jail(jail_config, "pmem_device")?,
    })
}

pub fn create_pmem_ext2_device(
    protection_type: ProtectionType,
    jail_config: Option<&JailConfig>,
    resources: &mut SystemAllocator,
    opts: &PmemExt2Option,
    index: usize,
    vm_memory_client: VmMemoryClient,
    pmem_device_tube: Tube,
    worker_process_pids: &mut BTreeSet<Pid>,
) -> DeviceResult {
    let mapping_size = opts.size as u64;
    let builder = ext2::Builder {
        inodes_per_group: opts.inodes_per_group,
        blocks_per_group: opts.blocks_per_group,
        size: mapping_size as u32,
        ..Default::default()
    };

    let max_open_files = base::linux::max_open_files()
        .context("failed to get max number of open files")?
        .rlim_max;
    let mapping_address = GuestAddress(
        resources
            .allocate_mmio(
                mapping_size,
                Alloc::PmemDevice(index),
                format!("pmem_ext2_image_{}", index),
                AllocOptions::new()
                .top_down(true)
                .prefetchable(true)
                // 2MB alignment for DAX
                // cf. https://docs.pmem.io/persistent-memory/getting-started-guide/creating-development-environments/linux-environments/advanced-topics/i-o-alignment-considerations#verifying-io-alignment
                .align(2 * 1024 * 1024),
            )
            .context("failed to allocate memory for pmem device")?,
    );

    let (mkfs_tube, mkfs_device_tube) = Tube::pair().context("failed to create tube")?;

    let ext2_proc_pid = crate::crosvm::sys::linux::ext2::launch(
        mapping_address,
        vm_memory_client,
        mkfs_tube,
        &opts.path,
        &opts.ugid,
        (&opts.uid_map, &opts.gid_map),
        builder,
        jail_config,
    )
    .context("failed to spawn mkfs process")?;

    worker_process_pids.insert(ext2_proc_pid);

    let dev = virtio::Pmem::new(
        virtio::base_features(protection_type),
        PmemConfig {
            disk_image: None,
            mapping_address,
            mem_slot: MemSlotConfig::LazyInit {
                tube: mkfs_device_tube,
            },
            mapping_size,
            pmem_device_tube,
            swap_interval: None,
            mapping_writable: false,
        },
    )
    .context("failed to create pmem device")?;

    let j = if let Some(jail_config) = jail_config {
        let mut config = SandboxConfig::new(jail_config, "pmem_device");
        config.limit_caps = false;
        create_sandbox_minijail(&opts.path, max_open_files, &config)?
    } else {
        create_base_minijail(&opts.path, max_open_files)?
    };
    Ok(VirtioDeviceStub {
        dev: Box::new(dev) as Box<dyn VirtioDevice>,
        jail: Some(j),
    })
}

pub fn create_anonymous_file<P: AsRef<Path>>(path: P, size: u64) -> Result<File> {
    let file_name = path
        .as_ref()
        .to_str()
        .ok_or_else(|| Error::new(libc::EINVAL))?;
    let mut shm = SharedMemory::new(file_name, size)?;
    let mut seals = MemfdSeals::new();

    seals.set_shrink_seal();
    seals.set_grow_seal();
    seals.set_seal_seal();
    shm.add_seals(seals)?;

    Ok(shm.descriptor.into())
}

pub fn create_iommu_device(
    protection_type: ProtectionType,
    jail_config: Option<&JailConfig>,
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

        Ok(Box::new(
            self.create_serial_device::<Console>(protection_type, &evt, &mut keep_rds)
                .context("failed to create console device")?,
        ))
    }

    fn create_vhost_user_device(
        self,
        keep_rds: &mut Vec<RawDescriptor>,
    ) -> anyhow::Result<Box<dyn VhostUserDeviceBuilder>> {
        Ok(Box::new(
            virtio::vhost_user_backend::create_vu_console_device(self, keep_rds)?,
        ))
    }

    fn create_jail(
        &self,
        jail_config: Option<&JailConfig>,
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
    jail_config: Option<&JailConfig>,
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
    jail_config: Option<&JailConfig>,
    vm: &impl Vm,
    resources: &mut SystemAllocator,
    add_control_tube: &mut impl FnMut(AnyControlTube),
    vfio_path: &Path,
    hotplug: bool,
    hotplug_bus: Option<u8>,
    guest_address: Option<PciAddress>,
    coiommu_endpoints: Option<&mut Vec<u16>>,
    iommu_dev: IommuDevType,
    dt_symbol: Option<String>,
    vfio_container_manager: &mut VfioContainerManager,
) -> DeviceResult<(VfioDeviceVariant, Option<Minijail>, Option<VfioWrapper>)> {
    let vfio_container = vfio_container_manager
        .get_container(iommu_dev, Some(vfio_path))
        .context("failed to get vfio container")?;

    let (vfio_host_tube_mem, vfio_device_tube_mem) =
        Tube::pair().context("failed to create tube")?;
    add_control_tube(
        VmMemoryTube {
            tube: vfio_host_tube_mem,
            expose_with_viommu: false,
        }
        .into(),
    );

    let (vfio_host_tube_vm, vfio_device_tube_vm) = Tube::pair().context("failed to create tube")?;
    add_control_tube(TaggedControlTube::Vm(vfio_host_tube_vm).into());

    let vfio_device =
        VfioDevice::new_passthrough(&vfio_path, vm, vfio_container.clone(), iommu_dev, dt_symbol)
            .context("failed to create vfio device")?;

    match vfio_device.device_type() {
        VfioDeviceType::Pci => {
            let (vfio_host_tube_msi, vfio_device_tube_msi) =
                Tube::pair().context("failed to create tube")?;
            add_control_tube(AnyControlTube::IrqTube(vfio_host_tube_msi));

            let (vfio_host_tube_msix, vfio_device_tube_msix) =
                Tube::pair().context("failed to create tube")?;
            add_control_tube(AnyControlTube::IrqTube(vfio_host_tube_msix));

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
                IommuDevType::NoIommu | IommuDevType::PkvmPviommu => None,
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
