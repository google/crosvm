// Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::cmp::Reverse;
use std::collections::BTreeMap;
use std::convert::TryFrom;
#[cfg(feature = "gpu")]
use std::env;
use std::ffi::CStr;
use std::fs::{File, OpenOptions};
use std::io::{self, stdin};
use std::iter;
use std::mem;
use std::net::Ipv4Addr;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::ptr;
use std::str;
use std::sync::{mpsc, Arc, Barrier};
use std::time::Duration;

use std::thread;
use std::thread::JoinHandle;

use libc::{self, c_int, gid_t, uid_t, EINVAL};

use acpi_tables::sdt::SDT;

use crate::error::{Error, Result};
use base::net::{UnixSeqpacket, UnixSeqpacketListener, UnlinkUnixSeqpacketListener};
use base::*;
use devices::vfio::{VfioCommonSetup, VfioCommonTrait};
#[cfg(feature = "gpu")]
use devices::virtio::gpu::{DEFAULT_DISPLAY_HEIGHT, DEFAULT_DISPLAY_WIDTH};
use devices::virtio::vhost::user::{
    Block as VhostUserBlock, Console as VhostUserConsole, Fs as VhostUserFs,
    Mac80211Hwsim as VhostUserMac80211Hwsim, Net as VhostUserNet, Wl as VhostUserWl,
};
#[cfg(feature = "gpu")]
use devices::virtio::EventDevice;
use devices::virtio::{self, Console, VirtioDevice};
#[cfg(feature = "audio")]
use devices::Ac97Dev;
use devices::ProtectionType;
use devices::{
    self, IrqChip, IrqEventIndex, KvmKernelIrqChip, PciDevice, VcpuRunState, VfioContainer,
    VfioDevice, VfioPciDevice, VirtioPciDevice,
};
#[cfg(feature = "usb")]
use devices::{HostBackendDeviceProvider, XhciController};
use hypervisor::kvm::{Kvm, KvmVcpu, KvmVm};
use hypervisor::{DeviceKind, HypervisorCap, Vcpu, VcpuExit, VcpuRunHandle, Vm, VmCap};
use minijail::{self, Minijail};
use net_util::{MacAddress, Tap};
use resources::{Alloc, MmioType, SystemAllocator};
use rutabaga_gfx::RutabagaGralloc;
use sync::Mutex;
use vm_control::*;
use vm_memory::{GuestAddress, GuestMemory, MemoryPolicy};

#[cfg(all(target_arch = "x86_64", feature = "gdb"))]
use crate::gdb::{gdb_thread, GdbStub};
use crate::{
    Config, DiskOption, Executable, SharedDir, SharedDirKind, TouchDeviceOption, VhostUserFsOption,
    VhostUserOption, VhostUserWlOption,
};
use arch::{
    self, LinuxArch, RunnableLinuxVm, SerialHardware, SerialParameters, VcpuAffinity,
    VirtioDeviceStub, VmComponents, VmImage,
};

#[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
use {
    aarch64::AArch64 as Arch,
    devices::IrqChipAArch64 as IrqChipArch,
    hypervisor::{VcpuAArch64 as VcpuArch, VmAArch64 as VmArch},
};
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
use {
    devices::{IrqChipX86_64 as IrqChipArch, KvmSplitIrqChip},
    hypervisor::{VcpuX86_64 as VcpuArch, VmX86_64 as VmArch},
    x86_64::X8664arch as Arch,
};

enum TaggedControlTube {
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

fn get_max_open_files() -> Result<u64> {
    let mut buf = mem::MaybeUninit::<libc::rlimit64>::zeroed();

    // Safe because this will only modify `buf` and we check the return value.
    let res = unsafe { libc::prlimit64(0, libc::RLIMIT_NOFILE, ptr::null(), buf.as_mut_ptr()) };
    if res == 0 {
        // Safe because the kernel guarantees that the struct is fully initialized.
        let limit = unsafe { buf.assume_init() };
        Ok(limit.rlim_max)
    } else {
        Err(Error::GetMaxOpenFiles(io::Error::last_os_error()))
    }
}

struct SandboxConfig<'a> {
    limit_caps: bool,
    log_failures: bool,
    seccomp_policy: &'a Path,
    uid_map: Option<&'a str>,
    gid_map: Option<&'a str>,
}

fn create_base_minijail(
    root: &Path,
    r_limit: Option<u64>,
    config: Option<&SandboxConfig>,
) -> Result<Minijail> {
    // All child jails run in a new user namespace without any users mapped,
    // they run as nobody unless otherwise configured.
    let mut j = Minijail::new().map_err(Error::DeviceJail)?;

    if let Some(config) = config {
        j.namespace_pids();
        j.namespace_user();
        j.namespace_user_disable_setgroups();
        if config.limit_caps {
            // Don't need any capabilities.
            j.use_caps(0);
        }
        if let Some(uid_map) = config.uid_map {
            j.uidmap(uid_map).map_err(Error::SettingUidMap)?;
        }
        if let Some(gid_map) = config.gid_map {
            j.gidmap(gid_map).map_err(Error::SettingGidMap)?;
        }
        // Run in a new mount namespace.
        j.namespace_vfs();

        // Run in an empty network namespace.
        j.namespace_net();

        // Don't allow the device to gain new privileges.
        j.no_new_privs();

        // By default we'll prioritize using the pre-compiled .bpf over the .policy
        // file (the .bpf is expected to be compiled using "trap" as the failure
        // behavior instead of the default "kill" behavior).
        // Refer to the code comment for the "seccomp-log-failures"
        // command-line parameter for an explanation about why the |log_failures|
        // flag forces the use of .policy files (and the build-time alternative to
        // this run-time flag).
        let bpf_policy_file = config.seccomp_policy.with_extension("bpf");
        if bpf_policy_file.exists() && !config.log_failures {
            j.parse_seccomp_program(&bpf_policy_file)
                .map_err(Error::DeviceJail)?;
        } else {
            // Use TSYNC only for the side effect of it using SECCOMP_RET_TRAP,
            // which will correctly kill the entire device process if a worker
            // thread commits a seccomp violation.
            j.set_seccomp_filter_tsync();
            if config.log_failures {
                j.log_seccomp_filter_failures();
            }
            j.parse_seccomp_filters(&config.seccomp_policy.with_extension("policy"))
                .map_err(Error::DeviceJail)?;
        }
        j.use_seccomp_filter();
        // Don't do init setup.
        j.run_as_init();
    }

    // Only pivot_root if we are not re-using the current root directory.
    if root != Path::new("/") {
        // It's safe to call `namespace_vfs` multiple times.
        j.namespace_vfs();
        j.enter_pivot_root(root).map_err(Error::DevicePivotRoot)?;
    }

    // Most devices don't need to open many fds.
    let limit = if let Some(r) = r_limit { r } else { 1024u64 };
    j.set_rlimit(libc::RLIMIT_NOFILE as i32, limit, limit)
        .map_err(Error::SettingMaxOpenFiles)?;

    Ok(j)
}

fn simple_jail(cfg: &Config, policy: &str) -> Result<Option<Minijail>> {
    if cfg.sandbox {
        let pivot_root: &str = option_env!("DEFAULT_PIVOT_ROOT").unwrap_or("/var/empty");
        // A directory for a jailed device's pivot root.
        let root_path = Path::new(pivot_root);
        if !root_path.exists() {
            return Err(Error::PivotRootDoesntExist(pivot_root));
        }
        let policy_path: PathBuf = cfg.seccomp_policy_dir.join(policy);
        let config = SandboxConfig {
            limit_caps: true,
            log_failures: cfg.seccomp_log_failures,
            seccomp_policy: &policy_path,
            uid_map: None,
            gid_map: None,
        };
        Ok(Some(create_base_minijail(root_path, None, Some(&config))?))
    } else {
        Ok(None)
    }
}

type DeviceResult<T = VirtioDeviceStub> = std::result::Result<T, Error>;

fn create_block_device(cfg: &Config, disk: &DiskOption, disk_device_tube: Tube) -> DeviceResult {
    let raw_image: File = open_file(&disk.path, disk.read_only, disk.o_direct)
        .map_err(|e| Error::Disk(disk.path.clone(), e.into()))?;
    // Lock the disk image to prevent other crosvm instances from using it.
    let lock_op = if disk.read_only {
        FlockOperation::LockShared
    } else {
        FlockOperation::LockExclusive
    };
    flock(&raw_image, lock_op, true).map_err(Error::DiskImageLock)?;

    let dev = if disk::async_ok(&raw_image).map_err(Error::CreateDiskError)? {
        let async_file = disk::create_async_disk_file(raw_image).map_err(Error::CreateDiskError)?;
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
            .map_err(Error::BlockDeviceNew)?,
        ) as Box<dyn VirtioDevice>
    } else {
        let disk_file = disk::create_disk_file(raw_image).map_err(Error::CreateDiskError)?;
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
            .map_err(Error::BlockDeviceNew)?,
        ) as Box<dyn VirtioDevice>
    };

    Ok(VirtioDeviceStub {
        dev,
        jail: simple_jail(&cfg, "block_device")?,
    })
}

fn create_vhost_user_block_device(cfg: &Config, opt: &VhostUserOption) -> DeviceResult {
    let dev = VhostUserBlock::new(virtio::base_features(cfg.protected_vm), &opt.socket)
        .map_err(Error::VhostUserBlockDeviceNew)?;

    Ok(VirtioDeviceStub {
        dev: Box::new(dev),
        // no sandbox here because virtqueue handling is exported to a different process.
        jail: None,
    })
}

fn create_vhost_user_console_device(cfg: &Config, opt: &VhostUserOption) -> DeviceResult {
    let dev = VhostUserConsole::new(virtio::base_features(cfg.protected_vm), &opt.socket)
        .map_err(Error::VhostUserConsoleDeviceNew)?;

    Ok(VirtioDeviceStub {
        dev: Box::new(dev),
        // no sandbox here because virtqueue handling is exported to a different process.
        jail: None,
    })
}

fn create_vhost_user_fs_device(cfg: &Config, option: &VhostUserFsOption) -> DeviceResult {
    let dev = VhostUserFs::new(
        virtio::base_features(cfg.protected_vm),
        &option.socket,
        &option.tag,
    )
    .map_err(Error::VhostUserFsDeviceNew)?;

    Ok(VirtioDeviceStub {
        dev: Box::new(dev),
        // no sandbox here because virtqueue handling is exported to a different process.
        jail: None,
    })
}

fn create_vhost_user_mac80211_hwsim_device(cfg: &Config, opt: &VhostUserOption) -> DeviceResult {
    let dev = VhostUserMac80211Hwsim::new(virtio::base_features(cfg.protected_vm), &opt.socket)
        .map_err(Error::VhostUserMac80211HwsimNew)?;

    Ok(VirtioDeviceStub {
        dev: Box::new(dev),
        // no sandbox here because virtqueue handling is exported to a different process.
        jail: None,
    })
}

fn create_rng_device(cfg: &Config) -> DeviceResult {
    let dev =
        virtio::Rng::new(virtio::base_features(cfg.protected_vm)).map_err(Error::RngDeviceNew)?;

    Ok(VirtioDeviceStub {
        dev: Box::new(dev),
        jail: simple_jail(&cfg, "rng_device")?,
    })
}

#[cfg(feature = "tpm")]
fn create_tpm_device(cfg: &Config) -> DeviceResult {
    use std::ffi::CString;
    use std::fs;
    use std::process;

    let tpm_storage: PathBuf;
    let mut tpm_jail = simple_jail(&cfg, "tpm_device")?;

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

            let crosvm_ids = add_crosvm_user_to_jail(jail, "tpm")?;

            let pid = process::id();
            let tpm_pid_dir = format!("/run/vm/tpm.{}", pid);
            tpm_storage = Path::new(&tpm_pid_dir).to_owned();
            fs::create_dir_all(&tpm_storage)
                .map_err(|e| Error::CreateTpmStorage(tpm_storage.to_owned(), e))?;
            let tpm_pid_dir_c = CString::new(tpm_pid_dir).expect("no nul bytes");
            chown(&tpm_pid_dir_c, crosvm_ids.uid, crosvm_ids.gid)
                .map_err(Error::ChownTpmStorage)?;

            jail.mount_bind(&tpm_storage, &tpm_storage, true)?;
        }
        None => {
            // Path used inside cros_sdk which does not have /run/vm.
            tpm_storage = Path::new("/tmp/tpm-simulator").to_owned();
        }
    }

    let dev = virtio::Tpm::new(tpm_storage);

    Ok(VirtioDeviceStub {
        dev: Box::new(dev),
        jail: tpm_jail,
    })
}

fn create_single_touch_device(
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
    .map_err(Error::InputDeviceNew)?;
    Ok(VirtioDeviceStub {
        dev: Box::new(dev),
        jail: simple_jail(&cfg, "input_device")?,
    })
}

fn create_multi_touch_device(
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
    .map_err(Error::InputDeviceNew)?;

    Ok(VirtioDeviceStub {
        dev: Box::new(dev),
        jail: simple_jail(&cfg, "input_device")?,
    })
}

fn create_trackpad_device(
    cfg: &Config,
    trackpad_spec: &TouchDeviceOption,
    idx: u32,
) -> DeviceResult {
    let socket = trackpad_spec.get_path().into_unix_stream().map_err(|e| {
        error!("failed configuring virtio trackpad: {}", e);
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
    .map_err(Error::InputDeviceNew)?;

    Ok(VirtioDeviceStub {
        dev: Box::new(dev),
        jail: simple_jail(&cfg, "input_device")?,
    })
}

fn create_mouse_device<T: IntoUnixStream>(cfg: &Config, mouse_socket: T, idx: u32) -> DeviceResult {
    let socket = mouse_socket.into_unix_stream().map_err(|e| {
        error!("failed configuring virtio mouse: {}", e);
        e
    })?;

    let dev = virtio::new_mouse(idx, socket, virtio::base_features(cfg.protected_vm))
        .map_err(Error::InputDeviceNew)?;

    Ok(VirtioDeviceStub {
        dev: Box::new(dev),
        jail: simple_jail(&cfg, "input_device")?,
    })
}

fn create_keyboard_device<T: IntoUnixStream>(
    cfg: &Config,
    keyboard_socket: T,
    idx: u32,
) -> DeviceResult {
    let socket = keyboard_socket.into_unix_stream().map_err(|e| {
        error!("failed configuring virtio keyboard: {}", e);
        e
    })?;

    let dev = virtio::new_keyboard(idx, socket, virtio::base_features(cfg.protected_vm))
        .map_err(Error::InputDeviceNew)?;

    Ok(VirtioDeviceStub {
        dev: Box::new(dev),
        jail: simple_jail(&cfg, "input_device")?,
    })
}

fn create_switches_device<T: IntoUnixStream>(
    cfg: &Config,
    switches_socket: T,
    idx: u32,
) -> DeviceResult {
    let socket = switches_socket.into_unix_stream().map_err(|e| {
        error!("failed configuring virtio switches: {}", e);
        e
    })?;

    let dev = virtio::new_switches(idx, socket, virtio::base_features(cfg.protected_vm))
        .map_err(Error::InputDeviceNew)?;

    Ok(VirtioDeviceStub {
        dev: Box::new(dev),
        jail: simple_jail(&cfg, "input_device")?,
    })
}

fn create_vinput_device(cfg: &Config, dev_path: &Path) -> DeviceResult {
    let dev_file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(dev_path)
        .map_err(|e| Error::OpenVinput(dev_path.to_owned(), e))?;

    let dev = virtio::new_evdev(dev_file, virtio::base_features(cfg.protected_vm))
        .map_err(Error::InputDeviceNew)?;

    Ok(VirtioDeviceStub {
        dev: Box::new(dev),
        jail: simple_jail(&cfg, "input_device")?,
    })
}

fn create_balloon_device(cfg: &Config, tube: Tube) -> DeviceResult {
    let dev = virtio::Balloon::new(virtio::base_features(cfg.protected_vm), tube)
        .map_err(Error::BalloonDeviceNew)?;

    Ok(VirtioDeviceStub {
        dev: Box::new(dev),
        jail: simple_jail(&cfg, "balloon_device")?,
    })
}

fn create_tap_net_device(cfg: &Config, tap_fd: RawDescriptor) -> DeviceResult {
    // Safe because we ensure that we get a unique handle to the fd.
    let tap = unsafe {
        Tap::from_raw_descriptor(
            validate_raw_descriptor(tap_fd).map_err(Error::ValidateRawDescriptor)?,
        )
        .map_err(Error::CreateTapDevice)?
    };

    let mut vq_pairs = cfg.net_vq_pairs.unwrap_or(1);
    let vcpu_count = cfg.vcpu_count.unwrap_or(1);
    if vcpu_count < vq_pairs as usize {
        error!("net vq pairs must be smaller than vcpu count, fall back to single queue mode");
        vq_pairs = 1;
    }
    let features = virtio::base_features(cfg.protected_vm);
    let dev = virtio::Net::from(features, tap, vq_pairs).map_err(Error::NetDeviceNew)?;

    Ok(VirtioDeviceStub {
        dev: Box::new(dev),
        jail: simple_jail(&cfg, "net_device")?,
    })
}

fn create_net_device(
    cfg: &Config,
    host_ip: Ipv4Addr,
    netmask: Ipv4Addr,
    mac_address: MacAddress,
    mem: &GuestMemory,
) -> DeviceResult {
    let mut vq_pairs = cfg.net_vq_pairs.unwrap_or(1);
    let vcpu_count = cfg.vcpu_count.unwrap_or(1);
    if vcpu_count < vq_pairs as usize {
        error!("net vq pairs must be smaller than vcpu count, fall back to single queue mode");
        vq_pairs = 1;
    }

    let features = virtio::base_features(cfg.protected_vm);
    let dev = if cfg.vhost_net {
        let dev = virtio::vhost::Net::<Tap, vhost::Net<Tap>>::new(
            &cfg.vhost_net_device_path,
            features,
            host_ip,
            netmask,
            mac_address,
            mem,
        )
        .map_err(Error::VhostNetDeviceNew)?;
        Box::new(dev) as Box<dyn VirtioDevice>
    } else {
        let dev = virtio::Net::<Tap>::new(features, host_ip, netmask, mac_address, vq_pairs)
            .map_err(Error::NetDeviceNew)?;
        Box::new(dev) as Box<dyn VirtioDevice>
    };

    let policy = if cfg.vhost_net {
        "vhost_net_device"
    } else {
        "net_device"
    };

    Ok(VirtioDeviceStub {
        dev,
        jail: simple_jail(&cfg, policy)?,
    })
}

fn create_vhost_user_net_device(cfg: &Config, opt: &VhostUserOption) -> DeviceResult {
    let dev = VhostUserNet::new(virtio::base_features(cfg.protected_vm), &opt.socket)
        .map_err(Error::VhostUserNetDeviceNew)?;

    Ok(VirtioDeviceStub {
        dev: Box::new(dev),
        // no sandbox here because virtqueue handling is exported to a different process.
        jail: None,
    })
}

fn create_vhost_user_wl_device(cfg: &Config, opt: &VhostUserWlOption) -> DeviceResult {
    // The crosvm wl device expects us to connect the tube before it will accept a vhost-user
    // connection.
    let dev = VhostUserWl::new(virtio::base_features(cfg.protected_vm), &opt.socket)
        .map_err(Error::VhostUserWlDeviceNew)?;

    Ok(VirtioDeviceStub {
        dev: Box::new(dev),
        // no sandbox here because virtqueue handling is exported to a different process.
        jail: None,
    })
}

#[cfg(feature = "gpu")]
fn create_gpu_device(
    cfg: &Config,
    exit_evt: &Event,
    gpu_device_tube: Tube,
    resource_bridges: Vec<Tube>,
    wayland_socket_path: Option<&PathBuf>,
    x_display: Option<String>,
    event_devices: Vec<EventDevice>,
    map_request: Arc<Mutex<Option<ExternalMapping>>>,
) -> DeviceResult {
    let mut display_backends = vec![
        virtio::DisplayBackend::X(x_display),
        virtio::DisplayBackend::Stub,
    ];

    let wayland_socket_dirs = cfg
        .wayland_socket_paths
        .iter()
        .map(|(_name, path)| path.parent())
        .collect::<Option<Vec<_>>>()
        .ok_or(Error::InvalidWaylandPath)?;

    if let Some(socket_path) = wayland_socket_path {
        display_backends.insert(
            0,
            virtio::DisplayBackend::Wayland(Some(socket_path.to_owned())),
        );
    }

    let dev = virtio::Gpu::new(
        exit_evt.try_clone().map_err(Error::CloneEvent)?,
        Some(gpu_device_tube),
        resource_bridges,
        display_backends,
        cfg.gpu_parameters.as_ref().unwrap(),
        event_devices,
        map_request,
        cfg.sandbox,
        virtio::base_features(cfg.protected_vm),
        cfg.wayland_socket_paths.clone(),
    );

    let jail = match simple_jail(&cfg, "gpu_device")? {
        Some(mut jail) => {
            // Create a tmpfs in the device's root directory so that we can bind mount the
            // dri directory into it.  The size=67108864 is size=64*1024*1024 or size=64MB.
            jail.mount_with_data(
                Path::new("none"),
                Path::new("/"),
                "tmpfs",
                (libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC) as usize,
                "size=67108864",
            )?;

            // Device nodes required for DRM.
            let sys_dev_char_path = Path::new("/sys/dev/char");
            jail.mount_bind(sys_dev_char_path, sys_dev_char_path, false)?;
            let sys_devices_path = Path::new("/sys/devices");
            jail.mount_bind(sys_devices_path, sys_devices_path, false)?;

            let drm_dri_path = Path::new("/dev/dri");
            if drm_dri_path.exists() {
                jail.mount_bind(drm_dri_path, drm_dri_path, false)?;
            }

            // Prepare GPU shader disk cache directory.
            if let Some(cache_dir) = cfg
                .gpu_parameters
                .as_ref()
                .and_then(|params| params.cache_path.as_ref())
            {
                if cfg!(any(target_arch = "arm", target_arch = "aarch64")) && cfg.sandbox {
                    warn!("shader caching not yet supported on ARM with sandbox enabled");
                    env::set_var("MESA_GLSL_CACHE_DISABLE", "true");
                } else {
                    env::set_var("MESA_GLSL_CACHE_DISABLE", "false");
                    env::set_var("MESA_GLSL_CACHE_DIR", cache_dir);
                    if let Some(cache_size) = cfg
                        .gpu_parameters
                        .as_ref()
                        .and_then(|params| params.cache_size.as_ref())
                    {
                        env::set_var("MESA_GLSL_CACHE_MAX_SIZE", cache_size);
                    }
                    let shadercache_path = Path::new(cache_dir);
                    jail.mount_bind(shadercache_path, shadercache_path, true)?;
                }
            }

            // If the ARM specific devices exist on the host, bind mount them in.
            let mali0_path = Path::new("/dev/mali0");
            if mali0_path.exists() {
                jail.mount_bind(mali0_path, mali0_path, true)?;
            }

            let pvr_sync_path = Path::new("/dev/pvr_sync");
            if pvr_sync_path.exists() {
                jail.mount_bind(pvr_sync_path, pvr_sync_path, true)?;
            }

            // If the udmabuf driver exists on the host, bind mount it in.
            let udmabuf_path = Path::new("/dev/udmabuf");
            if udmabuf_path.exists() {
                jail.mount_bind(udmabuf_path, udmabuf_path, true)?;
            }

            // Libraries that are required when mesa drivers are dynamically loaded.
            let lib_dirs = &[
                "/usr/lib",
                "/usr/lib64",
                "/lib",
                "/lib64",
                "/usr/share/glvnd",
                "/usr/share/vulkan",
            ];
            for dir in lib_dirs {
                let dir_path = Path::new(dir);
                if dir_path.exists() {
                    jail.mount_bind(dir_path, dir_path, false)?;
                }
            }

            // Bind mount the wayland socket's directory into jail's root. This is necessary since
            // each new wayland context must open() the socket. If the wayland socket is ever
            // destroyed and remade in the same host directory, new connections will be possible
            // without restarting the wayland device.
            for dir in &wayland_socket_dirs {
                jail.mount_bind(dir, dir, true)?;
            }

            add_crosvm_user_to_jail(&mut jail, "gpu")?;

            // pvr driver requires read access to /proc/self/task/*/comm.
            let proc_path = Path::new("/proc");
            jail.mount(
                proc_path,
                proc_path,
                "proc",
                (libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC | libc::MS_RDONLY) as usize,
            )?;

            // To enable perfetto tracing, we need to give access to the perfetto service IPC
            // endpoints.
            let perfetto_path = Path::new("/run/perfetto");
            if perfetto_path.exists() {
                jail.mount_bind(perfetto_path, perfetto_path, true)?;
            }

            Some(jail)
        }
        None => None,
    };

    Ok(VirtioDeviceStub {
        dev: Box::new(dev),
        jail,
    })
}

fn create_wayland_device(
    cfg: &Config,
    control_tube: Tube,
    resource_bridge: Option<Tube>,
) -> DeviceResult {
    let wayland_socket_dirs = cfg
        .wayland_socket_paths
        .iter()
        .map(|(_name, path)| path.parent())
        .collect::<Option<Vec<_>>>()
        .ok_or(Error::InvalidWaylandPath)?;

    let features = virtio::base_features(cfg.protected_vm);
    let dev = virtio::Wl::new(
        features,
        cfg.wayland_socket_paths.clone(),
        control_tube,
        resource_bridge,
    )
    .map_err(Error::WaylandDeviceNew)?;

    let jail = match simple_jail(&cfg, "wl_device")? {
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
            add_crosvm_user_to_jail(&mut jail, "Wayland")?;

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
fn create_video_device(
    cfg: &Config,
    typ: devices::virtio::VideoDeviceType,
    resource_bridge: Tube,
) -> DeviceResult {
    let jail = match simple_jail(&cfg, "video_device")? {
        Some(mut jail) => {
            match typ {
                devices::virtio::VideoDeviceType::Decoder => {
                    add_crosvm_user_to_jail(&mut jail, "video-decoder")?
                }
                devices::virtio::VideoDeviceType::Encoder => {
                    add_crosvm_user_to_jail(&mut jail, "video-encoder")?
                }
            };

            // Create a tmpfs in the device's root directory so that we can bind mount files.
            jail.mount_with_data(
                Path::new("none"),
                Path::new("/"),
                "tmpfs",
                (libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC) as usize,
                "size=67108864",
            )?;

            // Render node for libvda.
            let dev_dri_path = Path::new("/dev/dri/renderD128");
            jail.mount_bind(dev_dri_path, dev_dri_path, false)?;

            #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
            {
                // Device nodes used by libdrm through minigbm in libvda on AMD devices.
                let sys_dev_char_path = Path::new("/sys/dev/char");
                jail.mount_bind(sys_dev_char_path, sys_dev_char_path, false)?;
                let sys_devices_path = Path::new("/sys/devices");
                jail.mount_bind(sys_devices_path, sys_devices_path, false)?;

                // Required for loading dri libraries loaded by minigbm on AMD devices.
                let lib_dir = Path::new("/usr/lib64");
                jail.mount_bind(lib_dir, lib_dir, false)?;
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
            Some(resource_bridge),
        )),
        jail,
    })
}

#[cfg(any(feature = "video-decoder", feature = "video-encoder"))]
fn register_video_device(
    devs: &mut Vec<VirtioDeviceStub>,
    video_tube: Tube,
    cfg: &Config,
    typ: devices::virtio::VideoDeviceType,
) -> std::result::Result<(), Error> {
    devs.push(create_video_device(cfg, typ, video_tube)?);
    Ok(())
}

fn create_vhost_vsock_device(cfg: &Config, cid: u64, mem: &GuestMemory) -> DeviceResult {
    let features = virtio::base_features(cfg.protected_vm);
    let dev = virtio::vhost::Vsock::new(&cfg.vhost_vsock_device_path, features, cid, mem)
        .map_err(Error::VhostVsockDeviceNew)?;

    Ok(VirtioDeviceStub {
        dev: Box::new(dev),
        jail: simple_jail(&cfg, "vhost_vsock_device")?,
    })
}

fn create_fs_device(
    cfg: &Config,
    uid_map: &str,
    gid_map: &str,
    src: &Path,
    tag: &str,
    fs_cfg: virtio::fs::passthrough::Config,
    device_tube: Tube,
) -> DeviceResult {
    let max_open_files = get_max_open_files()?;
    let j = if cfg.sandbox {
        let seccomp_policy = cfg.seccomp_policy_dir.join("fs_device");
        let config = SandboxConfig {
            limit_caps: false,
            uid_map: Some(uid_map),
            gid_map: Some(gid_map),
            log_failures: cfg.seccomp_log_failures,
            seccomp_policy: &seccomp_policy,
        };
        let mut jail = create_base_minijail(src, Some(max_open_files), Some(&config))?;
        // We want bind mounts from the parent namespaces to propagate into the fs device's
        // namespace.
        jail.set_remount_mode(libc::MS_SLAVE);

        jail
    } else {
        create_base_minijail(src, Some(max_open_files), None)?
    };

    let features = virtio::base_features(cfg.protected_vm);
    // TODO(chirantan): Use more than one worker once the kernel driver has been fixed to not panic
    // when num_queues > 1.
    let dev =
        virtio::fs::Fs::new(features, tag, 1, fs_cfg, device_tube).map_err(Error::FsDeviceNew)?;

    Ok(VirtioDeviceStub {
        dev: Box::new(dev),
        jail: Some(j),
    })
}

fn create_9p_device(
    cfg: &Config,
    uid_map: &str,
    gid_map: &str,
    src: &Path,
    tag: &str,
    mut p9_cfg: p9::Config,
) -> DeviceResult {
    let max_open_files = get_max_open_files()?;
    let (jail, root) = if cfg.sandbox {
        let seccomp_policy = cfg.seccomp_policy_dir.join("9p_device");
        let config = SandboxConfig {
            limit_caps: false,
            uid_map: Some(uid_map),
            gid_map: Some(gid_map),
            log_failures: cfg.seccomp_log_failures,
            seccomp_policy: &seccomp_policy,
        };

        let mut jail = create_base_minijail(src, Some(max_open_files), Some(&config))?;
        // We want bind mounts from the parent namespaces to propagate into the 9p server's
        // namespace.
        jail.set_remount_mode(libc::MS_SLAVE);

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
    let dev = virtio::P9::new(features, tag, p9_cfg).map_err(Error::P9DeviceNew)?;

    Ok(VirtioDeviceStub {
        dev: Box::new(dev),
        jail,
    })
}

fn create_pmem_device(
    cfg: &Config,
    vm: &mut impl Vm,
    resources: &mut SystemAllocator,
    disk: &DiskOption,
    index: usize,
    pmem_device_tube: Tube,
) -> DeviceResult {
    let fd = open_file(&disk.path, disk.read_only, false /*O_DIRECT*/)
        .map_err(|e| Error::Disk(disk.path.clone(), e.into()))?;
    let arena_size = {
        let metadata =
            std::fs::metadata(&disk.path).map_err(|e| Error::Disk(disk.path.to_path_buf(), e))?;
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
        disk_len
            .checked_add(align_adjust)
            .ok_or(Error::PmemDeviceImageTooBig)?
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
        let arena_size = usize::try_from(arena_size).map_err(|_| Error::PmemDeviceImageTooBig)?;

        let mut arena = MemoryMappingArena::new(arena_size).map_err(Error::ReservePmemMemory)?;
        arena
            .add_fd_offset_protection(0, arena_size, &fd, 0, protection)
            .map_err(Error::ReservePmemMemory)?;
        arena
    };

    let mapping_address = resources
        .mmio_allocator(MmioType::High)
        .allocate_with_align(
            arena_size,
            Alloc::PmemDevice(index),
            format!("pmem_disk_image_{}", index),
            // Linux kernel requires pmem namespaces to be 128 MiB aligned.
            128 * 1024 * 1024, /* 128 MiB */
        )
        .map_err(Error::AllocatePmemDeviceAddress)?;

    let slot = vm
        .add_memory_region(
            GuestAddress(mapping_address),
            Box::new(arena),
            /* read_only = */ disk.read_only,
            /* log_dirty_pages = */ false,
        )
        .map_err(Error::AddPmemDeviceMemory)?;

    let dev = virtio::Pmem::new(
        virtio::base_features(cfg.protected_vm),
        fd,
        GuestAddress(mapping_address),
        slot,
        arena_size,
        Some(pmem_device_tube),
    )
    .map_err(Error::PmemDeviceNew)?;

    Ok(VirtioDeviceStub {
        dev: Box::new(dev) as Box<dyn VirtioDevice>,
        jail: simple_jail(&cfg, "pmem_device")?,
    })
}

fn create_iommu_device(
    cfg: &Config,
    phys_max_addr: u64,
    endpoints: BTreeMap<u32, Arc<Mutex<VfioContainer>>>,
) -> DeviceResult {
    let dev = virtio::Iommu::new(
        virtio::base_features(cfg.protected_vm),
        endpoints,
        phys_max_addr,
    )
    .map_err(Error::CreateVirtioIommu)?;

    Ok(VirtioDeviceStub {
        dev: Box::new(dev),
        jail: simple_jail(&cfg, "iommu_device")?,
    })
}

fn create_console_device(cfg: &Config, param: &SerialParameters) -> DeviceResult {
    let mut keep_rds = Vec::new();
    let evt = Event::new().map_err(Error::CreateEvent)?;
    let dev = param
        .create_serial_device::<Console>(cfg.protected_vm, &evt, &mut keep_rds)
        .map_err(Error::CreateConsole)?;

    let jail = match simple_jail(&cfg, "serial")? {
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
            add_crosvm_user_to_jail(&mut jail, "serial")?;
            let res = param.add_bind_mounts(&mut jail);
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
fn create_sound_device(path: &Path, cfg: &Config) -> DeviceResult {
    let dev = virtio::new_sound(path, virtio::base_features(cfg.protected_vm))
        .map_err(Error::SoundDeviceNew)?;

    Ok(VirtioDeviceStub {
        dev: Box::new(dev),
        jail: simple_jail(&cfg, "vios_audio_device")?,
    })
}

// gpu_device_tube is not used when GPU support is disabled.
#[cfg_attr(not(feature = "gpu"), allow(unused_variables))]
fn create_virtio_devices(
    cfg: &Config,
    vm: &mut impl Vm,
    resources: &mut SystemAllocator,
    _exit_evt: &Event,
    wayland_device_tube: Tube,
    gpu_device_tube: Tube,
    balloon_device_tube: Tube,
    disk_device_tubes: &mut Vec<Tube>,
    pmem_device_tubes: &mut Vec<Tube>,
    map_request: Arc<Mutex<Option<ExternalMapping>>>,
    fs_device_tubes: &mut Vec<Tube>,
) -> DeviceResult<Vec<VirtioDeviceStub>> {
    let mut devs = Vec::new();

    for (_, param) in cfg
        .serial_parameters
        .iter()
        .filter(|(_k, v)| v.hardware == SerialHardware::VirtioConsole)
    {
        let dev = create_console_device(cfg, param)?;
        devs.push(dev);
    }

    for disk in &cfg.disks {
        let disk_device_tube = disk_device_tubes.remove(0);
        devs.push(create_block_device(cfg, disk, disk_device_tube)?);
    }

    for blk in &cfg.vhost_user_blk {
        devs.push(create_vhost_user_block_device(cfg, blk)?);
    }

    for console in &cfg.vhost_user_console {
        devs.push(create_vhost_user_console_device(cfg, console)?);
    }

    for (index, pmem_disk) in cfg.pmem_devices.iter().enumerate() {
        let pmem_device_tube = pmem_device_tubes.remove(0);
        devs.push(create_pmem_device(
            cfg,
            vm,
            resources,
            pmem_disk,
            index,
            pmem_device_tube,
        )?);
    }

    devs.push(create_rng_device(cfg)?);

    #[cfg(feature = "tpm")]
    {
        if cfg.software_tpm {
            devs.push(create_tpm_device(cfg)?);
        }
    }

    for (idx, single_touch_spec) in cfg.virtio_single_touch.iter().enumerate() {
        devs.push(create_single_touch_device(
            cfg,
            single_touch_spec,
            idx as u32,
        )?);
    }

    for (idx, multi_touch_spec) in cfg.virtio_multi_touch.iter().enumerate() {
        devs.push(create_multi_touch_device(
            cfg,
            multi_touch_spec,
            idx as u32,
        )?);
    }

    for (idx, trackpad_spec) in cfg.virtio_trackpad.iter().enumerate() {
        devs.push(create_trackpad_device(cfg, trackpad_spec, idx as u32)?);
    }

    for (idx, mouse_socket) in cfg.virtio_mice.iter().enumerate() {
        devs.push(create_mouse_device(cfg, mouse_socket, idx as u32)?);
    }

    for (idx, keyboard_socket) in cfg.virtio_keyboard.iter().enumerate() {
        devs.push(create_keyboard_device(cfg, keyboard_socket, idx as u32)?);
    }

    for (idx, switches_socket) in cfg.virtio_switches.iter().enumerate() {
        devs.push(create_switches_device(cfg, switches_socket, idx as u32)?);
    }

    for dev_path in &cfg.virtio_input_evdevs {
        devs.push(create_vinput_device(cfg, &dev_path)?);
    }

    devs.push(create_balloon_device(cfg, balloon_device_tube)?);

    // We checked above that if the IP is defined, then the netmask is, too.
    for tap_fd in &cfg.tap_fd {
        devs.push(create_tap_net_device(cfg, *tap_fd)?);
    }

    if let (Some(host_ip), Some(netmask), Some(mac_address)) =
        (cfg.host_ip, cfg.netmask, cfg.mac_address)
    {
        if !cfg.vhost_user_net.is_empty() {
            return Err(Error::VhostUserNetWithNetArgs);
        }
        devs.push(create_net_device(
            cfg,
            host_ip,
            netmask,
            mac_address,
            vm.get_memory(),
        )?);
    }

    for net in &cfg.vhost_user_net {
        devs.push(create_vhost_user_net_device(cfg, net)?);
    }

    for opt in &cfg.vhost_user_wl {
        devs.push(create_vhost_user_wl_device(cfg, opt)?);
    }

    #[cfg_attr(not(feature = "gpu"), allow(unused_mut))]
    let mut resource_bridges = Vec::<Tube>::new();

    if !cfg.wayland_socket_paths.is_empty() {
        #[cfg_attr(not(feature = "gpu"), allow(unused_mut))]
        let mut wl_resource_bridge = None::<Tube>;

        #[cfg(feature = "gpu")]
        {
            if cfg.gpu_parameters.is_some() {
                let (wl_socket, gpu_socket) = Tube::pair().map_err(Error::CreateTube)?;
                resource_bridges.push(gpu_socket);
                wl_resource_bridge = Some(wl_socket);
            }
        }

        devs.push(create_wayland_device(
            cfg,
            wayland_device_tube,
            wl_resource_bridge,
        )?);
    }

    #[cfg(feature = "video-decoder")]
    let video_dec_tube = if cfg.video_dec {
        let (video_tube, gpu_tube) = Tube::pair().map_err(Error::CreateTube)?;
        resource_bridges.push(gpu_tube);
        Some(video_tube)
    } else {
        None
    };

    #[cfg(feature = "video-encoder")]
    let video_enc_tube = if cfg.video_enc {
        let (video_tube, gpu_tube) = Tube::pair().map_err(Error::CreateTube)?;
        resource_bridges.push(gpu_tube);
        Some(video_tube)
    } else {
        None
    };

    #[cfg(feature = "gpu")]
    {
        if let Some(gpu_parameters) = &cfg.gpu_parameters {
            let mut gpu_display_w = DEFAULT_DISPLAY_WIDTH;
            let mut gpu_display_h = DEFAULT_DISPLAY_HEIGHT;
            if !gpu_parameters.displays.is_empty() {
                gpu_display_w = gpu_parameters.displays[0].width;
                gpu_display_h = gpu_parameters.displays[0].height;
            }

            let mut event_devices = Vec::new();
            if cfg.display_window_mouse {
                let (event_device_socket, virtio_dev_socket) =
                    UnixStream::pair().map_err(Error::CreateSocket)?;
                let (multi_touch_width, multi_touch_height) = cfg
                    .virtio_multi_touch
                    .first()
                    .as_ref()
                    .map(|multi_touch_spec| multi_touch_spec.get_size())
                    .unwrap_or((gpu_display_w, gpu_display_h));
                let dev = virtio::new_multi_touch(
                    // u32::MAX is the least likely to collide with the indices generated above for
                    // the multi_touch options, which begin at 0.
                    u32::MAX,
                    virtio_dev_socket,
                    multi_touch_width,
                    multi_touch_height,
                    virtio::base_features(cfg.protected_vm),
                )
                .map_err(Error::InputDeviceNew)?;
                devs.push(VirtioDeviceStub {
                    dev: Box::new(dev),
                    jail: simple_jail(&cfg, "input_device")?,
                });
                event_devices.push(EventDevice::touchscreen(event_device_socket));
            }
            if cfg.display_window_keyboard {
                let (event_device_socket, virtio_dev_socket) =
                    UnixStream::pair().map_err(Error::CreateSocket)?;
                let dev = virtio::new_keyboard(
                    // u32::MAX is the least likely to collide with the indices generated above for
                    // the multi_touch options, which begin at 0.
                    u32::MAX,
                    virtio_dev_socket,
                    virtio::base_features(cfg.protected_vm),
                )
                .map_err(Error::InputDeviceNew)?;
                devs.push(VirtioDeviceStub {
                    dev: Box::new(dev),
                    jail: simple_jail(&cfg, "input_device")?,
                });
                event_devices.push(EventDevice::keyboard(event_device_socket));
            }
            devs.push(create_gpu_device(
                cfg,
                _exit_evt,
                gpu_device_tube,
                resource_bridges,
                // Use the unnamed socket for GPU display screens.
                cfg.wayland_socket_paths.get(""),
                cfg.x_display.clone(),
                event_devices,
                map_request,
            )?);
        }
    }

    #[cfg(feature = "video-decoder")]
    {
        if let Some(video_dec_tube) = video_dec_tube {
            register_video_device(
                &mut devs,
                video_dec_tube,
                cfg,
                devices::virtio::VideoDeviceType::Decoder,
            )?;
        }
    }

    #[cfg(feature = "video-encoder")]
    {
        if let Some(video_enc_tube) = video_enc_tube {
            register_video_device(
                &mut devs,
                video_enc_tube,
                cfg,
                devices::virtio::VideoDeviceType::Encoder,
            )?;
        }
    }

    if let Some(cid) = cfg.cid {
        devs.push(create_vhost_vsock_device(cfg, cid, vm.get_memory())?);
    }

    for vhost_user_fs in &cfg.vhost_user_fs {
        devs.push(create_vhost_user_fs_device(cfg, &vhost_user_fs)?);
    }

    for shared_dir in &cfg.shared_dirs {
        let SharedDir {
            src,
            tag,
            kind,
            uid_map,
            gid_map,
            fs_cfg,
            p9_cfg,
        } = shared_dir;

        let dev = match kind {
            SharedDirKind::FS => {
                let device_tube = fs_device_tubes.remove(0);
                create_fs_device(cfg, uid_map, gid_map, src, tag, fs_cfg.clone(), device_tube)?
            }
            SharedDirKind::P9 => create_9p_device(cfg, uid_map, gid_map, src, tag, p9_cfg.clone())?,
        };
        devs.push(dev);
    }

    if let Some(vhost_user_mac80211_hwsim) = &cfg.vhost_user_mac80211_hwsim {
        devs.push(create_vhost_user_mac80211_hwsim_device(
            cfg,
            &vhost_user_mac80211_hwsim,
        )?);
    }

    #[cfg(feature = "audio")]
    if let Some(path) = &cfg.sound {
        devs.push(create_sound_device(&path, &cfg)?);
    }

    Ok(devs)
}

fn create_vfio_device(
    cfg: &Config,
    vm: &impl Vm,
    resources: &mut SystemAllocator,
    control_tubes: &mut Vec<TaggedControlTube>,
    vfio_path: &Path,
    kvm_vfio_file: &SafeDescriptor,
    endpoints: &mut BTreeMap<u32, Arc<Mutex<VfioContainer>>>,
    iommu_enabled: bool,
) -> DeviceResult<(Box<VfioPciDevice>, Option<Minijail>)> {
    let vfio_container = VfioCommonSetup::vfio_get_container(vfio_path, iommu_enabled)
        .map_err(Error::CreateVfioDevice)?;

    // create MSI, MSI-X, and Mem request sockets for each vfio device
    let (vfio_host_tube_msi, vfio_device_tube_msi) = Tube::pair().map_err(Error::CreateTube)?;
    control_tubes.push(TaggedControlTube::VmIrq(vfio_host_tube_msi));

    let (vfio_host_tube_msix, vfio_device_tube_msix) = Tube::pair().map_err(Error::CreateTube)?;
    control_tubes.push(TaggedControlTube::VmIrq(vfio_host_tube_msix));

    let (vfio_host_tube_mem, vfio_device_tube_mem) = Tube::pair().map_err(Error::CreateTube)?;
    control_tubes.push(TaggedControlTube::VmMemory(vfio_host_tube_mem));

    let vfio_device = VfioDevice::new(
        vfio_path,
        vm.get_memory(),
        &kvm_vfio_file,
        vfio_container.clone(),
        iommu_enabled,
    )
    .map_err(Error::CreateVfioDevice)?;
    let mut vfio_pci_device = Box::new(VfioPciDevice::new(
        vfio_device,
        vfio_device_tube_msi,
        vfio_device_tube_msix,
        vfio_device_tube_mem,
    ));
    // early reservation for pass-through PCI devices.
    let endpoint_addr = vfio_pci_device.allocate_address(resources);
    if endpoint_addr.is_err() {
        warn!(
            "address reservation failed for vfio {}",
            vfio_pci_device.debug_label()
        );
    }

    if iommu_enabled {
        endpoints.insert(endpoint_addr.unwrap().to_u32(), vfio_container);
    }

    Ok((vfio_pci_device, simple_jail(cfg, "vfio_device")?))
}

fn create_devices(
    cfg: &Config,
    vm: &mut impl Vm,
    resources: &mut SystemAllocator,
    exit_evt: &Event,
    phys_max_addr: u64,
    control_tubes: &mut Vec<TaggedControlTube>,
    wayland_device_tube: Tube,
    gpu_device_tube: Tube,
    balloon_device_tube: Tube,
    disk_device_tubes: &mut Vec<Tube>,
    pmem_device_tubes: &mut Vec<Tube>,
    fs_device_tubes: &mut Vec<Tube>,
    #[cfg(feature = "usb")] usb_provider: HostBackendDeviceProvider,
    map_request: Arc<Mutex<Option<ExternalMapping>>>,
) -> DeviceResult<Vec<(Box<dyn PciDevice>, Option<Minijail>)>> {
    let stubs = create_virtio_devices(
        &cfg,
        vm,
        resources,
        exit_evt,
        wayland_device_tube,
        gpu_device_tube,
        balloon_device_tube,
        disk_device_tubes,
        pmem_device_tubes,
        map_request,
        fs_device_tubes,
    )?;

    let mut pci_devices = Vec::new();

    for stub in stubs {
        let (msi_host_tube, msi_device_tube) = Tube::pair().map_err(Error::CreateTube)?;
        control_tubes.push(TaggedControlTube::VmIrq(msi_host_tube));
        let dev = VirtioPciDevice::new(vm.get_memory().clone(), stub.dev, msi_device_tube)
            .map_err(Error::VirtioPciDev)?;
        let dev = Box::new(dev) as Box<dyn PciDevice>;
        pci_devices.push((dev, stub.jail));
    }

    #[cfg(feature = "audio")]
    for ac97_param in &cfg.ac97_parameters {
        let dev = Ac97Dev::try_new(vm.get_memory().clone(), ac97_param.clone())
            .map_err(Error::CreateAc97)?;
        let jail = simple_jail(&cfg, dev.minijail_policy())?;
        pci_devices.push((Box::new(dev), jail));
    }

    #[cfg(feature = "usb")]
    {
        // Create xhci controller.
        let usb_controller = Box::new(XhciController::new(vm.get_memory().clone(), usb_provider));
        pci_devices.push((usb_controller, simple_jail(&cfg, "xhci")?));
    }

    if !cfg.vfio.is_empty() {
        let kvm_vfio_file = vm
            .create_device(DeviceKind::Vfio)
            .map_err(Error::CreateVfioKvmDevice)?;

        let mut iommu_attached_endpoints: BTreeMap<u32, Arc<Mutex<VfioContainer>>> =
            BTreeMap::new();

        for (vfio_path, enable_iommu) in cfg.vfio.iter() {
            let (vfio_pci_device, jail) = create_vfio_device(
                cfg,
                vm,
                resources,
                control_tubes,
                vfio_path.as_path(),
                &kvm_vfio_file,
                &mut iommu_attached_endpoints,
                *enable_iommu,
            )?;

            pci_devices.push((vfio_pci_device, jail));
        }

        if !iommu_attached_endpoints.is_empty() {
            let iommu_dev = create_iommu_device(cfg, phys_max_addr, iommu_attached_endpoints)?;

            let (msi_host_tube, msi_device_tube) = Tube::pair().map_err(Error::CreateTube)?;
            control_tubes.push(TaggedControlTube::VmIrq(msi_host_tube));
            let mut dev =
                VirtioPciDevice::new(vm.get_memory().clone(), iommu_dev.dev, msi_device_tube)
                    .map_err(Error::VirtioPciDev)?;
            // early reservation for viommu.
            dev.allocate_address(resources)
                .map_err(|_| Error::VirtioPciDev(base::Error::new(EINVAL)))?;
            let dev = Box::new(dev);
            pci_devices.push((dev, iommu_dev.jail));
        }
    }

    Ok(pci_devices)
}

#[derive(Copy, Clone)]
#[cfg_attr(not(feature = "tpm"), allow(dead_code))]
struct Ids {
    uid: uid_t,
    gid: gid_t,
}

// Set the uid/gid for the jailed process and give a basic id map. This is
// required for bind mounts to work.
fn add_crosvm_user_to_jail(jail: &mut Minijail, feature: &str) -> Result<Ids> {
    let crosvm_user_group = CStr::from_bytes_with_nul(b"crosvm\0").unwrap();

    let crosvm_uid = match get_user_id(&crosvm_user_group) {
        Ok(u) => u,
        Err(e) => {
            warn!("falling back to current user id for {}: {}", feature, e);
            geteuid()
        }
    };

    let crosvm_gid = match get_group_id(&crosvm_user_group) {
        Ok(u) => u,
        Err(e) => {
            warn!("falling back to current group id for {}: {}", feature, e);
            getegid()
        }
    };

    jail.change_uid(crosvm_uid);
    jail.change_gid(crosvm_gid);
    jail.uidmap(&format!("{0} {0} 1", crosvm_uid))
        .map_err(Error::SettingUidMap)?;
    jail.gidmap(&format!("{0} {0} 1", crosvm_gid))
        .map_err(Error::SettingGidMap)?;

    Ok(Ids {
        uid: crosvm_uid,
        gid: crosvm_gid,
    })
}

trait IntoUnixStream {
    fn into_unix_stream(self) -> Result<UnixStream>;
}

impl<'a> IntoUnixStream for &'a Path {
    fn into_unix_stream(self) -> Result<UnixStream> {
        if let Some(fd) =
            safe_descriptor_from_path(self).map_err(|e| Error::InputEventsOpen(e.into()))?
        {
            Ok(fd.into())
        } else {
            UnixStream::connect(self).map_err(Error::InputEventsOpen)
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

fn setup_vcpu_signal_handler<T: Vcpu>(use_hypervisor_signals: bool) -> Result<()> {
    if use_hypervisor_signals {
        unsafe {
            extern "C" fn handle_signal(_: c_int) {}
            // Our signal handler does nothing and is trivially async signal safe.
            register_rt_signal_handler(SIGRTMIN() + 0, handle_signal)
                .map_err(Error::RegisterSignalHandler)?;
        }
        block_signal(SIGRTMIN() + 0).map_err(Error::BlockSignal)?;
    } else {
        unsafe {
            extern "C" fn handle_signal<T: Vcpu>(_: c_int) {
                T::set_local_immediate_exit(true);
            }
            register_rt_signal_handler(SIGRTMIN() + 0, handle_signal::<T>)
                .map_err(Error::RegisterSignalHandler)?;
        }
    }
    Ok(())
}

// Sets up a vcpu and converts it into a runnable vcpu.
fn runnable_vcpu<V>(
    cpu_id: usize,
    vcpu: Option<V>,
    vm: impl VmArch,
    irq_chip: &mut dyn IrqChipArch,
    vcpu_count: usize,
    run_rt: bool,
    vcpu_affinity: Vec<usize>,
    no_smt: bool,
    has_bios: bool,
    use_hypervisor_signals: bool,
) -> Result<(V, VcpuRunHandle)>
where
    V: VcpuArch,
{
    let mut vcpu = match vcpu {
        Some(v) => v,
        None => {
            // If vcpu is None, it means this arch/hypervisor requires create_vcpu to be called from
            // the vcpu thread.
            match vm
                .create_vcpu(cpu_id)
                .map_err(Error::CreateVcpu)?
                .downcast::<V>()
            {
                Ok(v) => *v,
                Err(_) => panic!("VM created wrong type of VCPU"),
            }
        }
    };

    irq_chip
        .add_vcpu(cpu_id, &vcpu)
        .map_err(Error::AddIrqChipVcpu)?;

    if !vcpu_affinity.is_empty() {
        if let Err(e) = set_cpu_affinity(vcpu_affinity) {
            error!("Failed to set CPU affinity: {}", e);
        }
    }

    Arch::configure_vcpu(
        vm.get_memory(),
        vm.get_hypervisor(),
        irq_chip,
        &mut vcpu,
        cpu_id,
        vcpu_count,
        has_bios,
        no_smt,
    )
    .map_err(Error::ConfigureVcpu)?;

    if let Err(e) = enable_core_scheduling() {
        error!("Failed to enable core scheduling: {}", e);
    }

    if run_rt {
        const DEFAULT_VCPU_RT_LEVEL: u16 = 6;
        if let Err(e) = set_rt_prio_limit(u64::from(DEFAULT_VCPU_RT_LEVEL))
            .and_then(|_| set_rt_round_robin(i32::from(DEFAULT_VCPU_RT_LEVEL)))
        {
            warn!("Failed to set vcpu to real time: {}", e);
        }
    }

    if use_hypervisor_signals {
        let mut v = get_blocked_signals().map_err(Error::GetSignalMask)?;
        v.retain(|&x| x != SIGRTMIN() + 0);
        vcpu.set_signal_mask(&v).map_err(Error::SettingSignalMask)?;
    }

    let vcpu_run_handle = vcpu
        .take_run_handle(Some(SIGRTMIN() + 0))
        .map_err(Error::RunnableVcpu)?;

    Ok((vcpu, vcpu_run_handle))
}

#[cfg(all(target_arch = "x86_64", feature = "gdb"))]
fn handle_debug_msg<V>(
    cpu_id: usize,
    vcpu: &V,
    guest_mem: &GuestMemory,
    d: VcpuDebug,
    reply_tube: &mpsc::Sender<VcpuDebugStatusMessage>,
) -> Result<()>
where
    V: VcpuArch + 'static,
{
    match d {
        VcpuDebug::ReadRegs => {
            let msg = VcpuDebugStatusMessage {
                cpu: cpu_id as usize,
                msg: VcpuDebugStatus::RegValues(
                    Arch::debug_read_registers(vcpu as &V).map_err(Error::HandleDebugCommand)?,
                ),
            };
            reply_tube
                .send(msg)
                .map_err(|e| Error::SendDebugStatus(Box::new(e)))
        }
        VcpuDebug::WriteRegs(regs) => {
            Arch::debug_write_registers(vcpu as &V, &regs).map_err(Error::HandleDebugCommand)?;
            reply_tube
                .send(VcpuDebugStatusMessage {
                    cpu: cpu_id as usize,
                    msg: VcpuDebugStatus::CommandComplete,
                })
                .map_err(|e| Error::SendDebugStatus(Box::new(e)))
        }
        VcpuDebug::ReadMem(vaddr, len) => {
            let msg = VcpuDebugStatusMessage {
                cpu: cpu_id as usize,
                msg: VcpuDebugStatus::MemoryRegion(
                    Arch::debug_read_memory(vcpu as &V, guest_mem, vaddr, len)
                        .unwrap_or(Vec::new()),
                ),
            };
            reply_tube
                .send(msg)
                .map_err(|e| Error::SendDebugStatus(Box::new(e)))
        }
        VcpuDebug::WriteMem(vaddr, buf) => {
            Arch::debug_write_memory(vcpu as &V, guest_mem, vaddr, &buf)
                .map_err(Error::HandleDebugCommand)?;
            reply_tube
                .send(VcpuDebugStatusMessage {
                    cpu: cpu_id as usize,
                    msg: VcpuDebugStatus::CommandComplete,
                })
                .map_err(|e| Error::SendDebugStatus(Box::new(e)))
        }
        VcpuDebug::EnableSinglestep => {
            Arch::debug_enable_singlestep(vcpu as &V).map_err(Error::HandleDebugCommand)?;
            reply_tube
                .send(VcpuDebugStatusMessage {
                    cpu: cpu_id as usize,
                    msg: VcpuDebugStatus::CommandComplete,
                })
                .map_err(|e| Error::SendDebugStatus(Box::new(e)))
        }
        VcpuDebug::SetHwBreakPoint(addrs) => {
            Arch::debug_set_hw_breakpoints(vcpu as &V, &addrs)
                .map_err(Error::HandleDebugCommand)?;
            reply_tube
                .send(VcpuDebugStatusMessage {
                    cpu: cpu_id as usize,
                    msg: VcpuDebugStatus::CommandComplete,
                })
                .map_err(|e| Error::SendDebugStatus(Box::new(e)))
        }
    }
}

fn run_vcpu<V>(
    cpu_id: usize,
    vcpu: Option<V>,
    vm: impl VmArch + 'static,
    mut irq_chip: Box<dyn IrqChipArch + 'static>,
    vcpu_count: usize,
    run_rt: bool,
    vcpu_affinity: Vec<usize>,
    delay_rt: bool,
    no_smt: bool,
    start_barrier: Arc<Barrier>,
    has_bios: bool,
    io_bus: devices::Bus,
    mmio_bus: devices::Bus,
    exit_evt: Event,
    requires_pvclock_ctrl: bool,
    from_main_tube: mpsc::Receiver<VcpuControl>,
    use_hypervisor_signals: bool,
    #[cfg(all(target_arch = "x86_64", feature = "gdb"))] to_gdb_tube: Option<
        mpsc::Sender<VcpuDebugStatusMessage>,
    >,
) -> Result<JoinHandle<()>>
where
    V: VcpuArch + 'static,
{
    thread::Builder::new()
        .name(format!("crosvm_vcpu{}", cpu_id))
        .spawn(move || {
            // The VCPU thread must trigger the `exit_evt` in all paths, and a `ScopedEvent`'s Drop
            // implementation accomplishes that.
            let _scoped_exit_evt = ScopedEvent::from(exit_evt);

            #[cfg(all(target_arch = "x86_64", feature = "gdb"))]
            let guest_mem = vm.get_memory().clone();
            let runnable_vcpu = runnable_vcpu(
                cpu_id,
                vcpu,
                vm,
                irq_chip.as_mut(),
                vcpu_count,
                run_rt && !delay_rt,
                vcpu_affinity,
                no_smt,
                has_bios,
                use_hypervisor_signals,
            );

            start_barrier.wait();

            let (vcpu, vcpu_run_handle) = match runnable_vcpu {
                Ok(v) => v,
                Err(e) => {
                    error!("failed to start vcpu {}: {}", cpu_id, e);
                    return;
                }
            };

            let mut run_mode = VmRunMode::Running;
            #[cfg(all(target_arch = "x86_64", feature = "gdb"))]
            if to_gdb_tube.is_some() {
                // Wait until a GDB client attaches
                run_mode = VmRunMode::Breakpoint;
            }

            let mut interrupted_by_signal = false;

            'vcpu_loop: loop {
                // Start by checking for messages to process and the run state of the CPU.
                // An extra check here for Running so there isn't a need to call recv unless a
                // message is likely to be ready because a signal was sent.
                if interrupted_by_signal || run_mode != VmRunMode::Running {
                    'state_loop: loop {
                        // Tries to get a pending message without blocking first.
                        let msg = match from_main_tube.try_recv() {
                            Ok(m) => m,
                            Err(mpsc::TryRecvError::Empty) if run_mode == VmRunMode::Running => {
                                // If the VM is running and no message is pending, the state won't
                                // change.
                                break 'state_loop;
                            }
                            Err(mpsc::TryRecvError::Empty) => {
                                // If the VM is not running, wait until a message is ready.
                                match from_main_tube.recv() {
                                    Ok(m) => m,
                                    Err(mpsc::RecvError) => {
                                        error!("Failed to read from main tube in vcpu");
                                        break 'vcpu_loop;
                                    }
                                }
                            }
                            Err(mpsc::TryRecvError::Disconnected) => {
                                error!("Failed to read from main tube in vcpu");
                                break 'vcpu_loop;
                            }
                        };

                        // Collect all pending messages.
                        let mut messages = vec![msg];
                        messages.append(&mut from_main_tube.try_iter().collect());

                        for msg in messages {
                            match msg {
                                VcpuControl::RunState(new_mode) => {
                                    run_mode = new_mode;
                                    match run_mode {
                                        VmRunMode::Running => break 'state_loop,
                                        VmRunMode::Suspending => {
                                            // On KVM implementations that use a paravirtualized
                                            // clock (e.g. x86), a flag must be set to indicate to
                                            // the guest kernel that a vCPU was suspended. The guest
                                            // kernel will use this flag to prevent the soft lockup
                                            // detection from triggering when this vCPU resumes,
                                            // which could happen days later in realtime.
                                            if requires_pvclock_ctrl {
                                                if let Err(e) = vcpu.pvclock_ctrl() {
                                                    error!(
                                                        "failed to tell hypervisor vcpu {} is suspending: {}",
                                                        cpu_id, e
                                                    );
                                                }
                                            }
                                        }
                                        VmRunMode::Breakpoint => {}
                                        VmRunMode::Exiting => break 'vcpu_loop,
                                    }
                                }
                                #[cfg(all(target_arch = "x86_64", feature = "gdb"))]
                                VcpuControl::Debug(d) => {
                                    match &to_gdb_tube {
                                        Some(ref ch) => {
                                            if let Err(e) = handle_debug_msg(
                                                cpu_id, &vcpu, &guest_mem, d, &ch,
                                            ) {
                                                error!("Failed to handle gdb message: {}", e);
                                            }
                                        },
                                        None => {
                                            error!("VcpuControl::Debug received while GDB feature is disabled: {:?}", d);
                                        }
                                    }
                                }
                                VcpuControl::MakeRT => {
                                    if run_rt && delay_rt {
                                        info!("Making vcpu {} RT\n", cpu_id);
                                        const DEFAULT_VCPU_RT_LEVEL: u16 = 6;
                                        if let Err(e) = set_rt_prio_limit(
                                            u64::from(DEFAULT_VCPU_RT_LEVEL))
                                            .and_then(|_|
                                                set_rt_round_robin(
                                                i32::from(DEFAULT_VCPU_RT_LEVEL)
                                            ))
                                        {
                                            warn!("Failed to set vcpu to real time: {}", e);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                interrupted_by_signal = false;

                // Vcpus may have run a HLT instruction, which puts them into a state other than
                // VcpuRunState::Runnable. In that case, this call to wait_until_runnable blocks
                // until either the irqchip receives an interrupt for this vcpu, or until the main
                // thread kicks this vcpu as a result of some VmControl operation. In most IrqChip
                // implementations HLT instructions do not make it to crosvm, and thus this is a
                // no-op that always returns VcpuRunState::Runnable.
                match irq_chip.wait_until_runnable(&vcpu) {
                    Ok(VcpuRunState::Runnable) => {}
                    Ok(VcpuRunState::Interrupted) => interrupted_by_signal = true,
                    Err(e) => error!(
                        "error waiting for vcpu {} to become runnable: {}",
                        cpu_id, e
                    ),
                }

                if !interrupted_by_signal {
                    match vcpu.run(&vcpu_run_handle) {
                        Ok(VcpuExit::IoIn { port, mut size }) => {
                            let mut data = [0; 8];
                            if size > data.len() {
                                error!("unsupported IoIn size of {} bytes at port {:#x}", size, port);
                                size = data.len();
                            }
                            io_bus.read(port as u64, &mut data[..size]);
                            if let Err(e) = vcpu.set_data(&data[..size]) {
                                error!("failed to set return data for IoIn at port {:#x}: {}", port, e);
                            }
                        }
                        Ok(VcpuExit::IoOut {
                            port,
                            mut size,
                            data,
                        }) => {
                            if size > data.len() {
                                error!("unsupported IoOut size of {} bytes at port {:#x}", size, port);
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
                        Ok(VcpuExit::IoapicEoi { vector }) => {
                            if let Err(e) = irq_chip.broadcast_eoi(vector) {
                                error!(
                                    "failed to broadcast eoi {} on vcpu {}: {}",
                                    vector, cpu_id, e
                                );
                            }
                        }
                        Ok(VcpuExit::IrqWindowOpen) => {}
                        Ok(VcpuExit::Hlt) => irq_chip.halted(cpu_id),
                        Ok(VcpuExit::Shutdown) => break,
                        Ok(VcpuExit::FailEntry {
                            hardware_entry_failure_reason,
                        }) => {
                            error!("vcpu hw run failure: {:#x}", hardware_entry_failure_reason);
                            break;
                        }
                        Ok(VcpuExit::SystemEvent(_, _)) => break,
                        Ok(VcpuExit::Debug { .. }) => {
                            #[cfg(all(target_arch = "x86_64", feature = "gdb"))]
                            {
                                let msg = VcpuDebugStatusMessage {
                                    cpu: cpu_id as usize,
                                    msg: VcpuDebugStatus::HitBreakPoint,
                                };
                                if let Some(ref ch) = to_gdb_tube {
                                    if let Err(e) = ch.send(msg) {
                                        error!("failed to notify breakpoint to GDB thread: {}", e);
                                        break;
                                    }
                                }
                                run_mode = VmRunMode::Breakpoint;
                            }
                        }
                        Ok(r) => warn!("unexpected vcpu exit: {:?}", r),
                        Err(e) => match e.errno() {
                            libc::EINTR => interrupted_by_signal = true,
                            libc::EAGAIN => {}
                            _ => {
                                error!("vcpu hit unknown error: {}", e);
                                break;
                            }
                        },
                    }
                }

                if interrupted_by_signal {
                    if use_hypervisor_signals {
                        // Try to clear the signal that we use to kick VCPU if it is pending before
                        // attempting to handle pause requests.
                        if let Err(e) = clear_signal(SIGRTMIN() + 0) {
                            error!("failed to clear pending signal: {}", e);
                            break;
                        }
                    } else {
                        vcpu.set_immediate_exit(false);
                    }
                }

                if let Err(e) = irq_chip.inject_interrupts(&vcpu) {
                    error!("failed to inject interrupts for vcpu {}: {}", cpu_id, e);
                }
            }
        })
        .map_err(Error::SpawnVcpu)
}

fn setup_vm_components(cfg: &Config) -> Result<VmComponents> {
    let initrd_image = if let Some(initrd_path) = &cfg.initrd_path {
        Some(
            open_file(
                initrd_path,
                true,  /*read_only*/
                false, /*O_DIRECT*/
            )
            .map_err(|e| Error::OpenInitrd(initrd_path.to_owned(), e.into()))?,
        )
    } else {
        None
    };

    let vm_image = match cfg.executable_path {
        Some(Executable::Kernel(ref kernel_path)) => VmImage::Kernel(
            open_file(
                kernel_path,
                true,  /*read_only*/
                false, /*O_DIRECT*/
            )
            .map_err(|e| Error::OpenKernel(kernel_path.to_owned(), e.into()))?,
        ),
        Some(Executable::Bios(ref bios_path)) => VmImage::Bios(
            open_file(bios_path, true /*read_only*/, false /*O_DIRECT*/)
                .map_err(|e| Error::OpenBios(bios_path.to_owned(), e.into()))?,
        ),
        _ => panic!("Did not receive a bios or kernel, should be impossible."),
    };

    let swiotlb = if let Some(size) = cfg.swiotlb {
        Some(
            size.checked_mul(1024 * 1024)
                .ok_or(Error::SwiotlbTooLarge)?,
        )
    } else {
        match cfg.protected_vm {
            ProtectionType::Protected => Some(64 * 1024 * 1024),
            ProtectionType::Unprotected => None,
        }
    };

    Ok(VmComponents {
        memory_size: cfg
            .memory
            .unwrap_or(256)
            .checked_mul(1024 * 1024)
            .ok_or(Error::MemoryTooLarge)?,
        swiotlb,
        vcpu_count: cfg.vcpu_count.unwrap_or(1),
        vcpu_affinity: cfg.vcpu_affinity.clone(),
        cpu_clusters: cfg.cpu_clusters.clone(),
        cpu_capacity: cfg.cpu_capacity.clone(),
        no_smt: cfg.no_smt,
        hugepages: cfg.hugepages,
        vm_image,
        android_fstab: cfg
            .android_fstab
            .as_ref()
            .map(|x| File::open(x).map_err(|e| Error::OpenAndroidFstab(x.to_path_buf(), e)))
            .map_or(Ok(None), |v| v.map(Some))?,
        pstore: cfg.pstore.clone(),
        initrd_image,
        extra_kernel_params: cfg.params.clone(),
        acpi_sdts: cfg
            .acpi_tables
            .iter()
            .map(|path| SDT::from_file(path).map_err(|e| Error::OpenAcpiTable(path.clone(), e)))
            .collect::<Result<Vec<SDT>>>()?,
        rt_cpus: cfg.rt_cpus.clone(),
        delay_rt: cfg.delay_rt,
        protected_vm: cfg.protected_vm,
        #[cfg(all(target_arch = "x86_64", feature = "gdb"))]
        gdb: None,
        dmi_path: cfg.dmi_path.clone(),
        no_legacy: cfg.no_legacy,
    })
}

pub fn run_config(cfg: Config) -> Result<()> {
    let components = setup_vm_components(&cfg)?;

    let guest_mem_layout =
        Arch::guest_memory_layout(&components).map_err(Error::GuestMemoryLayout)?;
    let guest_mem = GuestMemory::new(&guest_mem_layout).map_err(Error::CreateGuestMemory)?;
    let mut mem_policy = MemoryPolicy::empty();
    if components.hugepages {
        mem_policy |= MemoryPolicy::USE_HUGEPAGES;
    }
    guest_mem.set_memory_policy(mem_policy);
    let kvm = Kvm::new_with_path(&cfg.kvm_device_path).map_err(Error::CreateKvm)?;
    let vm = KvmVm::new(&kvm, guest_mem).map_err(Error::CreateVm)?;
    let vm_clone = vm.try_clone().map_err(Error::CreateVm)?;

    enum KvmIrqChip {
        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        Split(KvmSplitIrqChip),
        Kernel(KvmKernelIrqChip),
    }

    impl KvmIrqChip {
        fn as_mut(&mut self) -> &mut dyn IrqChipArch {
            match self {
                #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
                KvmIrqChip::Split(i) => i,
                KvmIrqChip::Kernel(i) => i,
            }
        }
    }

    let ioapic_host_tube;
    let mut irq_chip = if cfg.split_irqchip {
        #[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
        unimplemented!("KVM split irqchip mode only supported on x86 processors");
        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        {
            let (host_tube, ioapic_device_tube) = Tube::pair().map_err(Error::CreateTube)?;
            ioapic_host_tube = Some(host_tube);
            KvmIrqChip::Split(
                KvmSplitIrqChip::new(
                    vm_clone,
                    components.vcpu_count,
                    ioapic_device_tube,
                    Some(120),
                )
                .map_err(Error::CreateIrqChip)?,
            )
        }
    } else {
        ioapic_host_tube = None;
        KvmIrqChip::Kernel(
            KvmKernelIrqChip::new(vm_clone, components.vcpu_count).map_err(Error::CreateIrqChip)?,
        )
    };

    run_vm::<KvmVcpu, KvmVm>(cfg, components, vm, irq_chip.as_mut(), ioapic_host_tube)
}

fn run_vm<Vcpu, V>(
    cfg: Config,
    #[allow(unused_mut)] mut components: VmComponents,
    mut vm: V,
    irq_chip: &mut dyn IrqChipArch,
    ioapic_host_tube: Option<Tube>,
) -> Result<()>
where
    Vcpu: VcpuArch + 'static,
    V: VmArch + 'static,
{
    if cfg.sandbox {
        // Printing something to the syslog before entering minijail so that libc's syslogger has a
        // chance to open files necessary for its operation, like `/etc/localtime`. After jailing,
        // access to those files will not be possible.
        info!("crosvm entering multiprocess mode");
    }

    #[cfg(feature = "usb")]
    let (usb_control_tube, usb_provider) =
        HostBackendDeviceProvider::new().map_err(Error::CreateUsbProvider)?;

    // Masking signals is inherently dangerous, since this can persist across clones/execs. Do this
    // before any jailed devices have been spawned, so that we can catch any of them that fail very
    // quickly.
    let sigchld_fd = SignalFd::new(libc::SIGCHLD).map_err(Error::CreateSignalFd)?;

    let control_server_socket = match &cfg.socket_path {
        Some(path) => Some(UnlinkUnixSeqpacketListener(
            UnixSeqpacketListener::bind(path).map_err(Error::CreateControlServer)?,
        )),
        None => None,
    };

    let mut control_tubes = Vec::new();

    #[cfg(all(target_arch = "x86_64", feature = "gdb"))]
    if let Some(port) = cfg.gdb {
        // GDB needs a control socket to interrupt vcpus.
        let (gdb_host_tube, gdb_control_tube) = Tube::pair().map_err(Error::CreateTube)?;
        control_tubes.push(TaggedControlTube::Vm(gdb_host_tube));
        components.gdb = Some((port, gdb_control_tube));
    }

    for wl_cfg in &cfg.vhost_user_wl {
        let wayland_host_tube = UnixSeqpacket::connect(&wl_cfg.vm_tube)
            .map(Tube::new)
            .map_err(Error::ConnectTube)?;
        control_tubes.push(TaggedControlTube::VmMemory(wayland_host_tube));
    }

    let (wayland_host_tube, wayland_device_tube) = Tube::pair().map_err(Error::CreateTube)?;
    control_tubes.push(TaggedControlTube::VmMemory(wayland_host_tube));
    // Balloon gets a special socket so balloon requests can be forwarded from the main process.
    let (balloon_host_tube, balloon_device_tube) = Tube::pair().map_err(Error::CreateTube)?;
    // Set recv timeout to avoid deadlock on sending BalloonControlCommand before guest is ready.
    balloon_host_tube
        .set_recv_timeout(Some(Duration::from_millis(100)))
        .map_err(Error::CreateTube)?;

    // Create one control socket per disk.
    let mut disk_device_tubes = Vec::new();
    let mut disk_host_tubes = Vec::new();
    let disk_count = cfg.disks.len();
    for _ in 0..disk_count {
        let (disk_host_tub, disk_device_tube) = Tube::pair().map_err(Error::CreateTube)?;
        disk_host_tubes.push(disk_host_tub);
        disk_device_tubes.push(disk_device_tube);
    }

    let mut pmem_device_tubes = Vec::new();
    let pmem_count = cfg.pmem_devices.len();
    for _ in 0..pmem_count {
        let (pmem_host_tube, pmem_device_tube) = Tube::pair().map_err(Error::CreateTube)?;
        pmem_device_tubes.push(pmem_device_tube);
        control_tubes.push(TaggedControlTube::VmMsync(pmem_host_tube));
    }

    let (gpu_host_tube, gpu_device_tube) = Tube::pair().map_err(Error::CreateTube)?;
    control_tubes.push(TaggedControlTube::VmMemory(gpu_host_tube));

    if let Some(ioapic_host_tube) = ioapic_host_tube {
        control_tubes.push(TaggedControlTube::VmIrq(ioapic_host_tube));
    }

    let battery = if cfg.battery_type.is_some() {
        let jail = match simple_jail(&cfg, "battery")? {
            #[cfg_attr(not(feature = "powerd-monitor-powerd"), allow(unused_mut))]
            Some(mut jail) => {
                // Setup a bind mount to the system D-Bus socket if the powerd monitor is used.
                #[cfg(feature = "power-monitor-powerd")]
                {
                    add_crosvm_user_to_jail(&mut jail, "battery")?;

                    // Create a tmpfs in the device's root directory so that we can bind mount files.
                    jail.mount_with_data(
                        Path::new("none"),
                        Path::new("/"),
                        "tmpfs",
                        (libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC) as usize,
                        "size=67108864",
                    )?;

                    let system_bus_socket_path = Path::new("/run/dbus/system_bus_socket");
                    jail.mount_bind(system_bus_socket_path, system_bus_socket_path, true)?;
                }
                Some(jail)
            }
            None => None,
        };
        (&cfg.battery_type, jail)
    } else {
        (&cfg.battery_type, None)
    };

    let map_request: Arc<Mutex<Option<ExternalMapping>>> = Arc::new(Mutex::new(None));

    let fs_count = cfg
        .shared_dirs
        .iter()
        .filter(|sd| sd.kind == SharedDirKind::FS)
        .count();
    let mut fs_device_tubes = Vec::with_capacity(fs_count);
    for _ in 0..fs_count {
        let (fs_host_tube, fs_device_tube) = Tube::pair().map_err(Error::CreateTube)?;
        control_tubes.push(TaggedControlTube::Fs(fs_host_tube));
        fs_device_tubes.push(fs_device_tube);
    }

    let exit_evt = Event::new().map_err(Error::CreateEvent)?;
    let mut sys_allocator = Arch::create_system_allocator(vm.get_memory());
    let phys_max_addr = Arch::get_phys_max_addr();
    let mut pci_devices = create_devices(
        &cfg,
        &mut vm,
        &mut sys_allocator,
        &exit_evt,
        phys_max_addr,
        &mut control_tubes,
        wayland_device_tube,
        gpu_device_tube,
        balloon_device_tube,
        &mut disk_device_tubes,
        &mut pmem_device_tubes,
        &mut fs_device_tubes,
        #[cfg(feature = "usb")]
        usb_provider,
        Arc::clone(&map_request),
    )?;

    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    for (device, _jail) in pci_devices.iter_mut() {
        let sdts = device
            .generate_acpi(components.acpi_sdts)
            .or_else(|| {
                error!("ACPI table generation error");
                None
            })
            .ok_or(Error::GenerateAcpi)?;
        components.acpi_sdts = sdts;
    }

    #[cfg_attr(not(feature = "direct"), allow(unused_mut))]
    let mut linux = Arch::build_vm::<V, Vcpu>(
        components,
        &exit_evt,
        &mut sys_allocator,
        &cfg.serial_parameters,
        simple_jail(&cfg, "serial")?,
        battery,
        vm,
        pci_devices,
        irq_chip,
    )
    .map_err(Error::BuildVm)?;

    #[cfg(feature = "direct")]
    if let Some(pmio) = &cfg.direct_pmio {
        let direct_io =
            Arc::new(devices::DirectIo::new(&pmio.path, false).map_err(Error::DirectIo)?);
        for range in pmio.ranges.iter() {
            linux
                .io_bus
                .insert_sync(direct_io.clone(), range.0, range.1)
                .unwrap();
        }
    };

    #[cfg(feature = "direct")]
    let mut irqs = Vec::new();

    #[cfg(feature = "direct")]
    for irq in &cfg.direct_level_irq {
        if !sys_allocator.reserve_irq(*irq) {
            warn!("irq {} already reserved.", irq);
        }
        let trigger = Event::new().map_err(Error::CreateEvent)?;
        let resample = Event::new().map_err(Error::CreateEvent)?;
        linux
            .irq_chip
            .register_irq_event(*irq, &trigger, Some(&resample))
            .unwrap();
        let direct_irq =
            devices::DirectIrq::new(trigger, Some(resample)).map_err(Error::DirectIrq)?;
        direct_irq.irq_enable(*irq).map_err(Error::DirectIrq)?;
        irqs.push(direct_irq);
    }

    #[cfg(feature = "direct")]
    for irq in &cfg.direct_edge_irq {
        if !sys_allocator.reserve_irq(*irq) {
            warn!("irq {} already reserved.", irq);
        }
        let trigger = Event::new().map_err(Error::CreateEvent)?;
        linux
            .irq_chip
            .register_irq_event(*irq, &trigger, None)
            .unwrap();
        let direct_irq = devices::DirectIrq::new(trigger, None).map_err(Error::DirectIrq)?;
        direct_irq.irq_enable(*irq).map_err(Error::DirectIrq)?;
        irqs.push(direct_irq);
    }

    let gralloc = RutabagaGralloc::new().map_err(Error::CreateGrallocError)?;
    run_control(
        linux,
        sys_allocator,
        control_server_socket,
        control_tubes,
        balloon_host_tube,
        &disk_host_tubes,
        #[cfg(feature = "usb")]
        usb_control_tube,
        exit_evt,
        sigchld_fd,
        cfg.sandbox,
        Arc::clone(&map_request),
        gralloc,
    )
}

/// Signals all running VCPUs to vmexit, sends VcpuControl message to each VCPU tube, and tells
/// `irq_chip` to stop blocking halted VCPUs. The channel message is set first because both the
/// signal and the irq_chip kick could cause the VCPU thread to continue through the VCPU run
/// loop.
fn kick_all_vcpus(
    vcpu_handles: &[(JoinHandle<()>, mpsc::Sender<vm_control::VcpuControl>)],
    irq_chip: &dyn IrqChip,
    message: VcpuControl,
) {
    for (handle, tube) in vcpu_handles {
        if let Err(e) = tube.send(message.clone()) {
            error!("failed to send VcpuControl: {}", e);
        }
        let _ = handle.kill(SIGRTMIN() + 0);
    }
    irq_chip.kick_halted_vcpus();
}

fn run_control<V: VmArch + 'static, Vcpu: VcpuArch + 'static>(
    mut linux: RunnableLinuxVm<V, Vcpu>,
    mut sys_allocator: SystemAllocator,
    control_server_socket: Option<UnlinkUnixSeqpacketListener>,
    mut control_tubes: Vec<TaggedControlTube>,
    balloon_host_tube: Tube,
    disk_host_tubes: &[Tube],
    #[cfg(feature = "usb")] usb_control_tube: Tube,
    exit_evt: Event,
    sigchld_fd: SignalFd,
    sandbox: bool,
    map_request: Arc<Mutex<Option<ExternalMapping>>>,
    mut gralloc: RutabagaGralloc,
) -> Result<()> {
    #[derive(PollToken)]
    enum Token {
        Exit,
        Suspend,
        ChildSignal,
        IrqFd { index: IrqEventIndex },
        VmControlServer,
        VmControl { index: usize },
    }

    stdin()
        .set_raw_mode()
        .expect("failed to set terminal raw mode");

    let wait_ctx = WaitContext::build_with(&[
        (&exit_evt, Token::Exit),
        (&linux.suspend_evt, Token::Suspend),
        (&sigchld_fd, Token::ChildSignal),
    ])
    .map_err(Error::WaitContextAdd)?;

    if let Some(socket_server) = &control_server_socket {
        wait_ctx
            .add(socket_server, Token::VmControlServer)
            .map_err(Error::WaitContextAdd)?;
    }
    for (index, socket) in control_tubes.iter().enumerate() {
        wait_ctx
            .add(socket.as_ref(), Token::VmControl { index })
            .map_err(Error::WaitContextAdd)?;
    }

    let events = linux
        .irq_chip
        .irq_event_tokens()
        .map_err(Error::WaitContextAdd)?;

    for (index, _gsi, evt) in events {
        wait_ctx
            .add(&evt, Token::IrqFd { index })
            .map_err(Error::WaitContextAdd)?;
    }

    if sandbox {
        // Before starting VCPUs, in case we started with some capabilities, drop them all.
        drop_capabilities().map_err(Error::DropCapabilities)?;
    }

    #[cfg(all(target_arch = "x86_64", feature = "gdb"))]
    // Create a channel for GDB thread.
    let (to_gdb_channel, from_vcpu_channel) = if linux.gdb.is_some() {
        let (s, r) = mpsc::channel();
        (Some(s), Some(r))
    } else {
        (None, None)
    };

    let mut vcpu_handles = Vec::with_capacity(linux.vcpu_count);
    let vcpu_thread_barrier = Arc::new(Barrier::new(linux.vcpu_count + 1));
    let use_hypervisor_signals = !linux
        .vm
        .get_hypervisor()
        .check_capability(&HypervisorCap::ImmediateExit);
    setup_vcpu_signal_handler::<Vcpu>(use_hypervisor_signals)?;

    let vcpus: Vec<Option<_>> = match linux.vcpus.take() {
        Some(vec) => vec.into_iter().map(Some).collect(),
        None => iter::repeat_with(|| None).take(linux.vcpu_count).collect(),
    };
    for (cpu_id, vcpu) in vcpus.into_iter().enumerate() {
        let (to_vcpu_channel, from_main_channel) = mpsc::channel();
        let vcpu_affinity = match linux.vcpu_affinity.clone() {
            Some(VcpuAffinity::Global(v)) => v,
            Some(VcpuAffinity::PerVcpu(mut m)) => m.remove(&cpu_id).unwrap_or_default(),
            None => Default::default(),
        };
        let handle = run_vcpu(
            cpu_id,
            vcpu,
            linux.vm.try_clone().map_err(Error::CloneEvent)?,
            linux.irq_chip.try_box_clone().map_err(Error::CloneEvent)?,
            linux.vcpu_count,
            linux.rt_cpus.contains(&cpu_id),
            vcpu_affinity,
            linux.delay_rt,
            linux.no_smt,
            vcpu_thread_barrier.clone(),
            linux.has_bios,
            linux.io_bus.clone(),
            linux.mmio_bus.clone(),
            exit_evt.try_clone().map_err(Error::CloneEvent)?,
            linux.vm.check_capability(VmCap::PvClockSuspend),
            from_main_channel,
            use_hypervisor_signals,
            #[cfg(all(target_arch = "x86_64", feature = "gdb"))]
            to_gdb_channel.clone(),
        )?;
        vcpu_handles.push((handle, to_vcpu_channel));
    }

    #[cfg(all(target_arch = "x86_64", feature = "gdb"))]
    // Spawn GDB thread.
    if let Some((gdb_port_num, gdb_control_tube)) = linux.gdb.take() {
        let to_vcpu_channels = vcpu_handles
            .iter()
            .map(|(_handle, channel)| channel.clone())
            .collect();
        let target = GdbStub::new(
            gdb_control_tube,
            to_vcpu_channels,
            from_vcpu_channel.unwrap(), // Must succeed to unwrap()
        );
        thread::Builder::new()
            .name("gdb".to_owned())
            .spawn(move || gdb_thread(target, gdb_port_num))
            .map_err(Error::SpawnGdbServer)?;
    };

    vcpu_thread_barrier.wait();

    let mut balloon_stats_id: u64 = 0;

    'wait: loop {
        let events = {
            match wait_ctx.wait() {
                Ok(v) => v,
                Err(e) => {
                    error!("failed to poll: {}", e);
                    break;
                }
            }
        };

        if let Err(e) = linux.irq_chip.process_delayed_irq_events() {
            warn!("can't deliver delayed irqs: {}", e);
        }

        let mut vm_control_indices_to_remove = Vec::new();
        for event in events.iter().filter(|e| e.is_readable) {
            match event.token {
                Token::Exit => {
                    info!("vcpu requested shutdown");
                    break 'wait;
                }
                Token::Suspend => {
                    info!("VM requested suspend");
                    linux.suspend_evt.read().unwrap();
                    kick_all_vcpus(
                        &vcpu_handles,
                        linux.irq_chip.as_irq_chip(),
                        VcpuControl::RunState(VmRunMode::Suspending),
                    );
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
                    break 'wait;
                }
                Token::IrqFd { index } => {
                    if let Err(e) = linux.irq_chip.service_irq_event(index) {
                        error!("failed to signal irq {}: {}", index, e);
                    }
                }
                Token::VmControlServer => {
                    if let Some(socket_server) = &control_server_socket {
                        match socket_server.accept() {
                            Ok(socket) => {
                                wait_ctx
                                    .add(
                                        &socket,
                                        Token::VmControl {
                                            index: control_tubes.len(),
                                        },
                                    )
                                    .map_err(Error::WaitContextAdd)?;
                                control_tubes.push(TaggedControlTube::Vm(Tube::new(socket)));
                            }
                            Err(e) => error!("failed to accept socket: {}", e),
                        }
                    }
                }
                Token::VmControl { index } => {
                    if let Some(socket) = control_tubes.get(index) {
                        match socket {
                            TaggedControlTube::Vm(tube) => match tube.recv::<VmRequest>() {
                                Ok(request) => {
                                    let mut run_mode_opt = None;
                                    let response = request.execute(
                                        &mut run_mode_opt,
                                        &balloon_host_tube,
                                        &mut balloon_stats_id,
                                        disk_host_tubes,
                                        #[cfg(feature = "usb")]
                                        Some(&usb_control_tube),
                                        #[cfg(not(feature = "usb"))]
                                        None,
                                        &mut linux.bat_control,
                                        &vcpu_handles,
                                    );
                                    if let Err(e) = tube.send(&response) {
                                        error!("failed to send VmResponse: {}", e);
                                    }
                                    if let Some(run_mode) = run_mode_opt {
                                        info!("control socket changed run mode to {}", run_mode);
                                        match run_mode {
                                            VmRunMode::Exiting => {
                                                break 'wait;
                                            }
                                            other => {
                                                if other == VmRunMode::Running {
                                                    for dev in &linux.resume_notify_devices {
                                                        dev.lock().resume_imminent();
                                                    }
                                                }
                                                kick_all_vcpus(
                                                    &vcpu_handles,
                                                    linux.irq_chip.as_irq_chip(),
                                                    VcpuControl::RunState(other),
                                                );
                                            }
                                        }
                                    }
                                }
                                Err(e) => {
                                    if let TubeError::Disconnected = e {
                                        vm_control_indices_to_remove.push(index);
                                    } else {
                                        error!("failed to recv VmRequest: {}", e);
                                    }
                                }
                            },
                            TaggedControlTube::VmMemory(tube) => {
                                match tube.recv::<VmMemoryRequest>() {
                                    Ok(request) => {
                                        let response = request.execute(
                                            &mut linux.vm,
                                            &mut sys_allocator,
                                            Arc::clone(&map_request),
                                            &mut gralloc,
                                        );
                                        if let Err(e) = tube.send(&response) {
                                            error!("failed to send VmMemoryControlResponse: {}", e);
                                        }
                                    }
                                    Err(e) => {
                                        if let TubeError::Disconnected = e {
                                            vm_control_indices_to_remove.push(index);
                                        } else {
                                            error!("failed to recv VmMemoryControlRequest: {}", e);
                                        }
                                    }
                                }
                            }
                            TaggedControlTube::VmIrq(tube) => match tube.recv::<VmIrqRequest>() {
                                Ok(request) => {
                                    let response = {
                                        let irq_chip = &mut linux.irq_chip;
                                        request.execute(
                                            |setup| match setup {
                                                IrqSetup::Event(irq, ev) => {
                                                    if let Some(event_index) = irq_chip
                                                        .register_irq_event(irq, ev, None)?
                                                    {
                                                        match wait_ctx.add(
                                                            ev,
                                                            Token::IrqFd {
                                                                index: event_index
                                                            },
                                                        ) {
                                                            Err(e) => {
                                                                warn!("failed to add IrqFd to poll context: {}", e);
                                                                Err(e)
                                                            },
                                                            Ok(_) => {
                                                                Ok(())
                                                            }
                                                        }
                                                    } else {
                                                        Ok(())
                                                    }
                                                }
                                                IrqSetup::Route(route) => irq_chip.route_irq(route),
                                            },
                                            &mut sys_allocator,
                                        )
                                    };
                                    if let Err(e) = tube.send(&response) {
                                        error!("failed to send VmIrqResponse: {}", e);
                                    }
                                }
                                Err(e) => {
                                    if let TubeError::Disconnected = e {
                                        vm_control_indices_to_remove.push(index);
                                    } else {
                                        error!("failed to recv VmIrqRequest: {}", e);
                                    }
                                }
                            },
                            TaggedControlTube::VmMsync(tube) => {
                                match tube.recv::<VmMsyncRequest>() {
                                    Ok(request) => {
                                        let response = request.execute(&mut linux.vm);
                                        if let Err(e) = tube.send(&response) {
                                            error!("failed to send VmMsyncResponse: {}", e);
                                        }
                                    }
                                    Err(e) => {
                                        if let TubeError::Disconnected = e {
                                            vm_control_indices_to_remove.push(index);
                                        } else {
                                            error!("failed to recv VmMsyncRequest: {}", e);
                                        }
                                    }
                                }
                            }
                            TaggedControlTube::Fs(tube) => match tube.recv::<FsMappingRequest>() {
                                Ok(request) => {
                                    let response =
                                        request.execute(&mut linux.vm, &mut sys_allocator);
                                    if let Err(e) = tube.send(&response) {
                                        error!("failed to send VmResponse: {}", e);
                                    }
                                }
                                Err(e) => {
                                    if let TubeError::Disconnected = e {
                                        vm_control_indices_to_remove.push(index);
                                    } else {
                                        error!("failed to recv VmResponse: {}", e);
                                    }
                                }
                            },
                        }
                    }
                }
            }
        }

        // It's possible more data is readable and buffered while the socket is hungup,
        // so don't delete the tube from the poll context until we're sure all the
        // data is read.
        // Below case covers a condition where we have received a hungup event and the tube is not
        // readable.
        // In case of readable tube, once all data is read, any attempt to read more data on hungup
        // tube should fail. On such failure, we get Disconnected error and index gets added to
        // vm_control_indices_to_remove by the time we reach here.
        for event in events.iter().filter(|e| e.is_hungup && !e.is_readable) {
            if let Token::VmControl { index } = event.token {
                vm_control_indices_to_remove.push(index);
            }
        }

        // Sort in reverse so the highest indexes are removed first. This removal algorithm
        // preserves correct indexes as each element is removed.
        vm_control_indices_to_remove.sort_unstable_by_key(|&k| Reverse(k));
        vm_control_indices_to_remove.dedup();
        for index in vm_control_indices_to_remove {
            // Delete the socket from the `wait_ctx` synchronously. Otherwise, the kernel will do
            // this automatically when the FD inserted into the `wait_ctx` is closed after this
            // if-block, but this removal can be deferred unpredictably. In some instances where the
            // system is under heavy load, we can even get events returned by `wait_ctx` for an FD
            // that has already been closed. Because the token associated with that spurious event
            // now belongs to a different socket, the control loop will start to interact with
            // sockets that might not be ready to use. This can cause incorrect hangup detection or
            // blocking on a socket that will never be ready. See also: crbug.com/1019986
            if let Some(socket) = control_tubes.get(index) {
                wait_ctx.delete(socket).map_err(Error::WaitContextDelete)?;
            }

            // This line implicitly drops the socket at `index` when it gets returned by
            // `swap_remove`. After this line, the socket at `index` is not the one from
            // `vm_control_indices_to_remove`. Because of this socket's change in index, we need to
            // use `wait_ctx.modify` to change the associated index in its `Token::VmControl`.
            control_tubes.swap_remove(index);
            if let Some(tube) = control_tubes.get(index) {
                wait_ctx
                    .modify(tube, EventType::Read, Token::VmControl { index })
                    .map_err(Error::WaitContextAdd)?;
            }
        }
    }

    kick_all_vcpus(
        &vcpu_handles,
        linux.irq_chip.as_irq_chip(),
        VcpuControl::RunState(VmRunMode::Exiting),
    );
    for (handle, _) in vcpu_handles {
        if let Err(e) = handle.join() {
            error!("failed to join vcpu thread: {:?}", e);
        }
    }

    // Explicitly drop the VM structure here to allow the devices to clean up before the
    // control sockets are closed when this function exits.
    mem::drop(linux);

    stdin()
        .set_canon_mode()
        .expect("failed to restore canonical mode for terminal");

    Ok(())
}
