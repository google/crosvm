// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Implements virtio devices, queues, and transport mechanisms.

mod async_device;
mod async_utils;
#[cfg(feature = "balloon")]
mod balloon;
mod descriptor_chain;
mod descriptor_utils;
pub mod device_constants;
pub mod input;
mod interrupt;
mod iommu;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub mod pvclock;
mod queue;
mod rng;
#[cfg(any(feature = "tpm", feature = "vtpm"))]
mod tpm;
#[cfg(any(feature = "video-decoder", feature = "video-encoder"))]
mod video;
mod virtio_device;
mod virtio_mmio_device;
mod virtio_pci_common_config;
mod virtio_pci_device;

pub mod block;
pub mod console;
#[cfg(feature = "gpu")]
pub mod gpu;
pub mod resource_bridge;
#[cfg(feature = "audio")]
pub mod snd;
pub mod vhost;
pub mod vsock;

#[cfg(feature = "balloon")]
pub use self::balloon::Balloon;
#[cfg(feature = "balloon")]
pub use self::balloon::BalloonFeatures;
#[cfg(feature = "balloon")]
pub use self::balloon::BalloonMode;
pub use self::block::BlockAsync;
pub use self::console::Console;
pub use self::descriptor_chain::Desc;
pub use self::descriptor_chain::DescriptorChain;
pub use self::descriptor_chain::DescriptorChainIter;
pub use self::descriptor_chain::SplitDescriptorChain;
pub use self::descriptor_utils::create_descriptor_chain;
pub use self::descriptor_utils::DescriptorType;
pub use self::descriptor_utils::Reader;
pub use self::descriptor_utils::Writer;
#[cfg(feature = "gpu")]
pub use self::gpu::DisplayBackend;
#[cfg(feature = "gpu")]
pub use self::gpu::Gpu;
#[cfg(feature = "gpu")]
pub use self::gpu::GpuDisplayMode;
#[cfg(feature = "gpu")]
pub use self::gpu::GpuDisplayParameters;
#[cfg(feature = "gpu")]
pub use self::gpu::GpuMode;
#[cfg(feature = "gpu")]
pub use self::gpu::GpuParameters;
#[cfg(feature = "gpu")]
pub use self::gpu::GpuWsi;
pub use self::interrupt::Interrupt;
pub use self::interrupt::InterruptSnapshot;
pub use self::iommu::ipc_memory_mapper;
pub use self::iommu::memory_mapper;
pub use self::iommu::memory_util;
pub use self::iommu::Iommu;
pub use self::iommu::IommuError;
pub use self::queue::Queue;
pub use self::queue::QueueType;
pub use self::rng::Rng;
#[cfg(any(feature = "tpm", feature = "vtpm"))]
pub use self::tpm::Tpm;
#[cfg(any(feature = "tpm", feature = "vtpm"))]
pub use self::tpm::TpmBackend;
#[cfg(any(feature = "video-decoder", feature = "video-encoder"))]
pub use self::video::VideoDevice;
pub use self::virtio_device::SharedMemoryMapper;
pub use self::virtio_device::SharedMemoryRegion;
pub use self::virtio_device::VirtioDevice;
pub use self::virtio_device::VirtioTransportType;
pub use self::virtio_mmio_device::VirtioMmioDevice;
pub use self::virtio_pci_device::PciCapabilityType;
pub use self::virtio_pci_device::VirtioPciCap;
pub use self::virtio_pci_device::VirtioPciDevice;
pub use self::virtio_pci_device::VirtioPciShmCap;

cfg_if::cfg_if! {
    if #[cfg(unix)] {
        mod p9;
        mod pmem;

        pub mod wl;
        pub mod fs;
        pub mod net;

        pub use self::iommu::sys::unix::vfio_wrapper;
        pub use self::net::Net;
        pub use self::net::NetError;
        pub use self::net::NetParameters;
        pub use self::net::NetParametersMode;
        pub use self::net::VhostNetParameters;
        pub use self::net::VHOST_NET_DEFAULT_PATH;
        pub use self::p9::P9;
        pub use self::pmem::Pmem;
        #[cfg(feature = "audio")]
        pub use self::snd::new_sound;
        pub use self::wl::Wl;
    } else if #[cfg(windows)] {
        #[cfg(feature = "slirp")]
        pub mod net;

        #[cfg(feature = "slirp")]
        pub use self::net::Net;
        #[cfg(feature = "slirp")]
        pub use self::net::NetParameters;
        pub use self::vsock::Vsock;
    } else {
        compile_error!("Unsupported platform");
    }
}

use futures::channel::oneshot;
use std::cmp;
use std::convert::TryFrom;

use hypervisor::ProtectionType;
use virtio_sys::virtio_config::VIRTIO_F_ACCESS_PLATFORM;
use virtio_sys::virtio_config::VIRTIO_F_VERSION_1;
use virtio_sys::virtio_ids;
use virtio_sys::virtio_ring::VIRTIO_RING_F_EVENT_IDX;

const DEVICE_RESET: u32 = 0x0;

const INTERRUPT_STATUS_USED_RING: u32 = 0x1;
const INTERRUPT_STATUS_CONFIG_CHANGED: u32 = 0x2;

const VIRTIO_MSI_NO_VECTOR: u16 = 0xffff;

#[derive(Copy, Clone, Eq, PartialEq)]
#[repr(u32)]
pub enum DeviceType {
    Net = virtio_ids::VIRTIO_ID_NET,
    Block = virtio_ids::VIRTIO_ID_BLOCK,
    Console = virtio_ids::VIRTIO_ID_CONSOLE,
    Rng = virtio_ids::VIRTIO_ID_RNG,
    Balloon = virtio_ids::VIRTIO_ID_BALLOON,
    Rpmsg = virtio_ids::VIRTIO_ID_RPMSG,
    Scsi = virtio_ids::VIRTIO_ID_SCSI,
    P9 = virtio_ids::VIRTIO_ID_9P,
    RprocSerial = virtio_ids::VIRTIO_ID_RPROC_SERIAL,
    Caif = virtio_ids::VIRTIO_ID_CAIF,
    Gpu = virtio_ids::VIRTIO_ID_GPU,
    Input = virtio_ids::VIRTIO_ID_INPUT,
    Vsock = virtio_ids::VIRTIO_ID_VSOCK,
    Crypto = virtio_ids::VIRTIO_ID_CRYPTO,
    Iommu = virtio_ids::VIRTIO_ID_IOMMU,
    Sound = virtio_ids::VIRTIO_ID_SOUND,
    Fs = virtio_ids::VIRTIO_ID_FS,
    Pmem = virtio_ids::VIRTIO_ID_PMEM,
    Mac80211HwSim = virtio_ids::VIRTIO_ID_MAC80211_HWSIM,
    VideoEnc = virtio_ids::VIRTIO_ID_VIDEO_ENCODER,
    VideoDec = virtio_ids::VIRTIO_ID_VIDEO_DECODER,
    Scmi = virtio_ids::VIRTIO_ID_SCMI,
    Wl = virtio_ids::VIRTIO_ID_WL,
    Tpm = virtio_ids::VIRTIO_ID_TPM,
    Pvclock = virtio_ids::VIRTIO_ID_PVCLOCK,
    VhostUser = virtio_ids::VIRTIO_ID_VHOST_USER,
}

/// Prints a string representation of the given virtio device type.
impl std::fmt::Display for DeviceType {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match &self {
            DeviceType::Net => write!(f, "net"),
            DeviceType::Block => write!(f, "block"),
            DeviceType::Console => write!(f, "console"),
            DeviceType::Rng => write!(f, "rng"),
            DeviceType::Balloon => write!(f, "balloon"),
            DeviceType::Rpmsg => write!(f, "rpmsg"),
            DeviceType::Scsi => write!(f, "scsi"),
            DeviceType::P9 => write!(f, "9p"),
            DeviceType::RprocSerial => write!(f, "rproc-serial"),
            DeviceType::Caif => write!(f, "caif"),
            DeviceType::Input => write!(f, "input"),
            DeviceType::Gpu => write!(f, "gpu"),
            DeviceType::Vsock => write!(f, "vsock"),
            DeviceType::Crypto => write!(f, "crypto"),
            DeviceType::Iommu => write!(f, "iommu"),
            DeviceType::VhostUser => write!(f, "vhost-user"),
            DeviceType::Sound => write!(f, "snd"),
            DeviceType::Fs => write!(f, "fs"),
            DeviceType::Pmem => write!(f, "pmem"),
            DeviceType::Wl => write!(f, "wl"),
            DeviceType::Tpm => write!(f, "tpm"),
            DeviceType::Pvclock => write!(f, "pvclock"),
            DeviceType::VideoDec => write!(f, "video-decoder"),
            DeviceType::VideoEnc => write!(f, "video-encoder"),
            DeviceType::Mac80211HwSim => write!(f, "mac-80211-hw-sim"),
            DeviceType::Scmi => write!(f, "scmi"),
        }
    }
}

/// Copy virtio device configuration data from a subslice of `src` to a subslice of `dst`.
/// Unlike std::slice::copy_from_slice(), this function copies as much as possible within
/// the common subset of the two slices, truncating the requested range instead of
/// panicking if the slices do not match in size.
///
/// `dst_offset` and `src_offset` specify the starting indexes of the `dst` and `src`
/// slices, respectively; if either index is out of bounds, this function is a no-op
/// rather than panicking.  This makes it safe to call with arbitrary user-controlled
/// inputs.
pub fn copy_config(dst: &mut [u8], dst_offset: u64, src: &[u8], src_offset: u64) {
    if let Ok(dst_offset) = usize::try_from(dst_offset) {
        if let Ok(src_offset) = usize::try_from(src_offset) {
            if let Some(dst_slice) = dst.get_mut(dst_offset..) {
                if let Some(src_slice) = src.get(src_offset..) {
                    let len = cmp::min(dst_slice.len(), src_slice.len());
                    let dst_subslice = &mut dst_slice[0..len];
                    let src_subslice = &src_slice[0..len];
                    dst_subslice.copy_from_slice(src_subslice);
                }
            }
        }
    }
}

/// Returns the set of reserved base features common to all virtio devices.
pub fn base_features(protection_type: ProtectionType) -> u64 {
    let mut features: u64 = 1 << VIRTIO_F_VERSION_1 | 1 << VIRTIO_RING_F_EVENT_IDX;

    if protection_type != ProtectionType::Unprotected {
        features |= 1 << VIRTIO_F_ACCESS_PLATFORM;
    }

    features
}

/// Type of virtio transport.
///
/// The virtio protocol can be transported by several means, which affects a few things for device
/// creation - for instance, the seccomp policy we need to use when jailing the device.
pub enum VirtioDeviceType {
    /// A regular (in-VMM) virtio device.
    Regular,
    /// Socket-backed vhost-user device.
    VhostUser,
    /// Virtio-backed vhost-user device, aka virtio-vhost-user.
    Vvu,
}

impl VirtioDeviceType {
    /// Returns the seccomp policy file that we will want to load for device `base`, depending on
    /// the virtio transport type.
    pub fn seccomp_policy_file(&self, base: &str) -> String {
        match self {
            VirtioDeviceType::Regular => format!("{base}_device"),
            VirtioDeviceType::VhostUser => format!("{base}_device_vhost_user"),
            VirtioDeviceType::Vvu => format!("{base}_device_vvu"),
        }
    }
}

/// Creates a oneshot channel, returning the rx end and adding the tx end to the
/// provided `Vec`. Useful for creating oneshots that signal a virtqueue future
/// to stop processing and exit.
pub(crate) fn create_stop_oneshot(tx_vec: &mut Vec<oneshot::Sender<()>>) -> oneshot::Receiver<()> {
    let (stop_tx, stop_rx) = futures::channel::oneshot::channel();
    tx_vec.push(stop_tx);
    stop_rx
}
