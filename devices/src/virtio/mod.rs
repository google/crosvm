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
#[cfg(feature = "net")]
pub mod net;
#[cfg(target_arch = "x86_64")]
pub mod pvclock;
mod queue;
mod rng;
#[cfg(feature = "vtpm")]
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
pub mod scsi;
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
pub use self::descriptor_chain::DescriptorChain;
pub use self::descriptor_chain::DescriptorChainIter;
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
pub use self::iommu::Iommu;
pub use self::iommu::IommuError;
#[cfg(feature = "net")]
pub use self::net::Net;
#[cfg(feature = "net")]
pub use self::net::NetError;
#[cfg(feature = "net")]
pub use self::net::NetParameters;
#[cfg(feature = "net")]
pub use self::net::NetParametersMode;
pub use self::queue::split_descriptor_chain::Desc;
pub use self::queue::split_descriptor_chain::SplitDescriptorChain;
pub use self::queue::PeekedDescriptorChain;
pub use self::queue::Queue;
pub use self::queue::QueueConfig;
pub use self::rng::Rng;
pub use self::scsi::Controller as ScsiController;
pub use self::scsi::DiskConfig as ScsiDiskConfig;
#[cfg(feature = "vtpm")]
pub use self::tpm::Tpm;
#[cfg(feature = "vtpm")]
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
    if #[cfg(any(target_os = "android", target_os = "linux"))] {
        mod p9;
        mod pmem;

        pub mod wl;
        pub mod fs;

        pub use self::iommu::sys::linux::vfio_wrapper;
        #[cfg(feature = "net")]
        pub use self::net::VhostNetParameters;
        #[cfg(feature = "net")]
        pub use self::net::VHOST_NET_DEFAULT_PATH;
        pub use self::p9::P9;
        pub use self::pmem::Pmem;
        #[cfg(feature = "audio")]
        pub use self::snd::new_sound;
        pub use self::wl::Wl;
    } else if #[cfg(windows)] {
        pub use self::vsock::Vsock;
    } else {
        compile_error!("Unsupported platform");
    }
}

use std::cmp;
use std::convert::TryFrom;

use futures::channel::oneshot;
use hypervisor::ProtectionType;
use serde::Deserialize;
use serde::Serialize;
use virtio_sys::virtio_config::VIRTIO_F_ACCESS_PLATFORM;
use virtio_sys::virtio_config::VIRTIO_F_VERSION_1;
use virtio_sys::virtio_ids;
use virtio_sys::virtio_ring::VIRTIO_RING_F_EVENT_IDX;

const DEVICE_RESET: u32 = 0x0;

const INTERRUPT_STATUS_USED_RING: u32 = 0x1;
const INTERRUPT_STATUS_CONFIG_CHANGED: u32 = 0x2;

const VIRTIO_MSI_NO_VECTOR: u16 = 0xffff;

#[derive(Copy, Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
#[repr(u32)]
pub enum DeviceType {
    Net = virtio_ids::VIRTIO_ID_NET,
    Block = virtio_ids::VIRTIO_ID_BLOCK,
    Console = virtio_ids::VIRTIO_ID_CONSOLE,
    Rng = virtio_ids::VIRTIO_ID_RNG,
    Balloon = virtio_ids::VIRTIO_ID_BALLOON,
    Scsi = virtio_ids::VIRTIO_ID_SCSI,
    #[serde(rename = "9p")]
    P9 = virtio_ids::VIRTIO_ID_9P,
    Gpu = virtio_ids::VIRTIO_ID_GPU,
    Input = virtio_ids::VIRTIO_ID_INPUT,
    Vsock = virtio_ids::VIRTIO_ID_VSOCK,
    Iommu = virtio_ids::VIRTIO_ID_IOMMU,
    Sound = virtio_ids::VIRTIO_ID_SOUND,
    Fs = virtio_ids::VIRTIO_ID_FS,
    Pmem = virtio_ids::VIRTIO_ID_PMEM,
    #[serde(rename = "mac80211-hwsim")]
    Mac80211HwSim = virtio_ids::VIRTIO_ID_MAC80211_HWSIM,
    VideoEncoder = virtio_ids::VIRTIO_ID_VIDEO_ENCODER,
    VideoDecoder = virtio_ids::VIRTIO_ID_VIDEO_DECODER,
    Scmi = virtio_ids::VIRTIO_ID_SCMI,
    Wl = virtio_ids::VIRTIO_ID_WL,
    Tpm = virtio_ids::VIRTIO_ID_TPM,
    Pvclock = virtio_ids::VIRTIO_ID_PVCLOCK,
}

impl DeviceType {
    /// Returns the minimum number of queues that a device of the corresponding type must support.
    ///
    /// Note that this does not mean a driver must activate these queues, only that they must be
    /// implemented by a spec-compliant device.
    pub fn min_queues(&self) -> usize {
        match self {
            DeviceType::Net => 3,           // rx, tx (TODO: b/314353246: ctrl is optional)
            DeviceType::Block => 1,         // request queue
            DeviceType::Console => 2,       // receiveq, transmitq
            DeviceType::Rng => 1,           // request queue
            DeviceType::Balloon => 2,       // inflateq, deflateq
            DeviceType::Scsi => 3,          // controlq, eventq, request queue
            DeviceType::P9 => 1,            // request queue
            DeviceType::Gpu => 2,           // controlq, cursorq
            DeviceType::Input => 2,         // eventq, statusq
            DeviceType::Vsock => 3,         // rx, tx, event
            DeviceType::Iommu => 2,         // requestq, eventq
            DeviceType::Sound => 4,         // controlq, eventq, txq, rxq
            DeviceType::Fs => 2,            // hiprio, request queue
            DeviceType::Pmem => 1,          // request queue
            DeviceType::Mac80211HwSim => 2, // tx, rx
            DeviceType::VideoEncoder => 2,  // cmdq, eventq
            DeviceType::VideoDecoder => 2,  // cmdq, eventq
            DeviceType::Scmi => 2,          // cmdq, eventq
            DeviceType::Wl => 2,            // in, out
            DeviceType::Tpm => 1,           // request queue
            DeviceType::Pvclock => 1,       // request queue
        }
    }
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
            DeviceType::Scsi => write!(f, "scsi"),
            DeviceType::P9 => write!(f, "9p"),
            DeviceType::Input => write!(f, "input"),
            DeviceType::Gpu => write!(f, "gpu"),
            DeviceType::Vsock => write!(f, "vsock"),
            DeviceType::Iommu => write!(f, "iommu"),
            DeviceType::Sound => write!(f, "sound"),
            DeviceType::Fs => write!(f, "fs"),
            DeviceType::Pmem => write!(f, "pmem"),
            DeviceType::Wl => write!(f, "wl"),
            DeviceType::Tpm => write!(f, "tpm"),
            DeviceType::Pvclock => write!(f, "pvclock"),
            DeviceType::VideoDecoder => write!(f, "video-decoder"),
            DeviceType::VideoEncoder => write!(f, "video-encoder"),
            DeviceType::Mac80211HwSim => write!(f, "mac80211-hwsim"),
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
}

impl VirtioDeviceType {
    /// Returns the seccomp policy file that we will want to load for device `base`, depending on
    /// the virtio transport type.
    pub fn seccomp_policy_file(&self, base: &str) -> String {
        match self {
            VirtioDeviceType::Regular => format!("{base}_device"),
            VirtioDeviceType::VhostUser => format!("{base}_device_vhost_user"),
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

/// When we request to stop the worker, this represents the terminal state
/// for the thread (if it exists).
pub(crate) enum StoppedWorker<Q> {
    /// Worker stopped successfully & returned its queues.
    WithQueues(Box<Q>),

    /// Worker wasn't running when the stop was requested.
    AlreadyStopped,

    /// Worker was running but did not successfully return its queues. Something
    /// has gone wrong (and will be in the error log). In the case of a device
    /// reset this is fine since the next activation will replace the queues.
    MissingQueues,
}
