// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Implements virtio devices, queues, and transport mechanisms.

mod async_device;
mod async_utils;
#[cfg(feature = "balloon")]
mod balloon;
mod descriptor_utils;
pub mod device_constants;
mod input;
mod interrupt;
mod iommu;
mod queue;
mod rng;
mod sys;
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
pub mod resource_bridge;
#[cfg(feature = "audio")]
pub mod snd;
pub mod vhost;

#[cfg(feature = "balloon")]
pub use self::balloon::*;
pub use self::block::*;
pub use self::console::*;
pub use self::descriptor_utils::Error as DescriptorError;
pub use self::descriptor_utils::*;
pub use self::input::*;
pub use self::interrupt::*;
pub use self::iommu::*;
pub use self::queue::*;
pub use self::rng::*;
#[cfg(any(feature = "tpm", feature = "vtpm"))]
pub use self::tpm::*;
#[cfg(any(feature = "video-decoder", feature = "video-encoder"))]
pub use self::video::*;
pub use self::virtio_device::*;
pub use self::virtio_mmio_device::*;
pub use self::virtio_pci_device::*;
cfg_if::cfg_if! {
    if #[cfg(unix)] {
        mod p9;
        mod pmem;
        pub mod wl;

        pub mod fs;
        #[cfg(feature = "gpu")]
        pub mod gpu;
        pub mod net;

        #[cfg(feature = "gpu")]
        pub use self::gpu::*;
        pub use self::iommu::sys::unix::vfio_wrapper;
        pub use self::net::*;
        pub use self::p9::*;
        pub use self::pmem::*;
        #[cfg(feature = "audio")]
        pub use self::snd::*;
        pub use self::wl::*;

    } else if #[cfg(windows)] {
        mod vsock;

        #[cfg(feature = "slirp")]
        pub mod net;

        #[cfg(feature = "slirp")]
        pub use self::net::*;
        #[cfg(feature = "slirp")]
        pub use self::sys::windows::NetExt;
        pub use self::vsock::*;
    } else {
        compile_error!("Unsupported platform");
    }
}
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

/// Offset from the base MMIO address of a virtio device used by the guest to notify the device of
/// queue events.
pub const NOTIFY_REG_OFFSET: u32 = 0x50;

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
    Wl = virtio_ids::VIRTIO_ID_WL,
    Tpm = virtio_ids::VIRTIO_ID_TPM,
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
            DeviceType::VideoDec => write!(f, "video-decoder"),
            DeviceType::VideoEnc => write!(f, "video-encoder"),
            DeviceType::Mac80211HwSim => write!(f, "mac-80211-hw-sim"),
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
