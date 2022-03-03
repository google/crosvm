// Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Implements virtio devices, queues, and transport mechanisms.

mod async_utils;
mod balloon;
mod descriptor_utils;
mod input;
mod interrupt;
mod iommu;
mod p9;
mod pmem;
mod queue;
mod rng;
#[cfg(feature = "tpm")]
mod tpm;
#[cfg(any(feature = "video-decoder", feature = "video-encoder"))]
mod video;
mod virtio_device;
mod virtio_pci_common_config;
mod virtio_pci_device;
pub mod wl;

pub mod block;
pub mod console;
pub mod fs;
#[cfg(feature = "gpu")]
pub mod gpu;
pub mod net;
pub mod resource_bridge;
#[cfg(feature = "audio")]
pub mod snd;
pub mod vhost;

pub use self::balloon::*;
pub use self::block::*;
pub use self::console::*;
pub use self::descriptor_utils::Error as DescriptorError;
pub use self::descriptor_utils::*;
#[cfg(feature = "gpu")]
pub use self::gpu::*;
pub use self::input::*;
pub use self::interrupt::*;
pub use self::iommu::*;
pub use self::net::*;
pub use self::p9::*;
pub use self::pmem::*;
pub use self::queue::*;
pub use self::rng::*;
#[cfg(feature = "audio")]
pub use self::snd::*;
#[cfg(feature = "tpm")]
pub use self::tpm::*;
#[cfg(any(feature = "video-decoder", feature = "video-encoder"))]
pub use self::video::*;
pub use self::virtio_device::*;
pub use self::virtio_pci_device::*;
pub use self::wl::*;

use std::cmp;
use std::convert::TryFrom;

use hypervisor::ProtectionType;
use virtio_sys::virtio_ring::VIRTIO_RING_F_EVENT_IDX;

const DEVICE_RESET: u32 = 0x0;
const DEVICE_ACKNOWLEDGE: u32 = 0x01;
const DEVICE_DRIVER: u32 = 0x02;
const DEVICE_DRIVER_OK: u32 = 0x04;
const DEVICE_FEATURES_OK: u32 = 0x08;
const DEVICE_FAILED: u32 = 0x80;

// Types taken from linux/virtio_ids.h
const TYPE_NET: u32 = 1;
const TYPE_BLOCK: u32 = 2;
const TYPE_CONSOLE: u32 = 3;
const TYPE_RNG: u32 = 4;
const TYPE_BALLOON: u32 = 5;
const TYPE_RPMSG: u32 = 7;
const TYPE_SCSI: u32 = 8;
const TYPE_9P: u32 = 9;
const TYPE_RPROC_SERIAL: u32 = 11;
const TYPE_CAIF: u32 = 12;
const TYPE_GPU: u32 = 16;
const TYPE_INPUT: u32 = 18;
const TYPE_VSOCK: u32 = 19;
const TYPE_CRYPTO: u32 = 20;
const TYPE_IOMMU: u32 = 23;
const TYPE_SOUND: u32 = 25;
const TYPE_FS: u32 = 26;
const TYPE_PMEM: u32 = 27;
const TYPE_MAC80211_HWSIM: u32 = 29;
const TYPE_VIDEO_ENC: u32 = 30;
const TYPE_VIDEO_DEC: u32 = 31;
// Additional types invented by crosvm
const MAX_VIRTIO_DEVICE_ID: u32 = 63;
const TYPE_WL: u32 = MAX_VIRTIO_DEVICE_ID;
const TYPE_TPM: u32 = MAX_VIRTIO_DEVICE_ID - 1;
// TODO(abhishekbh): Fix this after this device is accepted upstream.
const TYPE_VHOST_USER: u32 = MAX_VIRTIO_DEVICE_ID - 2;

pub const VIRTIO_F_VERSION_1: u32 = 32;
pub const VIRTIO_F_ACCESS_PLATFORM: u32 = 33;

const INTERRUPT_STATUS_USED_RING: u32 = 0x1;
const INTERRUPT_STATUS_CONFIG_CHANGED: u32 = 0x2;

const VIRTIO_MSI_NO_VECTOR: u16 = 0xffff;

/// Offset from the base MMIO address of a virtio device used by the guest to notify the device of
/// queue events.
pub const NOTIFY_REG_OFFSET: u32 = 0x50;

/// Returns a string representation of the given virtio device type number.
pub fn type_to_str(type_: u32) -> Option<&'static str> {
    Some(match type_ {
        TYPE_NET => "net",
        TYPE_BLOCK => "block",
        TYPE_CONSOLE => "console",
        TYPE_RNG => "rng",
        TYPE_BALLOON => "balloon",
        TYPE_RPMSG => "rpmsg",
        TYPE_SCSI => "scsi",
        TYPE_9P => "9p",
        TYPE_RPROC_SERIAL => "rproc-serial",
        TYPE_CAIF => "caif",
        TYPE_INPUT => "input",
        TYPE_GPU => "gpu",
        TYPE_VSOCK => "vsock",
        TYPE_CRYPTO => "crypto",
        TYPE_IOMMU => "iommu",
        TYPE_VHOST_USER => "vhost-user",
        TYPE_SOUND => "snd",
        TYPE_FS => "fs",
        TYPE_PMEM => "pmem",
        TYPE_WL => "wl",
        TYPE_TPM => "tpm",
        TYPE_VIDEO_DEC => "video-decoder",
        TYPE_VIDEO_ENC => "video-encoder",
        _ => return None,
    })
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
pub fn base_features(protected_vm: ProtectionType) -> u64 {
    let mut features: u64 = 1 << VIRTIO_F_VERSION_1 | 1 << VIRTIO_RING_F_EVENT_IDX;

    if protected_vm != ProtectionType::Unprotected {
        features |= 1 << VIRTIO_F_ACCESS_PLATFORM;
    }

    features
}
