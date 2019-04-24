// Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Implements virtio devices, queues, and transport mechanisms.

mod balloon;
mod block;
#[cfg(feature = "gpu")]
mod gpu;
mod input;
mod net;
mod p9;
mod pmem;
mod queue;
mod rng;
#[cfg(feature = "tpm")]
mod tpm;
mod virtio_device;
mod virtio_pci_common_config;
mod virtio_pci_device;
mod wl;

pub mod resource_bridge;
pub mod vhost;

pub use self::balloon::*;
pub use self::block::*;
#[cfg(feature = "gpu")]
pub use self::gpu::*;
pub use self::input::*;
pub use self::net::*;
pub use self::p9::*;
pub use self::pmem::*;
pub use self::queue::*;
pub use self::rng::*;
#[cfg(feature = "tpm")]
pub use self::tpm::*;
pub use self::virtio_device::*;
pub use self::virtio_pci_device::*;
pub use self::wl::*;

const DEVICE_ACKNOWLEDGE: u32 = 0x01;
const DEVICE_DRIVER: u32 = 0x02;
const DEVICE_DRIVER_OK: u32 = 0x04;
const DEVICE_FEATURES_OK: u32 = 0x08;
const DEVICE_FAILED: u32 = 0x80;

// Types taken from linux/virtio_ids.h
const TYPE_NET: u32 = 1;
const TYPE_BLOCK: u32 = 2;
const TYPE_RNG: u32 = 4;
const TYPE_BALLOON: u32 = 5;
#[allow(dead_code)]
const TYPE_GPU: u32 = 16;
const TYPE_9P: u32 = 9;
const TYPE_INPUT: u32 = 18;
const TYPE_VSOCK: u32 = 19;
const TYPE_PMEM: u32 = 27;
// Additional types invented by crosvm
const TYPE_WL: u32 = 30;
#[cfg(feature = "tpm")]
const TYPE_TPM: u32 = 31;

const VIRTIO_F_VERSION_1: u32 = 32;

const INTERRUPT_STATUS_USED_RING: u32 = 0x1;
const INTERRUPT_STATUS_CONFIG_CHANGED: u32 = 0x2;

/// Offset from the base MMIO address of a virtio device used by the guest to notify the device of
/// queue events.
pub const NOTIFY_REG_OFFSET: u32 = 0x50;

/// Returns a string representation of the given virtio device type number.
pub fn type_to_str(type_: u32) -> Option<&'static str> {
    Some(match type_ {
        TYPE_NET => "net",
        TYPE_BLOCK => "block",
        TYPE_RNG => "rng",
        TYPE_BALLOON => "balloon",
        TYPE_GPU => "gpu",
        TYPE_9P => "9p",
        TYPE_VSOCK => "vsock",
        TYPE_WL => "wl",
        _ => return None,
    })
}
