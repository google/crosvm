// Copyright (C) 2019-2021 Alibaba Cloud. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 or BSD-3-Clause
//
// Portions Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE-BSD-Google file.

//! Common traits and structs for vhost-user backend drivers.

use base::RawDescriptor;

/// Maximum number of memory regions supported.
pub const VHOST_MAX_MEMORY_REGIONS: usize = 255;

/// Vring configuration data.
pub struct VringConfigData {
    /// Actual queue size negotiated by the driver.
    pub queue_size: u16,
    /// Bitmask of vring flags.
    pub flags: u32,
    /// Descriptor table address.
    pub desc_table_addr: u64,
    /// Used ring buffer address.
    pub used_ring_addr: u64,
    /// Available ring buffer address.
    pub avail_ring_addr: u64,
    /// Optional address for logging.
    pub log_addr: Option<u64>,
}

impl VringConfigData {
    /// Check whether the log (flag, address) pair is valid.
    pub fn is_log_addr_valid(&self) -> bool {
        if self.flags & 0x1 != 0 && self.log_addr.is_none() {
            return false;
        }

        true
    }

    /// Get the log address, default to zero if not available.
    pub fn get_log_addr(&self) -> u64 {
        if self.flags & 0x1 != 0 && self.log_addr.is_some() {
            self.log_addr.unwrap()
        } else {
            0
        }
    }
}

/// Memory region configuration data.
pub struct VhostUserMemoryRegionInfo {
    /// Guest physical address of the memory region.
    pub guest_phys_addr: u64,
    /// Size of the memory region.
    pub memory_size: u64,
    /// Virtual address in the current process.
    pub userspace_addr: u64,
    /// Offset where region starts in the mapped memory.
    pub mmap_offset: u64,
    /// File descriptor for mmap.
    pub mmap_handle: RawDescriptor,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vring_config_data() {
        let mut config = VringConfigData {
            queue_size: 0x2000,
            flags: 0x0,
            desc_table_addr: 0x4000,
            used_ring_addr: 0x5000,
            avail_ring_addr: 0x6000,
            log_addr: None,
        };

        assert!(config.is_log_addr_valid());
        assert_eq!(config.get_log_addr(), 0);

        config.flags = 0x1;
        assert!(!config.is_log_addr_valid());
        assert_eq!(config.get_log_addr(), 0);

        config.log_addr = Some(0x7000);
        assert!(config.is_log_addr_valid());
        assert_eq!(config.get_log_addr(), 0x7000);

        config.flags = 0x0;
        assert!(config.is_log_addr_valid());
        assert_eq!(config.get_log_addr(), 0);
    }
}
