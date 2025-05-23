// Copyright 2025 Google
// SPDX-License-Identifier: MIT

use crate::defines::MappedRegion;
use crate::sys::platform::MemoryMapping as PlatformMapping;
use crate::MesaMapping;
use crate::MesaResult;
use crate::OwnedDescriptor;

pub struct MemoryMapping {
    mapping: PlatformMapping,
}

impl MemoryMapping {
    pub fn from_safe_descriptor(
        descriptor: OwnedDescriptor,
        size: usize,
        map_info: u32,
    ) -> MesaResult<MemoryMapping> {
        let mapping = PlatformMapping::from_safe_descriptor(descriptor, size, map_info)?;
        Ok(MemoryMapping { mapping })
    }

    pub fn from_offset(
        descriptor: &OwnedDescriptor,
        offset: usize,
        size: usize,
    ) -> MesaResult<MemoryMapping> {
        let mapping = PlatformMapping::from_offset(descriptor, offset, size)?;
        Ok(MemoryMapping { mapping })
    }

    pub fn as_mesa_mapping(&self) -> MesaMapping {
        MesaMapping {
            ptr: self.mapping.addr as u64,
            size: self.mapping.size as u64,
        }
    }
}

// SAFETY: Safe since these functions just access the MemoryMapping structure.
unsafe impl MappedRegion for MemoryMapping {
    fn as_ptr(&self) -> *mut u8 {
        self.mapping.addr as *mut u8
    }

    fn size(&self) -> usize {
        self.mapping.size
    }

    fn as_mesa_mapping(&self) -> MesaMapping {
        self.as_mesa_mapping()
    }
}
