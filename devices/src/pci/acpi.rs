// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use acpi_tables::aml;
use acpi_tables::aml::Aml;
use anyhow::anyhow;
use anyhow::Result;
use base::MemoryMapping;
use base::MemoryMappingBuilder;
use base::Protection;
use base::SharedMemory;

pub const SHM_OFFSET: u32 = 0x1000;
pub const SHM_SIZE: u32 = 0x1000;

pub struct DeviceVcfgRegister {
    offset: u32,
    shm: SharedMemory,
}

impl DeviceVcfgRegister {
    pub fn new(offset: u32) -> Result<DeviceVcfgRegister> {
        let shm = SharedMemory::new("VCFG register", SHM_SIZE as u64)
            .map_err(|_| anyhow!("failed to create shared memory"))?;
        Ok(DeviceVcfgRegister { offset, shm })
    }

    pub fn create_shm_mmap(&self) -> Option<MemoryMapping> {
        MemoryMappingBuilder::new(SHM_SIZE as usize)
            .from_shared_memory(&self.shm)
            .offset(0)
            .protection(Protection::read_write())
            .build()
            .ok()
    }
}

impl Aml for DeviceVcfgRegister {
    fn to_aml_bytes(&self, bytes: &mut Vec<u8>) {
        aml::OpRegion::new(
            "VREG".into(),
            aml::OpRegionSpace::SystemMemory,
            &aml::Add::new(&aml::ZERO, &aml::Name::new_field_name("VCFG"), &self.offset),
            &4096_usize,
        )
        .to_aml_bytes(bytes);
        aml::Field::new(
            "VREG".into(),
            aml::FieldAccessType::DWord,
            aml::FieldLockRule::Lock,
            aml::FieldUpdateRule::Preserve,
            vec![aml::FieldEntry::Named(*b"PFPM", 32)],
        )
        .to_aml_bytes(bytes);
        aml::OpRegion::new(
            "SHAM".into(),
            aml::OpRegionSpace::SystemMemory,
            &aml::Add::new(
                &aml::ZERO,
                &aml::Name::new_field_name("VCFG"),
                &(self.offset + SHM_OFFSET),
            ),
            &SHM_SIZE,
        )
        .to_aml_bytes(bytes);
    }
}

pub struct PowerResourceMethod {}

impl Aml for PowerResourceMethod {
    fn to_aml_bytes(&self, aml: &mut Vec<u8>) {
        aml::PowerResource::new(
            "PRIC".into(),
            0u8,
            0u16,
            vec![
                &aml::Name::new("_STA".into(), &aml::ONE),
                &aml::Method::new(
                    "_ON_".into(),
                    0,
                    true,
                    vec![
                        &aml::Store::new(&aml::Name::new_field_name("PFPM"), &aml::ONE),
                        &aml::Store::new(&aml::Name::new_field_name("_STA"), &aml::ONE),
                    ],
                ),
                &aml::Method::new(
                    "_OFF".into(),
                    0,
                    true,
                    vec![
                        &aml::Store::new(&aml::Name::new_field_name("_STA"), &aml::ZERO),
                        &aml::Store::new(&aml::Name::new_field_name("PFPM"), &aml::ZERO),
                    ],
                ),
            ],
        )
        .to_aml_bytes(aml);
        aml::Name::new(
            "_PR0".into(),
            &aml::Package::new(vec![&aml::Name::new_field_name("PRIC")]),
        )
        .to_aml_bytes(aml);
        aml::Name::new(
            "_PR3".into(),
            &aml::Package::new(vec![&aml::Name::new_field_name("PRIC")]),
        )
        .to_aml_bytes(aml);
    }
}
