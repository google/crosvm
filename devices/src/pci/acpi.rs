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
            vec![
                aml::FieldEntry::Named(*b"PFPM", 32),
                aml::FieldEntry::Named(*b"PDSM", 32),
            ],
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
        aml::Field::new(
            "SHAM".into(),
            aml::FieldAccessType::Any,
            aml::FieldLockRule::Lock,
            aml::FieldUpdateRule::Preserve,
            vec![
                aml::FieldEntry::Named(*b"DSM0", 128),
                aml::FieldEntry::Named(*b"DSM1", 64),
                aml::FieldEntry::Named(*b"DSM2", 64),
                aml::FieldEntry::Named(*b"DSM3", 16384),
            ],
        )
        .to_aml_bytes(bytes);
        // HACK: TODO: Using "VREG" here is intentional.
        // Refer to `read_virtual_config_register` in devices/src/pci/vfio_pci.rs for more info.
        aml::Field::new(
            "VREG".into(),
            aml::FieldAccessType::DWord,
            aml::FieldLockRule::Lock,
            aml::FieldUpdateRule::Preserve,
            vec![
                aml::FieldEntry::Reserved(256),
                aml::FieldEntry::Named(*b"RTTP", 32),
                aml::FieldEntry::Named(*b"RTSZ", 32),
                aml::FieldEntry::Named(*b"RTDT", 16576),
            ],
        )
        .to_aml_bytes(bytes);
    }
}

pub struct DsmMethod {}

impl Aml for DsmMethod {
    fn to_aml_bytes(&self, aml: &mut Vec<u8>) {
        aml::Method::new(
            "_DSM".into(),
            4,
            true,
            vec![
                &aml::Store::new(&aml::Name::new_field_name("DSM0"), &aml::Arg(0)),
                &aml::Store::new(&aml::Name::new_field_name("DSM1"), &aml::Arg(1)),
                &aml::Store::new(&aml::Name::new_field_name("DSM2"), &aml::Arg(2)),
                &aml::Store::new(&aml::Local(2), &aml::ObjectType::new(&aml::Arg(3))),
                &aml::Store::new(&aml::Local(1), &aml::SizeOf::new(&aml::Arg(3))),
                &aml::Store::new(&aml::Local(0), &aml::BufferTerm::new(&16384_usize)),
                &aml::If::new(
                    &aml::Equal::new(&aml::Local(2), &3_usize),
                    vec![
                        &aml::CreateDWordField::new(
                            &aml::Name::new_field_name("BFTP"),
                            &aml::Local(0),
                            &0_usize,
                        ),
                        &aml::CreateDWordField::new(
                            &aml::Name::new_field_name("BFSZ"),
                            &aml::Local(0),
                            &4_usize,
                        ),
                        &aml::CreateField::new(
                            &aml::Name::new_field_name("BFDT"),
                            &aml::Local(0),
                            &(8_usize * 8_usize),
                            &aml::Multiply::new(&aml::ZERO, &aml::Local(1), &8_usize),
                        ),
                        &aml::Store::new(&aml::Name::new_field_name("BFTP"), &0x3_usize),
                        &aml::Store::new(&aml::Name::new_field_name("BFSZ"), &aml::Local(1)),
                        &aml::Store::new(&aml::Name::new_field_name("BFDT"), &aml::Arg(3)),
                    ],
                ),
                &aml::Else::new(vec![
                    &aml::If::new(
                        &aml::Equal::new(&aml::Local(2), &4_usize),
                        vec![
                            &aml::Store::new(&aml::Local(5), &aml::ZERO),
                            &aml::CreateDWordField::new(
                                &aml::Name::new_field_name("PKTP"),
                                &aml::Local(0),
                                &aml::Local(5),
                            ),
                            &aml::Store::new(&aml::Name::new_field_name("PKTP"), &0x4_usize),
                            &aml::Add::new(&aml::Local(5), &aml::Local(5), &4_usize),
                            &aml::CreateDWordField::new(
                                &aml::Name::new_field_name("PKSZ"),
                                &aml::Local(0),
                                &aml::Local(5),
                            ),
                            &aml::Store::new(&aml::Name::new_field_name("PKSZ"), &aml::Local(1)),
                            &aml::Add::new(&aml::Local(5), &aml::Local(5), &4_usize),
                            &aml::Store::new(&aml::Local(2), &aml::ZERO),
                            &aml::While::new(
                                &aml::LessThan::new(&aml::Local(2), &aml::Local(1)),
                                vec![
                                    &aml::Store::new(
                                        &aml::Local(3),
                                        &aml::DeRefOf::new(&aml::Index::new(
                                            &aml::ZERO,
                                            &aml::Arg(3),
                                            &aml::Local(2),
                                        )),
                                    ),
                                    &aml::Store::new(
                                        &aml::Local(4),
                                        &aml::ObjectType::new(&aml::Local(3)),
                                    ),
                                    &aml::Store::new(
                                        &aml::Local(6),
                                        &aml::SizeOf::new(&aml::Local(3)),
                                    ),
                                    &aml::CreateDWordField::new(
                                        &aml::Name::new_field_name("OUTP"),
                                        &aml::Local(0),
                                        &aml::Local(5),
                                    ),
                                    &aml::Store::new(
                                        &aml::Name::new_field_name("OUTP"),
                                        &aml::Local(4),
                                    ),
                                    &aml::Add::new(&aml::Local(5), &aml::Local(5), &4_usize),
                                    &aml::CreateDWordField::new(
                                        &aml::Name::new_field_name("OUSZ"),
                                        &aml::Local(0),
                                        &aml::Local(5),
                                    ),
                                    &aml::Store::new(
                                        &aml::Name::new_field_name("OUSZ"),
                                        &aml::Local(6),
                                    ),
                                    &aml::Add::new(&aml::Local(5), &aml::Local(5), &4_usize),
                                    &aml::If::new(
                                        &aml::Equal::new(&aml::Local(4), &1_usize),
                                        vec![
                                            &aml::CreateQWordField::new(
                                                &aml::Name::new_field_name("OUDT"),
                                                &aml::Local(0),
                                                &aml::Local(5),
                                            ),
                                            &aml::Store::new(
                                                &aml::Name::new_field_name("OUDT"),
                                                &aml::Local(3),
                                            ),
                                            &aml::Add::new(
                                                &aml::Local(5),
                                                &aml::Local(5),
                                                &8_usize,
                                            ),
                                        ],
                                    ),
                                    &aml::Else::new(vec![
                                        &aml::If::new(
                                            &aml::Equal::new(&aml::Local(4), &2_usize),
                                            vec![
                                                &aml::CreateField::new(
                                                    &aml::Name::new_field_name("OSDT"),
                                                    &aml::Local(0),
                                                    &aml::Multiply::new(
                                                        &aml::ZERO,
                                                        &aml::Local(5),
                                                        &8_usize,
                                                    ),
                                                    &aml::Multiply::new(
                                                        &aml::ZERO,
                                                        &aml::Local(6),
                                                        &8_usize,
                                                    ),
                                                ),
                                                &aml::Store::new(
                                                    &aml::Name::new_field_name("OSDT"),
                                                    &aml::Local(3),
                                                ),
                                                &aml::And::new(
                                                    &aml::Local(7),
                                                    &aml::Local(6),
                                                    &7_usize,
                                                ),
                                                &aml::If::new(
                                                    &aml::NotEqual::new(&aml::Local(7), &aml::ZERO),
                                                    vec![&aml::Add::new(
                                                        &aml::Local(6),
                                                        &aml::Local(6),
                                                        &8_usize,
                                                    )],
                                                ),
                                                &aml::Subtract::new(
                                                    &aml::Local(6),
                                                    &aml::Local(6),
                                                    &aml::Local(7),
                                                ),
                                                &aml::Add::new(
                                                    &aml::Local(5),
                                                    &aml::Local(5),
                                                    &aml::Local(6),
                                                ),
                                            ],
                                        ),
                                        &aml::Else::new(vec![&aml::If::new(
                                            &aml::Equal::new(&aml::Local(4), &3_usize),
                                            vec![
                                                &aml::CreateField::new(
                                                    &aml::Name::new_field_name("OBDT"),
                                                    &aml::Local(0),
                                                    &aml::Multiply::new(
                                                        &aml::ZERO,
                                                        &aml::Local(5),
                                                        &8_usize,
                                                    ),
                                                    &aml::Multiply::new(
                                                        &aml::ZERO,
                                                        &aml::Local(6),
                                                        &8_usize,
                                                    ),
                                                ),
                                                &aml::Store::new(
                                                    &aml::Name::new_field_name("OBDT"),
                                                    &aml::Local(3),
                                                ),
                                                &aml::And::new(
                                                    &aml::Local(7),
                                                    &aml::Local(6),
                                                    &7_usize,
                                                ),
                                                &aml::If::new(
                                                    &aml::NotEqual::new(&aml::Local(7), &aml::ZERO),
                                                    vec![&aml::Add::new(
                                                        &aml::Local(6),
                                                        &aml::Local(6),
                                                        &8_usize,
                                                    )],
                                                ),
                                                &aml::Subtract::new(
                                                    &aml::Local(6),
                                                    &aml::Local(6),
                                                    &aml::Local(7),
                                                ),
                                                &aml::Add::new(
                                                    &aml::Local(5),
                                                    &aml::Local(5),
                                                    &aml::Local(6),
                                                ),
                                            ],
                                        )]),
                                    ]),
                                    &aml::Add::new(&aml::Local(2), &aml::Local(2), &aml::ONE),
                                ],
                            ),
                        ],
                    ),
                    &aml::Else::new(vec![&aml::Return::new(&aml::ZERO)]),
                ]),
                &aml::Store::new(&aml::Name::new_field_name("DSM3"), &aml::Local(0)),
                &aml::Store::new(&aml::Name::new_field_name("PDSM"), &aml::ZERO),
                &aml::Store::new(
                    &aml::Local(0),
                    &aml::ToInteger::new(&aml::ZERO, &aml::Name::new_field_name("RTTP")),
                ),
                &aml::If::new(
                    &aml::Equal::new(&aml::Local(0), &1_usize),
                    vec![&aml::Return::new(&aml::ToInteger::new(
                        &aml::ZERO,
                        &aml::Name::new_field_name("RTDT"),
                    ))],
                ),
                &aml::Else::new(vec![
                    &aml::If::new(
                        &aml::Equal::new(&aml::Local(0), &2_usize),
                        vec![&aml::Return::new(&aml::ToString::new(
                            &aml::ZERO,
                            &aml::Name::new_field_name("RTDT"),
                            &aml::ONES,
                        ))],
                    ),
                    &aml::Else::new(vec![
                        &aml::If::new(
                            &aml::Equal::new(&aml::Local(0), &3_usize),
                            vec![&aml::Return::new(&aml::Mid::new(
                                &aml::Name::new_field_name("RTDT"),
                                &0_usize,
                                &aml::ToInteger::new(
                                    &aml::ZERO,
                                    &aml::Name::new_field_name("RTSZ"),
                                ),
                                &aml::ZERO,
                            ))],
                        ),
                        &aml::Else::new(vec![
                            &aml::If::new(
                                &aml::Equal::new(&aml::Local(0), &4_usize),
                                vec![
                                    &aml::Store::new(&aml::Local(0), &aml::ZERO),
                                    &aml::Store::new(
                                        &aml::Local(1),
                                        &aml::ToInteger::new(
                                            &aml::ZERO,
                                            &aml::Name::new_field_name("RTSZ"),
                                        ),
                                    ),
                                    &aml::Store::new(
                                        &aml::Local(2),
                                        &aml::VarPackageTerm::new(&aml::Local(1)),
                                    ),
                                    &aml::Store::new(&aml::Local(3), &aml::ZERO),
                                    &aml::While::new(
                                        &aml::LessThan::new(&aml::Local(0), &aml::Local(1)),
                                        vec![
                                            &aml::Store::new(
                                                &aml::Local(4),
                                                &aml::ToInteger::new(
                                                    &aml::ZERO,
                                                    &aml::Mid::new(
                                                        &aml::Name::new_field_name("RTDT"),
                                                        &aml::Local(3),
                                                        &4_usize,
                                                        &aml::ZERO,
                                                    ),
                                                ),
                                            ),
                                            &aml::Add::new(
                                                &aml::Local(3),
                                                &aml::Local(3),
                                                &4_usize,
                                            ),
                                            &aml::Store::new(
                                                &aml::Local(5),
                                                &aml::ToInteger::new(
                                                    &aml::ZERO,
                                                    &aml::Mid::new(
                                                        &aml::Name::new_field_name("RTDT"),
                                                        &aml::Local(3),
                                                        &4_usize,
                                                        &aml::ZERO,
                                                    ),
                                                ),
                                            ),
                                            &aml::Add::new(
                                                &aml::Local(3),
                                                &aml::Local(3),
                                                &4_usize,
                                            ),
                                            &aml::Store::new(
                                                &aml::Local(6),
                                                &aml::Mid::new(
                                                    &aml::Name::new_field_name("RTDT"),
                                                    &aml::Local(3),
                                                    &aml::Local(5),
                                                    &aml::ZERO,
                                                ),
                                            ),
                                            &aml::Add::new(
                                                &aml::Local(3),
                                                &aml::Local(3),
                                                &aml::Local(5),
                                            ),
                                            &aml::If::new(
                                                &aml::Equal::new(&aml::Local(4), &1_usize),
                                                vec![&aml::Store::new(
                                                    &aml::Local(6),
                                                    &aml::ToInteger::new(
                                                        &aml::ZERO,
                                                        &aml::Local(6),
                                                    ),
                                                )],
                                            ),
                                            &aml::Else::new(vec![&aml::If::new(
                                                &aml::Equal::new(&aml::Local(4), &2_usize),
                                                vec![&aml::Store::new(
                                                    &aml::Local(6),
                                                    &aml::ToString::new(
                                                        &aml::ZERO,
                                                        &aml::Local(6),
                                                        &aml::ONES,
                                                    ),
                                                )],
                                            )]),
                                            &aml::Store::new(
                                                &aml::Index::new(
                                                    &aml::ZERO,
                                                    &aml::Local(2),
                                                    &aml::Local(0),
                                                ),
                                                &aml::Local(6),
                                            ),
                                            &aml::Add::new(
                                                &aml::Local(0),
                                                &aml::Local(0),
                                                &aml::ONE,
                                            ),
                                        ],
                                    ),
                                    &aml::Return::new(&aml::Local(2)),
                                ],
                            ),
                            &aml::Else::new(vec![&aml::Return::new(&aml::ZERO)]),
                        ]),
                    ]),
                ]),
            ],
        )
        .to_aml_bytes(aml);
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
