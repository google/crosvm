// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

/*
The struct must be named in non_camel and non_snake because we want to query the windows wmi
interface and conform to the windows naming convension.
*/
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

use std::collections::HashMap;
use std::error::Error;
use std::rc::Rc;

use base::warn;
use serde::de::DeserializeOwned;
use serde::Deserialize;
use wmi::query::FilterValue;
use wmi::COMLibrary;
use wmi::WMIConnection;

const VIDEO_CONTROLLER_AVAILABILITY_ENABLED: i64 = 3;

#[derive(Deserialize, Debug)]
pub struct Win32_Processor {
    pub Manufacturer: String,
    pub Name: String,
    pub NumberOfCores: u32,
    pub NumberOfLogicalProcessors: u32,
    pub ThreadCount: u32,
}

#[derive(Deserialize, Debug)]
pub struct Win32_VideoController {
    pub Name: String,
    // TODO(b/191406729): re-enable.
    // pub AdapterRAM: u64,
    pub DriverVersion: String,
    pub Availability: u16,
    pub Description: String,
}

#[derive(Deserialize, Debug)]
struct MSFT_Partition {
    DriveLetter: String,
}

#[derive(Deserialize, Debug)]
struct MSFT_Disk {
    __Path: String,
    UniqueId: String,
}

#[derive(Deserialize, Debug)]
struct MSFT_DiskToPartition {}

#[derive(Deserialize, Debug)]
struct MSFT_PhysicalDisk {
    FriendlyName: String,
    MediaType: u16,
    BusType: u16,
    Size: u64,
    UniqueId: String,
}

// Keep the formatting so that the debug output string matches the proto field
// values.
#[derive(Debug)]
pub enum MediaType {
    UNKNOWN,
    HDD,
    SSD,
    SCM,
}

impl From<u16> for MediaType {
    fn from(value: u16) -> Self {
        match value {
            3 => MediaType::HDD,
            4 => MediaType::SSD,
            5 => MediaType::SCM,
            _ => MediaType::UNKNOWN,
        }
    }
}

// Keep the formatting so that the debug output string matches the proto field
// values.
#[derive(Debug)]
pub enum BusType {
    UNKNOWN,
    SCSI,
    ATAPI,
    ATA,
    TYPE_1394,
    SSA,
    FIBRE_CHANNEL,
    USB,
    RAID,
    ISCSI,
    SAS,
    SATA,
    SD,
    MMC,
    FILE_BACKED_VIRTUAL,
    STORAGE_SPACES,
    NVME,
}

impl From<u16> for BusType {
    fn from(value: u16) -> Self {
        match value {
            1 => BusType::SCSI,
            2 => BusType::ATAPI,
            3 => BusType::ATA,
            4 => BusType::TYPE_1394,
            5 => BusType::SSA,
            6 => BusType::FIBRE_CHANNEL,
            7 => BusType::USB,
            8 => BusType::RAID,
            9 => BusType::ISCSI,
            10 => BusType::SAS,
            11 => BusType::SATA,
            12 => BusType::SD,
            13 => BusType::MMC,
            15 => BusType::FILE_BACKED_VIRTUAL,
            16 => BusType::STORAGE_SPACES,
            17 => BusType::NVME,
            _ => BusType::UNKNOWN,
        }
    }
}

// Friendly format for MSFT_PhysicalDisk.
// Also includes the cross-referenced partitions within the disk.
#[derive(Debug)]
pub struct PhysicalDisk {
    pub Name: String,
    pub MediaType: MediaType,
    pub BusType: BusType,
    pub Size: u64,
    pub DriveLetters: Vec<String>,
}

#[derive(Deserialize, Debug)]
pub struct Win32_PhysicalMemory {
    pub Capacity: u64,
    pub ConfiguredClockSpeed: u32,
    pub PartNumber: String,
}

#[derive(Clone, Deserialize, Debug)]
pub struct Win32_BaseBoard {
    pub Manufacturer: String,
    pub Product: String,
}

#[derive(Debug)]
pub struct WmiMetrics {
    pub cpus: Vec<Win32_Processor>,
    pub gpus: Vec<Win32_VideoController>,
    pub disks: Vec<PhysicalDisk>,
    pub mems: Vec<Win32_PhysicalMemory>,
    pub motherboard: Option<Win32_BaseBoard>,
}

pub fn get_wmi_metrics() -> Result<WmiMetrics, Box<dyn Error>> {
    let com_con = Rc::new(COMLibrary::new()?);
    let wmi_con = WMIConnection::new(Rc::clone(&com_con))?;

    // Fetch WMI data, including all entries.
    let cpus: Vec<Win32_Processor> = run_wmi_query(&wmi_con);
    let disks = get_disks(Rc::clone(&com_con))?;
    let mems: Vec<Win32_PhysicalMemory> = run_wmi_query(&wmi_con);
    let motherboard: Option<Win32_BaseBoard> = run_wmi_query(&wmi_con).into_iter().next();
    let gpus = get_gpus(&wmi_con);

    let wmi_metrics = WmiMetrics {
        cpus,
        gpus,
        disks,
        mems,
        motherboard,
    };

    Ok(wmi_metrics)
}

fn get_disks(com_con: Rc<COMLibrary>) -> Result<Vec<PhysicalDisk>, Box<dyn Error>> {
    // For MSFT_PhysicalDisk, we need to connect with storage namespace.
    let wmi_con = WMIConnection::with_namespace_path("Root\\Microsoft\\Windows\\Storage", com_con)?;
    // First we get all instances of following classes:
    // MSFT_Disk, MSFT_PhysicalDisk
    // We use the WMI associator query to find mapping for each:
    // MSFT_Disk -> MSFT_Partition (1:N)
    // Then, we find the mapping from each:
    // MSFT_Disk -> MSFT_PhysicalDisk (1:1)
    // Finally, we construct each PhysicalDisk structure by combining the
    // matched MSFT_PhysicalDisk and MSFT_Parition instances.
    let msft_disks: Vec<MSFT_Disk> = run_wmi_query(&wmi_con);
    let physical_disks: Vec<MSFT_PhysicalDisk> = run_wmi_query(&wmi_con);

    let mut disks = Vec::with_capacity(physical_disks.len());
    for msft_disk in msft_disks {
        let partitions =
            wmi_con.associators::<MSFT_Partition, MSFT_DiskToPartition>(&msft_disk.__Path)?;
        let physical_disk = physical_disks
            .iter()
            .find(|d| d.UniqueId == msft_disk.UniqueId)
            .ok_or("Could not find a matching MSFT_PhysicalDisk!")?;
        disks.push(PhysicalDisk {
            Name: physical_disk.FriendlyName.clone(),
            MediaType: physical_disk.MediaType.into(),
            BusType: physical_disk.BusType.into(),
            Size: physical_disk.Size,
            DriveLetters: partitions.into_iter().map(|p| p.DriveLetter).collect(),
        });
    }
    Ok(disks)
}

fn get_gpus(wmi_con: &WMIConnection) -> Vec<Win32_VideoController> {
    // TODO(b/191406729): Fix the query once the AdapterRAM can be correctly
    // queried.
    let mut filters = HashMap::new();
    filters.insert(
        "Availability".to_string(),
        FilterValue::Number(VIDEO_CONTROLLER_AVAILABILITY_ENABLED),
    );
    wmi_con
        .filtered_query(&filters)
        .map_err(|e| warn!("wmi query failed: {}", e))
        .unwrap_or_default()
}

fn run_wmi_query<T>(wmi_con: &WMIConnection) -> Vec<T>
where
    T: DeserializeOwned,
{
    wmi_con
        .query()
        .map_err(|e| warn!("wmi query failed: {}", e))
        .unwrap_or_default()
}
