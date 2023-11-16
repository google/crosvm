// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#![deny(missing_docs)]
//! A SCSI controller has SCSI target(s), a SCSI target has logical unit(s).
//! crosvm currently supports only one logical unit in a target (LUN0), therefore a SCSI target is
//! tied to a logical unit and a disk image belongs to a logical unit in crosvm.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::io;
use std::io::Read;
use std::io::Write;
use std::rc::Rc;

use anyhow::Context;
use base::error;
use base::warn;
use base::Event;
use base::WorkerThread;
use cros_async::EventAsync;
use cros_async::Executor;
use cros_async::ExecutorKind;
use disk::AsyncDisk;
use disk::DiskFile;
use futures::pin_mut;
use futures::stream::FuturesUnordered;
use futures::FutureExt;
use futures::StreamExt;
use remain::sorted;
use thiserror::Error as ThisError;
use virtio_sys::virtio_scsi::virtio_scsi_config;
use virtio_sys::virtio_scsi::virtio_scsi_ctrl_an_resp;
use virtio_sys::virtio_scsi::virtio_scsi_ctrl_tmf_req;
use virtio_sys::virtio_scsi::virtio_scsi_ctrl_tmf_resp;
use virtio_sys::virtio_scsi::virtio_scsi_event;
use virtio_sys::virtio_scsi::VIRTIO_SCSI_CDB_DEFAULT_SIZE;
use virtio_sys::virtio_scsi::VIRTIO_SCSI_SENSE_DEFAULT_SIZE;
use virtio_sys::virtio_scsi::VIRTIO_SCSI_S_BAD_TARGET;
use virtio_sys::virtio_scsi::VIRTIO_SCSI_S_FUNCTION_REJECTED;
use virtio_sys::virtio_scsi::VIRTIO_SCSI_S_FUNCTION_SUCCEEDED;
use virtio_sys::virtio_scsi::VIRTIO_SCSI_S_INCORRECT_LUN;
use virtio_sys::virtio_scsi::VIRTIO_SCSI_S_OK;
use virtio_sys::virtio_scsi::VIRTIO_SCSI_T_AN_QUERY;
use virtio_sys::virtio_scsi::VIRTIO_SCSI_T_AN_SUBSCRIBE;
use virtio_sys::virtio_scsi::VIRTIO_SCSI_T_TMF;
use virtio_sys::virtio_scsi::VIRTIO_SCSI_T_TMF_I_T_NEXUS_RESET;
use virtio_sys::virtio_scsi::VIRTIO_SCSI_T_TMF_LOGICAL_UNIT_RESET;
use vm_memory::GuestMemory;
use zerocopy::AsBytes;
use zerocopy::FromBytes;
use zerocopy::FromZeroes;

use crate::virtio::async_utils;
use crate::virtio::block::sys::get_seg_max;
use crate::virtio::copy_config;
use crate::virtio::scsi::commands::Command;
use crate::virtio::scsi::constants::CHECK_CONDITION;
use crate::virtio::scsi::constants::GOOD;
use crate::virtio::scsi::constants::ILLEGAL_REQUEST;
use crate::virtio::scsi::constants::MEDIUM_ERROR;
use crate::virtio::DescriptorChain;
use crate::virtio::DeviceType as VirtioDeviceType;
use crate::virtio::Interrupt;
use crate::virtio::Queue;
use crate::virtio::Reader;
use crate::virtio::VirtioDevice;
use crate::virtio::Writer;

// The following values reflects the virtio v1.2 spec:
// <https://docs.oasis-open.org/virtio/virtio/v1.2/csd01/virtio-v1.2-csd01.html#x1-3470004>

// Should have one controlq, one eventq, and at least one request queue.
const MIN_NUM_QUEUES: usize = 3;
// The number of queues exposed by the device.
// First crosvm pass this value through `VirtioDevice::read_config`, and then the driver determines
// the number of queues which does not exceed the passed value. The determined value eventually
// shows as the length of `queues` in `VirtioDevice::activate`.
const MAX_NUM_QUEUES: usize = 16;
// Max channel should be 0.
const DEFAULT_MAX_CHANNEL: u16 = 0;
// Max target should be less than or equal to 255.
const DEFAULT_MAX_TARGET: u16 = 255;
// Max lun should be less than or equal to 16383
const DEFAULT_MAX_LUN: u32 = 16383;

const DEFAULT_QUEUE_SIZE: u16 = 256;

// The maximum number of linked commands.
const MAX_CMD_PER_LUN: u32 = 128;
// We do not set a limit on the transfer size.
const MAX_SECTORS: u32 = u32::MAX;

// The length of sense data in fixed format. Details are in SPC-3 t10 revision 23:
// <https://www.t10.org/cgi-bin/ac.pl?t=f&f=spc3r23.pdf>
const FIXED_FORMAT_SENSE_SIZE: u32 = 18;

#[repr(C, packed)]
#[derive(Debug, Default, Copy, Clone, FromZeroes, FromBytes, AsBytes)]
struct VirtioScsiCmdReqHeader {
    lun: [u8; 8usize],
    tag: u64,
    task_attr: u8,
    prio: u8,
    crn: u8,
}

#[repr(C, packed)]
#[derive(Debug, Default, Copy, Clone, FromZeroes, FromBytes, AsBytes)]
struct VirtioScsiCmdRespHeader {
    sense_len: u32,
    resid: u32,
    status_qualifier: u16,
    status: u8,
    response: u8,
}

impl VirtioScsiCmdRespHeader {
    fn ok() -> Self {
        VirtioScsiCmdRespHeader {
            sense_len: 0,
            resid: 0,
            status_qualifier: 0,
            status: GOOD,
            response: VIRTIO_SCSI_S_OK as u8,
        }
    }
}

/// Errors that happen while handling scsi commands.
#[sorted]
#[derive(ThisError, Debug)]
pub enum ExecuteError {
    #[error("invalid cdb field")]
    InvalidField,
    #[error("invalid parameter length")]
    InvalidParamLen,
    #[error("{length} bytes from sector {sector} exceeds end of this device {max_lba}")]
    LbaOutOfRange {
        length: usize,
        sector: u64,
        max_lba: u64,
    },
    #[error("failed to read message: {0}")]
    Read(io::Error),
    #[error("failed to read command from cdb")]
    ReadCommand,
    #[error("io error {resid} bytes remained to be read: {desc_error}")]
    ReadIo {
        resid: usize,
        desc_error: disk::Error,
    },
    #[error("writing to a read only device")]
    ReadOnly,
    #[error("saving parameters not supported")]
    SavingParamNotSupported,
    #[error("synchronization error")]
    SynchronizationError,
    #[error("unsupported scsi command: {0}")]
    Unsupported(u8),
    #[error("failed to write message: {0}")]
    Write(io::Error),
    #[error("io error {resid} bytes remained to be written: {desc_error}")]
    WriteIo {
        resid: usize,
        desc_error: disk::Error,
    },
}

impl ExecuteError {
    // converts ExecuteError to (VirtioScsiCmdReqHeader, Sense)
    fn as_resp(&self) -> (VirtioScsiCmdRespHeader, Sense) {
        let resp = VirtioScsiCmdRespHeader::ok();
        // The asc and ascq assignments are taken from the t10 SPC spec.
        // cf) Table 28 of <https://www.t10.org/cgi-bin/ac.pl?t=f&f=spc3r23.pdf>
        let sense = match self {
            Self::Read(_) | Self::ReadCommand => {
                // UNRECOVERED READ ERROR
                Sense {
                    key: MEDIUM_ERROR,
                    asc: 0x11,
                    ascq: 0x00,
                }
            }
            Self::Write(_) => {
                // WRITE ERROR
                Sense {
                    key: MEDIUM_ERROR,
                    asc: 0x0c,
                    ascq: 0x00,
                }
            }
            Self::InvalidField => {
                // INVALID FIELD IN CDB
                Sense {
                    key: ILLEGAL_REQUEST,
                    asc: 0x24,
                    ascq: 0x00,
                }
            }
            Self::InvalidParamLen => {
                // INVALID PARAMETER LENGTH
                Sense {
                    key: ILLEGAL_REQUEST,
                    asc: 0x1a,
                    ascq: 0x00,
                }
            }
            Self::Unsupported(_) => {
                // INVALID COMMAND OPERATION CODE
                Sense {
                    key: ILLEGAL_REQUEST,
                    asc: 0x20,
                    ascq: 0x00,
                }
            }
            Self::ReadOnly | Self::LbaOutOfRange { .. } => {
                // LOGICAL BLOCK ADDRESS OUT OF RANGE
                Sense {
                    key: ILLEGAL_REQUEST,
                    asc: 0x21,
                    ascq: 0x00,
                }
            }
            Self::SavingParamNotSupported => Sense {
                // SAVING PARAMETERS NOT SUPPORTED
                key: ILLEGAL_REQUEST,
                asc: 0x39,
                ascq: 0x00,
            },
            Self::SynchronizationError => Sense {
                // SYNCHRONIZATION ERROR
                key: MEDIUM_ERROR,
                asc: 0x16,
                ascq: 0x00,
            },
            // Ignore these errors.
            Self::ReadIo { resid, desc_error } | Self::WriteIo { resid, desc_error } => {
                warn!("error while performing I/O {}", desc_error);
                let hdr = VirtioScsiCmdRespHeader {
                    resid: (*resid).try_into().unwrap_or(u32::MAX).to_be(),
                    ..resp
                };
                return (hdr, Sense::default());
            }
        };
        (
            VirtioScsiCmdRespHeader {
                sense_len: FIXED_FORMAT_SENSE_SIZE,
                status: CHECK_CONDITION,
                ..resp
            },
            sense,
        )
    }
}

/// Sense code representation
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct Sense {
    /// Provides generic information describing an error or exception condition.
    pub key: u8,
    /// Additional Sense Code.
    /// Indicates further information related to the error or exception reported in the key field.
    pub asc: u8,
    /// Additional Sense Code Qualifier.
    /// Indicates further detailed information related to the additional sense code.
    pub ascq: u8,
}

impl Sense {
    fn write_to(&self, writer: &mut Writer, sense_size: u32) -> Result<(), ExecuteError> {
        let mut sense_data = [0u8; FIXED_FORMAT_SENSE_SIZE as usize];
        // Fixed format sense data has response code:
        // 1) 0x70 for current errors
        // 2) 0x71 for deferred errors
        sense_data[0] = 0x70;
        // sense_data[1]: Obsolete
        // Sense key
        sense_data[2] = self.key;
        // sense_data[3..7]: Information field, which we do not support.
        // Additional length. The data is 18 bytes, and this byte is 8th.
        sense_data[7] = 10;
        // sense_data[8..12]: Command specific information, which we do not support.
        // Additional sense code
        sense_data[12] = self.asc;
        // Additional sense code qualifier
        sense_data[13] = self.ascq;
        // sense_data[14]: Field replaceable unit code, which we do not support.
        // sense_data[15..18]: Field replaceable unit code, which we do not support.
        writer.write_all(&sense_data).map_err(ExecuteError::Write)?;
        writer.consume_bytes(sense_size as usize - sense_data.len());
        Ok(())
    }
}

/// Describes each SCSI logical unit.
struct LogicalUnit {
    /// The maximum logical block address of the target device.
    max_lba: u64,
    /// Block size of the target device.
    block_size: u32,
    read_only: bool,
    // Represents the image on disk.
    disk_image: Box<dyn DiskFile>,
}

impl LogicalUnit {
    fn make_async(self, ex: &Executor) -> anyhow::Result<AsyncLogicalUnit> {
        let disk_image = self
            .disk_image
            .to_async_disk(ex)
            .context("Failed to create async disk")?;
        Ok(AsyncLogicalUnit {
            max_lba: self.max_lba,
            block_size: self.block_size,
            read_only: self.read_only,
            disk_image,
        })
    }
}

/// A logical unit with an AsyncDisk as the disk.
pub struct AsyncLogicalUnit {
    pub max_lba: u64,
    pub block_size: u32,
    pub read_only: bool,
    // Represents the async image on disk.
    pub disk_image: Box<dyn AsyncDisk>,
}

type TargetId = u8;
struct Targets(BTreeMap<TargetId, LogicalUnit>);

impl Targets {
    fn try_clone(&self) -> io::Result<Self> {
        let logical_units = self
            .0
            .iter()
            .map(|(id, logical_unit)| {
                let disk_image = logical_unit.disk_image.try_clone()?;
                Ok((
                    *id,
                    LogicalUnit {
                        disk_image,
                        max_lba: logical_unit.max_lba,
                        block_size: logical_unit.block_size,
                        read_only: logical_unit.read_only,
                    },
                ))
            })
            .collect::<io::Result<_>>()?;
        Ok(Self(logical_units))
    }

    fn target_ids(&self) -> BTreeSet<TargetId> {
        self.0.keys().cloned().collect()
    }
}

/// Configuration of each SCSI device.
pub struct DiskConfig {
    /// The disk file of the device.
    pub file: Box<dyn DiskFile>,
    /// The block size of the SCSI disk.
    pub block_size: u32,
    /// Indicates whether the SCSI disk is read only.
    pub read_only: bool,
}

/// Vitio device for exposing SCSI command operations on a host file.
pub struct Controller {
    // Bitmap of virtio-scsi feature bits.
    avail_features: u64,
    // Sizes for the virtqueue.
    queue_sizes: Vec<u16>,
    // The maximum number of segments that can be in a command.
    seg_max: u32,
    // The size of the sense data.
    sense_size: u32,
    // The byte size of the CDB that the driver will write.
    cdb_size: u32,
    executor_kind: ExecutorKind,
    worker_threads: Vec<WorkerThread<()>>,
    // Stores target devices by its target id. Currently we only support bus id 0.
    targets: Option<Targets>,
    // Whether the devices handles requests in multiple request queues.
    // If true, each virtqueue will be handled in a separate worker thread.
    multi_queue: bool,
}

impl Controller {
    /// Creates a virtio-scsi device.
    pub fn new(base_features: u64, disks: Vec<DiskConfig>) -> anyhow::Result<Self> {
        let multi_queue = disks.iter().all(|disk| disk.file.try_clone().is_ok());
        let num_queues = if multi_queue {
            MAX_NUM_QUEUES
        } else {
            MIN_NUM_QUEUES
        };
        let logical_units = disks
            .into_iter()
            .enumerate()
            .map(|(i, disk)| {
                let max_lba = disk
                    .file
                    .get_len()
                    .context("Failed to get the length of the disk image")?
                    / disk.block_size as u64;
                let target = LogicalUnit {
                    max_lba,
                    block_size: disk.block_size,
                    read_only: disk.read_only,
                    disk_image: disk.file,
                };
                Ok((i as TargetId, target))
            })
            .collect::<anyhow::Result<_>>()?;
        // b/300560198: Support feature bits in virtio-scsi.
        Ok(Self {
            avail_features: base_features,
            queue_sizes: vec![DEFAULT_QUEUE_SIZE; num_queues],
            seg_max: get_seg_max(DEFAULT_QUEUE_SIZE),
            sense_size: VIRTIO_SCSI_SENSE_DEFAULT_SIZE,
            cdb_size: VIRTIO_SCSI_CDB_DEFAULT_SIZE,
            executor_kind: ExecutorKind::default(),
            worker_threads: vec![],
            targets: Some(Targets(logical_units)),
            multi_queue,
        })
    }

    fn build_config_space(&self) -> virtio_scsi_config {
        virtio_scsi_config {
            // num_queues is the number of request queues only so we subtract 2 for the control
            // queue and the event queue.
            num_queues: self.queue_sizes.len() as u32 - 2,
            seg_max: self.seg_max,
            max_sectors: MAX_SECTORS,
            cmd_per_lun: MAX_CMD_PER_LUN,
            event_info_size: std::mem::size_of::<virtio_scsi_event>() as u32,
            sense_size: self.sense_size,
            cdb_size: self.cdb_size,
            max_channel: DEFAULT_MAX_CHANNEL,
            max_target: DEFAULT_MAX_TARGET,
            max_lun: DEFAULT_MAX_LUN,
        }
    }

    // Executes a request in the controlq.
    fn execute_control(
        reader: &mut Reader,
        writer: &mut Writer,
        target_ids: &BTreeSet<TargetId>,
    ) -> Result<(), ExecuteError> {
        let typ = reader.peek_obj::<u32>().map_err(ExecuteError::Read)?;
        match typ {
            VIRTIO_SCSI_T_TMF => {
                let tmf = reader
                    .read_obj::<virtio_scsi_ctrl_tmf_req>()
                    .map_err(ExecuteError::Read)?;
                let resp = Self::execute_tmf(tmf, target_ids);
                writer.write_obj(resp).map_err(ExecuteError::Write)?;
                Ok(())
            }
            VIRTIO_SCSI_T_AN_QUERY | VIRTIO_SCSI_T_AN_SUBSCRIBE => {
                // We do not support any asynchronous notification queries hence `event_actual`
                // will be 0.
                let resp = virtio_scsi_ctrl_an_resp {
                    event_actual: 0,
                    response: VIRTIO_SCSI_S_OK as u8,
                };
                writer.write_obj(resp).map_err(ExecuteError::Write)?;
                Ok(())
            }
            _ => {
                error!("invalid type of a control request: {typ}");
                Err(ExecuteError::InvalidField)
            }
        }
    }

    // Executes a TMF (task management function) request.
    fn execute_tmf(
        tmf: virtio_scsi_ctrl_tmf_req,
        target_ids: &BTreeSet<TargetId>,
    ) -> virtio_scsi_ctrl_tmf_resp {
        match tmf.subtype {
            VIRTIO_SCSI_T_TMF_LOGICAL_UNIT_RESET | VIRTIO_SCSI_T_TMF_I_T_NEXUS_RESET => {
                // We only have LUN0.
                let lun = tmf.lun;
                let target_id = lun[1];
                let response = if target_ids.contains(&target_id) {
                    let is_lun0 = u16::from_be_bytes([lun[2], lun[3]]) & 0x3fff == 0;
                    if is_lun0 {
                        VIRTIO_SCSI_S_FUNCTION_SUCCEEDED as u8
                    } else {
                        VIRTIO_SCSI_S_INCORRECT_LUN as u8
                    }
                } else {
                    VIRTIO_SCSI_S_BAD_TARGET as u8
                };
                virtio_scsi_ctrl_tmf_resp { response }
            }
            subtype => {
                error!("TMF request {subtype} is not supported");
                virtio_scsi_ctrl_tmf_resp {
                    response: VIRTIO_SCSI_S_FUNCTION_REJECTED as u8,
                }
            }
        }
    }

    async fn execute_request(
        reader: &mut Reader,
        resp_writer: &mut Writer,
        data_writer: &mut Writer,
        targets: &BTreeMap<TargetId, AsyncLogicalUnit>,
        sense_size: u32,
        cdb_size: u32,
    ) -> Result<(), ExecuteError> {
        let req_header = reader
            .read_obj::<VirtioScsiCmdReqHeader>()
            .map_err(ExecuteError::Read)?;
        match Self::get_logical_unit(req_header.lun, targets) {
            Some(target) => {
                let mut cdb = vec![0; cdb_size as usize];
                reader.read_exact(&mut cdb).map_err(ExecuteError::Read)?;
                let command = Command::new(&cdb)?;
                match command.execute(reader, data_writer, target).await {
                    Ok(()) => {
                        let hdr = VirtioScsiCmdRespHeader {
                            sense_len: 0,
                            resid: 0,
                            status_qualifier: 0,
                            status: GOOD,
                            response: VIRTIO_SCSI_S_OK as u8,
                        };
                        resp_writer.write_obj(hdr).map_err(ExecuteError::Write)?;
                        resp_writer.consume_bytes(sense_size as usize);
                        Ok(())
                    }
                    Err(err) => {
                        error!("error while executing a scsi request: {err}");
                        let (hdr, sense) = err.as_resp();
                        resp_writer.write_obj(hdr).map_err(ExecuteError::Write)?;
                        sense.write_to(resp_writer, sense_size)
                    }
                }
            }
            None => {
                let hdr = VirtioScsiCmdRespHeader {
                    response: VIRTIO_SCSI_S_BAD_TARGET as u8,
                    ..Default::default()
                };
                resp_writer.write_obj(hdr).map_err(ExecuteError::Write)?;
                resp_writer.consume_bytes(sense_size as usize);
                Ok(())
            }
        }
    }

    fn get_logical_unit(
        lun: [u8; 8],
        targets: &BTreeMap<TargetId, AsyncLogicalUnit>,
    ) -> Option<&AsyncLogicalUnit> {
        // First byte should be 1.
        if lun[0] != 1 {
            return None;
        }
        // General search strategy for scsi devices is as follows:
        // 1) Look for a device which has the same bus id and lun indicated by the given lun. If
        //    there is one, that is the target device.
        // 2) If we cannot find such device, then we return the first device that has the same bus
        //    id.
        // Since we only support one LUN per target, we only need to use the target id.
        let target_id = lun[1];
        targets.get(&target_id)
    }
}

impl VirtioDevice for Controller {
    fn keep_rds(&self) -> Vec<base::RawDescriptor> {
        match &self.targets {
            Some(targets) => targets
                .0
                .values()
                .flat_map(|t| t.disk_image.as_raw_descriptors())
                .collect(),
            None => vec![],
        }
    }

    fn features(&self) -> u64 {
        self.avail_features
    }

    fn device_type(&self) -> VirtioDeviceType {
        VirtioDeviceType::Scsi
    }

    fn queue_max_sizes(&self) -> &[u16] {
        &self.queue_sizes
    }

    fn read_config(&self, offset: u64, data: &mut [u8]) {
        let config_space = self.build_config_space();
        copy_config(data, 0, config_space.as_bytes(), offset);
    }

    fn write_config(&mut self, offset: u64, data: &[u8]) {
        let mut config = [0; std::mem::size_of::<virtio_scsi_config>()];
        copy_config(&mut config, offset, data, 0);
        let config = match virtio_scsi_config::read_from(&config) {
            Some(cfg) => cfg,
            None => {
                warn!("failed to parse virtio_scsi_config");
                return;
            }
        };

        let mut updated = [0; std::mem::size_of::<virtio_scsi_config>()];
        updated[offset as usize..offset as usize + data.len()].fill(1);
        let updated = match virtio_scsi_config::read_from(&updated) {
            Some(cfg) => cfg,
            None => {
                warn!("failed to parse virtio_scsi_config");
                return;
            }
        };

        if updated.sense_size != 0 {
            self.sense_size = config.sense_size;
        }
        if updated.cdb_size != 0 {
            self.cdb_size = config.cdb_size;
        }
    }

    fn activate(
        &mut self,
        _mem: GuestMemory,
        interrupt: Interrupt,
        mut queues: BTreeMap<usize, Queue>,
    ) -> anyhow::Result<()> {
        let executor_kind = self.executor_kind;
        // 0th virtqueue is the controlq.
        let controlq = queues.remove(&0).context("controlq should be present")?;
        // 1st virtqueue is the eventq.
        // We do not send any events through eventq.
        let _eventq = queues.remove(&1).context("eventq should be present")?;
        let targets = self.targets.take().context("failed to take SCSI targets")?;
        let target_ids = targets.target_ids();
        let sense_size = self.sense_size;
        let cdb_size = self.cdb_size;
        // The rest of the queues are request queues.
        let request_queues = if self.multi_queue {
            queues
                .into_values()
                .map(|queue| {
                    let targets = targets
                        .try_clone()
                        .context("Failed to clone a disk image")?;
                    Ok((queue, targets))
                })
                .collect::<anyhow::Result<_>>()?
        } else {
            // Handle all virtio requests with one thread.
            vec![(
                queues
                    .remove(&2)
                    .context("request queue should be present")?,
                targets,
            )]
        };

        let intr = interrupt.clone();
        let worker_thread = WorkerThread::start("v_scsi_ctrlq", move |kill_evt| {
            let ex =
                Executor::with_executor_kind(executor_kind).expect("Failed to create an executor");
            if let Err(err) = ex
                .run_until(run_worker(
                    &ex,
                    intr,
                    controlq,
                    kill_evt,
                    QueueType::Control { target_ids },
                    sense_size,
                    cdb_size,
                ))
                .expect("run_until failed")
            {
                error!("run_worker failed: {err}");
            }
        });
        self.worker_threads.push(worker_thread);

        for (i, (queue, targets)) in request_queues.into_iter().enumerate() {
            let interrupt = interrupt.clone();
            let worker_thread =
                WorkerThread::start(format!("v_scsi_req_{}", i + 2), move |kill_evt| {
                    let ex = Executor::with_executor_kind(executor_kind)
                        .expect("Failed to create an executor");
                    let async_logical_unit = targets
                        .0
                        .into_iter()
                        .map(|(idx, unit)| match unit.make_async(&ex) {
                            Ok(async_unit) => (idx, async_unit),
                            Err(err) => panic!("{err}"),
                        })
                        .collect();
                    if let Err(err) = ex
                        .run_until(run_worker(
                            &ex,
                            interrupt,
                            queue,
                            kill_evt,
                            QueueType::Request(async_logical_unit),
                            sense_size,
                            cdb_size,
                        ))
                        .expect("run_until failed")
                    {
                        error!("run_worker failed: {err}");
                    }
                });
            self.worker_threads.push(worker_thread);
        }
        Ok(())
    }
}

enum QueueType {
    Control { target_ids: BTreeSet<TargetId> },
    Request(BTreeMap<TargetId, AsyncLogicalUnit>),
}

async fn run_worker(
    ex: &Executor,
    interrupt: Interrupt,
    queue: Queue,
    kill_evt: Event,
    queue_type: QueueType,
    sense_size: u32,
    cdb_size: u32,
) -> anyhow::Result<()> {
    let kill = async_utils::await_and_exit(ex, kill_evt).fuse();
    pin_mut!(kill);

    let resample = async_utils::handle_irq_resample(ex, interrupt.clone()).fuse();
    pin_mut!(resample);

    let kick_evt = queue
        .event()
        .try_clone()
        .expect("Failed to clone queue event");
    let queue_handler = handle_queue(
        Rc::new(RefCell::new(queue)),
        EventAsync::new(kick_evt, ex).expect("Failed to create async event for queue"),
        interrupt,
        queue_type,
        sense_size,
        cdb_size,
    )
    .fuse();
    pin_mut!(queue_handler);

    futures::select! {
        _ = queue_handler => anyhow::bail!("queue handler exited unexpectedly"),
        r = resample => r.context("failed to resample an irq value"),
        r = kill => r.context("failed to wait on the kill event"),
    }
}

async fn handle_queue(
    queue: Rc<RefCell<Queue>>,
    evt: EventAsync,
    interrupt: Interrupt,
    queue_type: QueueType,
    sense_size: u32,
    cdb_size: u32,
) {
    let mut background_tasks = FuturesUnordered::new();
    let evt_future = evt.next_val().fuse();
    pin_mut!(evt_future);
    loop {
        futures::select! {
            _ = background_tasks.next() => continue,
            res = evt_future => {
                evt_future.set(evt.next_val().fuse());
                if let Err(e) = res {
                    error!("Failed to read the next queue event: {e}");
                    continue;
                }
            }
        }
        while let Some(chain) = queue.borrow_mut().pop() {
            background_tasks.push(process_one_chain(
                &queue,
                chain,
                &interrupt,
                &queue_type,
                sense_size,
                cdb_size,
            ));
        }
    }
}

async fn process_one_chain(
    queue: &RefCell<Queue>,
    mut avail_desc: DescriptorChain,
    interrupt: &Interrupt,
    queue_type: &QueueType,
    sense_size: u32,
    cdb_size: u32,
) {
    let _trace = cros_tracing::trace_event!(VirtioScsi, "process_one_chain");
    let len = process_one_request(&mut avail_desc, queue_type, sense_size, cdb_size).await;
    let mut queue = queue.borrow_mut();
    queue.add_used(avail_desc, len as u32);
    queue.trigger_interrupt(interrupt);
}

async fn process_one_request(
    avail_desc: &mut DescriptorChain,
    queue_type: &QueueType,
    sense_size: u32,
    cdb_size: u32,
) -> usize {
    let reader = &mut avail_desc.reader;
    let resp_writer = &mut avail_desc.writer;
    match queue_type {
        QueueType::Control { target_ids } => {
            if let Err(err) = Controller::execute_control(reader, resp_writer, target_ids) {
                error!("failed to execute control request: {err}");
            }
            resp_writer.bytes_written()
        }
        QueueType::Request(async_targets) => {
            let mut data_writer = resp_writer
                .split_at(std::mem::size_of::<VirtioScsiCmdRespHeader>() + sense_size as usize);
            if let Err(err) = Controller::execute_request(
                reader,
                resp_writer,
                &mut data_writer,
                async_targets,
                sense_size,
                cdb_size,
            )
            .await
            {
                // If the write of the virtio_scsi_cmd_resp fails, there is nothing we can do to
                // inform the error to the guest driver (we usually propagate errors with sense
                // field, which is in the struct virtio_scsi_cmd_resp). The guest driver should
                // have at least sizeof(virtio_scsi_cmd_resp) bytes of device-writable part
                // regions. For now we simply emit an error message.
                let (hdr, sense) = err.as_resp();
                if let Err(e) = resp_writer.write_obj(hdr) {
                    error!("failed to write VirtioScsiCmdRespHeader: {e}");
                }
                if let Err(e) = sense.write_to(resp_writer, sense_size) {
                    error!("failed to write sense data: {e}");
                }
            }
            resp_writer.bytes_written() + data_writer.bytes_written()
        }
    }
}

#[cfg(test)]
mod tests {
    use std::fs::File;
    use std::mem::size_of;
    use std::mem::size_of_val;
    use std::rc::Rc;

    use cros_async::Executor;
    use disk::SingleFileDisk;
    use tempfile::tempfile;
    use virtio_sys::virtio_scsi::virtio_scsi_cmd_req;
    use virtio_sys::virtio_scsi::virtio_scsi_cmd_resp;
    use virtio_sys::virtio_scsi::VIRTIO_SCSI_S_OK;
    use vm_memory::GuestAddress;
    use vm_memory::GuestMemory;

    use crate::virtio::create_descriptor_chain;
    use crate::virtio::scsi::constants::READ_10;
    use crate::virtio::DescriptorType;

    use super::*;

    fn setup_disk(disk_size: u64) -> (File, Vec<u8>) {
        let mut file_content = vec![0; disk_size as usize];
        for i in 0..disk_size {
            file_content[i as usize] = (i % 10) as u8;
        }
        let mut f = tempfile().unwrap();
        f.set_len(disk_size).unwrap();
        f.write_all(file_content.as_slice()).unwrap();
        (f, file_content)
    }

    fn build_read_req_header(target_id: u8, start_lba: u8, xfer_blocks: u8) -> virtio_scsi_cmd_req {
        let mut cdb = [0; 32];
        cdb[0] = READ_10;
        cdb[5] = start_lba;
        cdb[8] = xfer_blocks;
        virtio_scsi_cmd_req {
            lun: [1, 0, 0, target_id, 0, 0, 0, 0],
            cdb,
            ..Default::default()
        }
    }

    fn setup_desciptor_chain(
        target_id: TargetId,
        start_lba: u8,
        xfer_blocks: u8,
        block_size: u32,
        mem: &Rc<GuestMemory>,
    ) -> DescriptorChain {
        let req_hdr = build_read_req_header(target_id, start_lba, xfer_blocks);
        let xfer_bytes = xfer_blocks as u32 * block_size;
        create_descriptor_chain(
            mem,
            GuestAddress(0x100),  // Place descriptor chain at 0x100.
            GuestAddress(0x1000), // Describe buffer at 0x1000.
            vec![
                // Request header
                (DescriptorType::Readable, size_of_val(&req_hdr) as u32),
                // Response header
                (
                    DescriptorType::Writable,
                    size_of::<virtio_scsi_cmd_resp>() as u32,
                ),
                (DescriptorType::Writable, xfer_bytes),
            ],
            0,
        )
        .expect("create_descriptor_chain failed")
    }

    fn read_blocks(
        ex: &Executor,
        file_disks: &[File],
        target_id: u8,
        start_lba: u8,
        xfer_blocks: u8,
        block_size: u32,
    ) -> (virtio_scsi_cmd_resp, Vec<u8>) {
        let xfer_bytes = xfer_blocks as u32 * block_size;
        let mem = Rc::new(
            GuestMemory::new(&[(GuestAddress(0u64), 4 * 1024 * 1024)])
                .expect("Creating guest memory failed."),
        );
        let req_hdr = build_read_req_header(target_id, start_lba, xfer_blocks);
        mem.write_obj_at_addr(req_hdr, GuestAddress(0x1000))
            .expect("writing req failed");

        let mut avail_desc = setup_desciptor_chain(target_id, 0, xfer_blocks, block_size, &mem);

        let targets = file_disks
            .iter()
            .enumerate()
            .map(|(i, file)| {
                let file = file.try_clone().unwrap();
                let disk_image = Box::new(SingleFileDisk::new(file, ex).unwrap());
                let logical_unit = AsyncLogicalUnit {
                    max_lba: 0x1000,
                    block_size,
                    read_only: false,
                    disk_image,
                };
                (i as TargetId, logical_unit)
            })
            .collect();
        ex.run_until(process_one_request(
            &mut avail_desc,
            &QueueType::Request(targets),
            VIRTIO_SCSI_SENSE_DEFAULT_SIZE,
            VIRTIO_SCSI_CDB_DEFAULT_SIZE,
        ))
        .expect("running executor failed");
        let resp_offset = GuestAddress((0x1000 + size_of::<virtio_scsi_cmd_resp>()) as u64);
        let resp = mem
            .read_obj_from_addr::<virtio_scsi_cmd_resp>(resp_offset)
            .unwrap();
        let dataout_offset = GuestAddress(
            (0x1000 + size_of::<virtio_scsi_cmd_req>() + size_of::<virtio_scsi_cmd_resp>()) as u64,
        );
        let dataout_slice = mem
            .get_slice_at_addr(dataout_offset, xfer_bytes as usize)
            .unwrap();
        let mut dataout = vec![0; xfer_bytes as usize];
        dataout_slice.copy_to(&mut dataout);
        (resp, dataout)
    }

    fn test_read_blocks(
        num_targets: usize,
        blocks: u8,
        start_lba: u8,
        xfer_blocks: u8,
        block_size: u32,
    ) {
        let ex = Executor::new().expect("creating an executor failed");
        let file_len = blocks as u64 * block_size as u64;
        let xfer_bytes = xfer_blocks as usize * block_size as usize;
        let start_off = start_lba as usize * block_size as usize;

        let (files, file_contents): (Vec<_>, Vec<_>) =
            (0..num_targets).map(|_| setup_disk(file_len)).unzip();
        for (target_id, file_content) in file_contents.iter().enumerate() {
            let (resp, dataout) = read_blocks(
                &ex,
                &files,
                target_id as TargetId,
                start_lba,
                xfer_blocks,
                block_size,
            );

            let sense_len = resp.sense_len;
            assert_eq!(sense_len, 0);
            assert_eq!(resp.status, VIRTIO_SCSI_S_OK as u8);
            assert_eq!(resp.response, GOOD);

            assert_eq!(&dataout, &file_content[start_off..(start_off + xfer_bytes)]);
        }
    }

    #[test]
    fn read_first_blocks() {
        // Read the first 3 blocks of a 8-block device.
        let blocks = 8u8;
        let start_lba = 0u8;
        let xfer_blocks = 3u8;

        test_read_blocks(1, blocks, start_lba, xfer_blocks, 64u32);
        test_read_blocks(1, blocks, start_lba, xfer_blocks, 128u32);
        test_read_blocks(1, blocks, start_lba, xfer_blocks, 512u32);
    }

    #[test]
    fn read_middle_blocks() {
        // Read 3 blocks from the 2nd block in the 8-block device.
        let blocks = 8u8;
        let start_lba = 1u8;
        let xfer_blocks = 3u8;

        test_read_blocks(1, blocks, start_lba, xfer_blocks, 64u32);
        test_read_blocks(1, blocks, start_lba, xfer_blocks, 128u32);
        test_read_blocks(1, blocks, start_lba, xfer_blocks, 512u32);
    }

    #[test]
    fn read_first_blocks_with_multiple_disks() {
        // Read the first 3 blocks of a 8-block device.
        let blocks = 8u8;
        let start_lba = 0u8;
        let xfer_blocks = 3u8;

        test_read_blocks(3, blocks, start_lba, xfer_blocks, 64u32);
        test_read_blocks(3, blocks, start_lba, xfer_blocks, 128u32);
        test_read_blocks(3, blocks, start_lba, xfer_blocks, 512u32);
    }

    #[test]
    fn read_middle_blocks_with_multiple_disks() {
        // Read 3 blocks from the 2nd block in the 8-block device.
        let blocks = 8u8;
        let start_lba = 1u8;
        let xfer_blocks = 3u8;

        test_read_blocks(3, blocks, start_lba, xfer_blocks, 64u32);
        test_read_blocks(3, blocks, start_lba, xfer_blocks, 128u32);
        test_read_blocks(3, blocks, start_lba, xfer_blocks, 512u32);
    }
}
