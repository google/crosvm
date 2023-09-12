// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::io;
use std::io::Write;
use std::mem::size_of;
#[cfg(windows)]
use std::num::NonZeroU32;
use std::ops::Deref;
use std::rc::Rc;
use std::result;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;
use std::u32;

use anyhow::Context;
use base::debug;
use base::error;
use base::info;
use base::warn;
use base::AsRawDescriptor;
use base::Error as SysError;
use base::Event;
use base::RawDescriptor;
use base::Result as SysResult;
use base::Timer;
use base::Tube;
use base::TubeError;
use base::WorkerThread;
use cros_async::sync::RwLock as AsyncRwLock;
use cros_async::AsyncError;
use cros_async::AsyncTube;
use cros_async::EventAsync;
use cros_async::Executor;
use cros_async::ExecutorKind;
use cros_async::TimerAsync;
use data_model::Le16;
use data_model::Le32;
use data_model::Le64;
use disk::AsyncDisk;
use disk::DiskFile;
use futures::channel::mpsc;
use futures::channel::oneshot;
use futures::pin_mut;
use futures::stream::FuturesUnordered;
use futures::stream::StreamExt;
use futures::FutureExt;
use remain::sorted;
use sync::Mutex;
use thiserror::Error as ThisError;
use virtio_sys::virtio_config::VIRTIO_F_RING_PACKED;
use vm_control::DiskControlCommand;
use vm_control::DiskControlResult;
use vm_memory::GuestMemory;
use zerocopy::AsBytes;

use crate::virtio::async_utils;
use crate::virtio::block::sys::*;
use crate::virtio::block::DiskOption;
use crate::virtio::copy_config;
use crate::virtio::device_constants::block::virtio_blk_config;
use crate::virtio::device_constants::block::virtio_blk_discard_write_zeroes;
use crate::virtio::device_constants::block::virtio_blk_req_header;
use crate::virtio::device_constants::block::VIRTIO_BLK_DISCARD_WRITE_ZEROES_FLAG_UNMAP;
use crate::virtio::device_constants::block::VIRTIO_BLK_F_BLK_SIZE;
use crate::virtio::device_constants::block::VIRTIO_BLK_F_DISCARD;
use crate::virtio::device_constants::block::VIRTIO_BLK_F_FLUSH;
use crate::virtio::device_constants::block::VIRTIO_BLK_F_MQ;
use crate::virtio::device_constants::block::VIRTIO_BLK_F_RO;
use crate::virtio::device_constants::block::VIRTIO_BLK_F_SEG_MAX;
use crate::virtio::device_constants::block::VIRTIO_BLK_F_WRITE_ZEROES;
use crate::virtio::device_constants::block::VIRTIO_BLK_S_IOERR;
use crate::virtio::device_constants::block::VIRTIO_BLK_S_OK;
use crate::virtio::device_constants::block::VIRTIO_BLK_S_UNSUPP;
use crate::virtio::device_constants::block::VIRTIO_BLK_T_DISCARD;
use crate::virtio::device_constants::block::VIRTIO_BLK_T_FLUSH;
use crate::virtio::device_constants::block::VIRTIO_BLK_T_GET_ID;
use crate::virtio::device_constants::block::VIRTIO_BLK_T_IN;
use crate::virtio::device_constants::block::VIRTIO_BLK_T_OUT;
use crate::virtio::device_constants::block::VIRTIO_BLK_T_WRITE_ZEROES;
use crate::virtio::vhost::user::device::VhostBackendReqConnectionState;
use crate::virtio::DescriptorChain;
use crate::virtio::DeviceType;
use crate::virtio::Interrupt;
use crate::virtio::Queue;
use crate::virtio::Reader;
use crate::virtio::VirtioDevice;
use crate::virtio::Writer;

const DEFAULT_QUEUE_SIZE: u16 = 256;
pub const DEFAULT_NUM_QUEUES: u16 = 16;

const SECTOR_SHIFT: u8 = 9;
const SECTOR_SIZE: u64 = 0x01 << SECTOR_SHIFT;

const MAX_DISCARD_SECTORS: u32 = u32::MAX;
const MAX_WRITE_ZEROES_SECTORS: u32 = u32::MAX;
// Arbitrary limits for number of discard/write zeroes segments.
const MAX_DISCARD_SEG: u32 = 32;
const MAX_WRITE_ZEROES_SEG: u32 = 32;
// Hard-coded to 64 KiB (in 512-byte sectors) for now,
// but this should probably be based on cluster size for qcow.
const DISCARD_SECTOR_ALIGNMENT: u32 = 128;

#[sorted]
#[derive(ThisError, Debug)]
pub enum ExecuteError {
    #[error("failed to copy ID string: {0}")]
    CopyId(io::Error),
    #[error("failed to perform discard or write zeroes; sector={sector} num_sectors={num_sectors} flags={flags}; {ioerr:?}")]
    DiscardWriteZeroes {
        ioerr: Option<disk::Error>,
        sector: u64,
        num_sectors: u32,
        flags: u32,
    },
    #[error("failed to flush: {0}")]
    Flush(disk::Error),
    #[error("not enough space in descriptor chain to write status")]
    MissingStatus,
    #[error("out of range")]
    OutOfRange,
    #[error("failed to read message: {0}")]
    Read(io::Error),
    #[error("io error reading {length} bytes from sector {sector}: {desc_error}")]
    ReadIo {
        length: usize,
        sector: u64,
        desc_error: disk::Error,
    },
    #[error("read only; request_type={request_type}")]
    ReadOnly { request_type: u32 },
    #[error("failed to recieve command message: {0}")]
    ReceivingCommand(TubeError),
    #[error("failed to send command response: {0}")]
    SendingResponse(TubeError),
    #[error("couldn't reset the timer: {0}")]
    TimerReset(base::Error),
    #[error("unsupported ({0})")]
    Unsupported(u32),
    #[error("io error writing {length} bytes from sector {sector}: {desc_error}")]
    WriteIo {
        length: usize,
        sector: u64,
        desc_error: disk::Error,
    },
    #[error("failed to write request status: {0}")]
    WriteStatus(io::Error),
}

enum LogLevel {
    Debug,
    Error,
}

impl ExecuteError {
    fn status(&self) -> u8 {
        match self {
            ExecuteError::CopyId(_) => VIRTIO_BLK_S_IOERR,
            ExecuteError::DiscardWriteZeroes { .. } => VIRTIO_BLK_S_IOERR,
            ExecuteError::Flush(_) => VIRTIO_BLK_S_IOERR,
            ExecuteError::MissingStatus => VIRTIO_BLK_S_IOERR,
            ExecuteError::OutOfRange { .. } => VIRTIO_BLK_S_IOERR,
            ExecuteError::Read(_) => VIRTIO_BLK_S_IOERR,
            ExecuteError::ReadIo { .. } => VIRTIO_BLK_S_IOERR,
            ExecuteError::ReadOnly { .. } => VIRTIO_BLK_S_IOERR,
            ExecuteError::ReceivingCommand(_) => VIRTIO_BLK_S_IOERR,
            ExecuteError::SendingResponse(_) => VIRTIO_BLK_S_IOERR,
            ExecuteError::TimerReset(_) => VIRTIO_BLK_S_IOERR,
            ExecuteError::WriteIo { .. } => VIRTIO_BLK_S_IOERR,
            ExecuteError::WriteStatus(_) => VIRTIO_BLK_S_IOERR,
            ExecuteError::Unsupported(_) => VIRTIO_BLK_S_UNSUPP,
        }
    }

    fn log_level(&self) -> LogLevel {
        match self {
            // Since there is no feature bit for the guest to detect support for
            // VIRTIO_BLK_T_GET_ID, the driver has to try executing the request to see if it works.
            ExecuteError::Unsupported(VIRTIO_BLK_T_GET_ID) => LogLevel::Debug,
            // Log disk I/O errors at debug level to avoid flooding the logs.
            ExecuteError::ReadIo { .. }
            | ExecuteError::WriteIo { .. }
            | ExecuteError::Flush { .. }
            | ExecuteError::DiscardWriteZeroes { .. } => LogLevel::Debug,
            // Log all other failures as errors.
            _ => LogLevel::Error,
        }
    }
}

/// Errors that happen in block outside of executing a request.
/// This includes errors during resize and flush operations.
#[sorted]
#[derive(ThisError, Debug)]
pub enum ControlError {
    #[error("couldn't create an async resample event: {0}")]
    AsyncResampleCreate(AsyncError),
    #[error("couldn't clone the resample event: {0}")]
    CloneResampleEvent(base::Error),
    #[error("couldn't get a value from a timer for flushing: {0}")]
    FlushTimer(AsyncError),
    #[error("failed to fsync the disk: {0}")]
    FsyncDisk(disk::Error),
    #[error("couldn't read the resample event: {0}")]
    ReadResampleEvent(AsyncError),
}

/// Maximum length of the virtio-block ID string field.
pub const ID_LEN: usize = 20;

/// Virtio block device identifier.
/// This is an ASCII string terminated by a \0, unless all 20 bytes are used,
/// in which case the \0 terminator is omitted.
pub type BlockId = [u8; ID_LEN];

/// Tracks the state of an anynchronous disk.
pub struct DiskState {
    pub disk_image: Box<dyn AsyncDisk>,
    pub read_only: bool,
    pub sparse: bool,
    pub id: Option<BlockId>,
    /// A DiskState is owned by each worker's executor and cannot be shared by workers, thus
    /// `worker_shared_state` holds the state shared by workers in Arc.
    worker_shared_state: Arc<AsyncRwLock<WorkerSharedState>>,
}

/// Disk state which can be modified by other worker threads
struct WorkerSharedState {
    disk_size: Arc<AtomicU64>,
}

impl DiskState {
    /// Creates a `DiskState` with the given params.
    pub fn new(
        disk_image: Box<dyn AsyncDisk>,
        disk_size: Arc<AtomicU64>,
        read_only: bool,
        sparse: bool,
        id: Option<BlockId>,
    ) -> DiskState {
        DiskState {
            disk_image,
            read_only,
            sparse,
            id,
            worker_shared_state: Arc::new(AsyncRwLock::new(WorkerSharedState { disk_size })),
        }
    }
}

async fn process_one_request(
    avail_desc: &mut DescriptorChain,
    disk_state: &AsyncRwLock<DiskState>,
    flush_timer: &RefCell<TimerAsync<Timer>>,
    flush_timer_armed: &RefCell<bool>,
) -> result::Result<usize, ExecuteError> {
    let reader = &mut avail_desc.reader;
    let writer = &mut avail_desc.writer;

    // The last byte of the buffer is virtio_blk_req::status.
    // Split it into a separate Writer so that status_writer is the final byte and
    // the original writer is left with just the actual block I/O data.
    let available_bytes = writer.available_bytes();
    let status_offset = available_bytes
        .checked_sub(1)
        .ok_or(ExecuteError::MissingStatus)?;
    let mut status_writer = writer.split_at(status_offset);

    let status = match BlockAsync::execute_request(
        reader,
        writer,
        disk_state,
        flush_timer,
        flush_timer_armed,
    )
    .await
    {
        Ok(()) => VIRTIO_BLK_S_OK,
        Err(e) => {
            match e.log_level() {
                LogLevel::Debug => debug!("failed executing disk request: {:#}", e),
                LogLevel::Error => error!("failed executing disk request: {:#}", e),
            }
            e.status()
        }
    };

    status_writer
        .write_all(&[status])
        .map_err(ExecuteError::WriteStatus)?;
    Ok(available_bytes)
}

/// Process one descriptor chain asynchronously.
pub async fn process_one_chain(
    queue: &RefCell<Queue>,
    mut avail_desc: DescriptorChain,
    disk_state: &AsyncRwLock<DiskState>,
    interrupt: &Interrupt,
    flush_timer: &RefCell<TimerAsync<Timer>>,
    flush_timer_armed: &RefCell<bool>,
) {
    let len = match process_one_request(&mut avail_desc, disk_state, flush_timer, flush_timer_armed)
        .await
    {
        Ok(len) => len,
        Err(e) => {
            error!("block: failed to handle request: {:#}", e);
            0
        }
    };

    let mut queue = queue.borrow_mut();
    queue.add_used(avail_desc, len as u32);
    queue.trigger_interrupt(interrupt);
}

// There is one async task running `handle_queue` per virtio queue in use.
// Receives messages from the guest and queues a task to complete the operations with the async
// executor.
async fn handle_queue(
    disk_state: Rc<AsyncRwLock<DiskState>>,
    queue: Rc<RefCell<Queue>>,
    evt: EventAsync,
    interrupt: Interrupt,
    flush_timer: Rc<RefCell<TimerAsync<Timer>>>,
    flush_timer_armed: Rc<RefCell<bool>>,
    mut stop_rx: oneshot::Receiver<()>,
) -> Rc<RefCell<Queue>> {
    let mut background_tasks = FuturesUnordered::new();
    let evt_future = evt.next_val().fuse();
    pin_mut!(evt_future);
    loop {
        // Wait for the next signal from `evt` and process `background_tasks` in the meantime.
        //
        // NOTE: We can't call `evt.next_val()` directly in the `select!` expression. That would
        // create a new future each time, which, in the completion-based async backends like
        // io_uring, means we'd submit a new syscall each time (i.e. a race condition on the
        // eventfd).
        futures::select! {
            _ = background_tasks.next() => continue,
            res = evt_future => {
                evt_future.set(evt.next_val().fuse());
                if let Err(e) = res {
                    error!("Failed to read the next queue event: {:#}", e);
                    continue;
                }
            }
            _ = stop_rx => {
                // Process all the descriptors we've already popped from the queue so that we leave
                // the queue in a consistent state.
                background_tasks.collect::<()>().await;
                return queue;
            }
        };
        while let Some(descriptor_chain) = queue.borrow_mut().pop() {
            background_tasks.push(process_one_chain(
                &queue,
                descriptor_chain,
                &disk_state,
                &interrupt,
                &flush_timer,
                &flush_timer_armed,
            ));
        }
    }
}

pub enum ConfigChangeSignal {
    Interrupt(Interrupt),
    VhostUserBackendRequest(Arc<Mutex<VhostBackendReqConnectionState>>),
}

async fn handle_command_tube(
    command_tube: &Option<AsyncTube>,
    signal: ConfigChangeSignal,
    disk_state: Rc<AsyncRwLock<DiskState>>,
) -> Result<(), ExecuteError> {
    let command_tube = match command_tube {
        Some(c) => c,
        None => {
            futures::future::pending::<()>().await;
            return Ok(());
        }
    };
    loop {
        match command_tube.next().await {
            Ok(command) => {
                let resp = match command {
                    DiskControlCommand::Resize { new_size } => resize(&disk_state, new_size).await,
                };

                let resp_clone = resp.clone();
                command_tube
                    .send(resp_clone)
                    .await
                    .map_err(ExecuteError::SendingResponse)?;
                if let DiskControlResult::Ok = resp {
                    match &signal {
                        ConfigChangeSignal::Interrupt(interrupt) => {
                            interrupt.signal_config_changed();
                        }
                        ConfigChangeSignal::VhostUserBackendRequest(request) => {
                            match &request.lock().deref() {
                                VhostBackendReqConnectionState::Connected(frontend) => {
                                    if let Err(e) = frontend.send_config_changed() {
                                        error!("Failed to notify config change: {:#}", e);
                                    }
                                }
                                VhostBackendReqConnectionState::NoConnection => {
                                    error!("No Backend request connection found");
                                }
                            }
                        }
                    };
                }
            }
            Err(e) => return Err(ExecuteError::ReceivingCommand(e)),
        }
    }
}

async fn resize(disk_state: &AsyncRwLock<DiskState>, new_size: u64) -> DiskControlResult {
    // Acquire exclusive, mutable access to the state so the virtqueue task won't be able to read
    // the state while resizing.
    let mut disk_state = disk_state.lock().await;
    // Prevent any other worker threads won't be able to do IO.
    let worker_shared_state = Arc::clone(&disk_state.worker_shared_state);
    let worker_shared_state = worker_shared_state.lock().await;

    if disk_state.read_only {
        error!("Attempted to resize read-only block device");
        return DiskControlResult::Err(SysError::new(libc::EROFS));
    }

    info!("Resizing block device to {} bytes", new_size);

    if let Err(e) = disk_state.disk_image.set_len(new_size) {
        error!("Resizing disk failed! {:#}", e);
        return DiskControlResult::Err(SysError::new(libc::EIO));
    }

    // Allocate new space if the disk image is not sparse.
    if !disk_state.sparse {
        if let Err(e) = disk_state.disk_image.allocate(0, new_size) {
            error!("Allocating disk space after resize failed! {:#}", e);
            return DiskControlResult::Err(SysError::new(libc::EIO));
        }
    }

    if let Ok(new_disk_size) = disk_state.disk_image.get_len() {
        worker_shared_state
            .disk_size
            .store(new_disk_size, Ordering::Release);
    }
    DiskControlResult::Ok
}

/// Periodically flushes the disk when the given timer fires.
async fn flush_disk(
    disk_state: Rc<AsyncRwLock<DiskState>>,
    timer: TimerAsync<Timer>,
    armed: Rc<RefCell<bool>>,
) -> Result<(), ControlError> {
    loop {
        timer.wait().await.map_err(ControlError::FlushTimer)?;
        if !*armed.borrow() {
            continue;
        }

        // Reset armed before calling fsync to guarantee that IO requests that started after we call
        // fsync will be committed eventually.
        *armed.borrow_mut() = false;

        disk_state
            .read_lock()
            .await
            .disk_image
            .fsync()
            .await
            .map_err(ControlError::FsyncDisk)?;
    }
}

pub enum WorkerCmd {
    StartQueue {
        index: usize,
        queue: Queue,
        interrupt: Interrupt,
    },
    StopQueue {
        index: usize,
        // Once the queue is stopped, it will be sent back over `response_tx`.
        // `None` indicates that there was no queue at the given index.
        response_tx: oneshot::Sender<Option<Queue>>,
    },
}

// The main worker thread. Initialized the asynchronous worker tasks and passes them to the executor
// to be processed.
//
// `disk_state` is wrapped by `AsyncRwLock`, which provides both shared and exclusive locks. It's
// because the state can be read from the virtqueue task while the control task is processing a
// resizing command.
pub async fn run_worker(
    ex: &Executor,
    signal: ConfigChangeSignal,
    disk_state: &Rc<AsyncRwLock<DiskState>>,
    control_tube: &Option<AsyncTube>,
    mut worker_rx: mpsc::UnboundedReceiver<WorkerCmd>,
    kill_evt: Event,
    resample_future: impl std::future::Future<Output = anyhow::Result<()>>,
) -> anyhow::Result<()> {
    // One flush timer per disk.
    let timer = Timer::new().expect("Failed to create a timer");
    let flush_timer_armed = Rc::new(RefCell::new(false));

    // Handles control requests.
    let control = handle_command_tube(control_tube, signal, disk_state.clone()).fuse();
    pin_mut!(control);

    // Handle all the queues in one sub-select call.
    let flush_timer = Rc::new(RefCell::new(
        TimerAsync::new(
            // Call try_clone() to share the same underlying FD with the `flush_disk` task.
            timer.try_clone().expect("Failed to clone flush_timer"),
            ex,
        )
        .expect("Failed to create an async timer"),
    ));

    // Flushes the disk periodically.
    let flush_timer2 = TimerAsync::new(timer, ex).expect("Failed to create an async timer");
    let disk_flush = flush_disk(disk_state.clone(), flush_timer2, flush_timer_armed.clone()).fuse();
    pin_mut!(disk_flush);

    // Exit if the kill event is triggered.
    let kill = async_utils::await_and_exit(ex, kill_evt).fuse();
    pin_mut!(kill);

    let resample_future = resample_future.fuse();
    pin_mut!(resample_future);

    // Running queue handlers.
    let mut queue_handlers = FuturesUnordered::new();
    // Async stop functions for queue handlers, by queue index.
    let mut queue_handler_stop_fns = std::collections::BTreeMap::new();

    loop {
        futures::select! {
            _ = queue_handlers.next() => continue,
            r = disk_flush => return r.context("failed to flush a disk"),
            r = control => return r.context("failed to handle a control request"),
            r = resample_future => return r.context("failed to resample an irq value"),
            r = kill => return r.context("failed to wait on the kill event"),
            worker_cmd = worker_rx.next() => {
                match worker_cmd {
                    None => anyhow::bail!("worker control channel unexpectedly closed"),
                    Some(WorkerCmd::StartQueue{index, queue, interrupt}) => {
                        let (tx, rx) = oneshot::channel();
                        let kick_evt = queue.event().try_clone().expect("Failed to clone queue event");
                        let (handle_queue_future, remote_handle) = handle_queue(
                            Rc::clone(disk_state),
                            Rc::new(RefCell::new(queue)),
                            EventAsync::new(kick_evt, ex).expect("Failed to create async event for queue"),
                            interrupt,
                            Rc::clone(&flush_timer),
                            Rc::clone(&flush_timer_armed),
                            rx,
                        ).remote_handle();
                        let old_stop_fn = queue_handler_stop_fns.insert(index, move || {
                            // Ask the handler to stop.
                            tx.send(()).unwrap_or_else(|_| panic!("queue handler channel closed early"));
                            // Wait for its return value.
                            remote_handle
                        });

                        // If there was already a handler for this index, stop it before adding the
                        // new handler future.
                        if let Some(stop_fn) = old_stop_fn {
                            warn!("Starting new queue handler without stopping old handler");
                            // Unfortunately we can't just do `stop_fn().await` because the actual
                            // work we are waiting on is in `queue_handlers`. So, run both.
                            let mut fut = stop_fn().fuse();
                            loop {
                                futures::select! {
                                    _ = queue_handlers.next() => continue,
                                    _queue = fut => break,
                                }
                            }
                        }

                        queue_handlers.push(handle_queue_future);
                    }
                    Some(WorkerCmd::StopQueue{index, response_tx}) => {
                        match queue_handler_stop_fns.remove(&index) {
                            Some(stop_fn) => {
                                // NOTE: This await is blocking the select loop. If we want to
                                // support stopping queues concurrently, then it needs to be moved.
                                // For now, keep it simple.
                                //
                                // Unfortunately we can't just do `stop_fn().await` because the
                                // actual work we are waiting on is in `queue_handlers`. So, run
                                // both.
                                let mut fut = stop_fn().fuse();
                                let queue = loop {
                                    futures::select! {
                                        _ = queue_handlers.next() => continue,
                                        queue = fut => break queue,
                                    }
                                };
                                let queue = Rc::try_unwrap(queue).unwrap_or_else(|_| panic!("Rc had too many refs")).into_inner();
                                let _ = response_tx.send(Some(queue));
                            }
                            None => { let _ = response_tx.send(None); },
                        }
                    }
                }
            }
        };
    }
}

/// Virtio device for exposing block level read/write operations on a host file.
pub struct BlockAsync {
    // We need to make boot_index public bc the field is used by the main crate to determine boot
    // order
    pub boot_index: Option<usize>,
    // We keep these members crate-public as they are accessed by the vhost-user device.
    pub(crate) disk_image: Option<Box<dyn DiskFile>>,
    pub(crate) disk_size: Arc<AtomicU64>,
    pub(crate) avail_features: u64,
    pub(crate) read_only: bool,
    pub(crate) sparse: bool,
    pub(crate) seg_max: u32,
    pub(crate) block_size: u32,
    pub(crate) id: Option<BlockId>,
    pub(crate) control_tube: Option<Tube>,
    pub(crate) queue_sizes: Vec<u16>,
    pub(crate) executor_kind: ExecutorKind,
    worker_threads: Vec<(
        WorkerThread<(Box<dyn DiskFile>, Option<Tube>)>,
        mpsc::UnboundedSender<WorkerCmd>,
    )>,
    // Whether to run worker threads in parallel for each queue
    worker_per_queue: bool,
    // Number of queues passed to `activate`. None if device not activated.
    num_activated_queues: Option<usize>,
}

impl BlockAsync {
    /// Create a new virtio block device that operates on the given AsyncDisk.
    pub fn new(
        base_features: u64,
        disk_image: Box<dyn DiskFile>,
        disk_option: &DiskOption,
        control_tube: Option<Tube>,
        queue_size: Option<u16>,
        num_queues: Option<u16>,
    ) -> SysResult<BlockAsync> {
        let read_only = disk_option.read_only;
        let sparse = disk_option.sparse;
        let block_size = disk_option.block_size;
        let packed_queue = disk_option.packed_queue;
        let id = disk_option.id;
        let multiple_workers = disk_option.multiple_workers;
        let executor_kind = disk_option.async_executor;
        let boot_index = disk_option.bootindex;

        if block_size % SECTOR_SIZE as u32 != 0 {
            error!(
                "Block size {} is not a multiple of {}.",
                block_size, SECTOR_SIZE,
            );
            return Err(SysError::new(libc::EINVAL));
        }
        let disk_size = disk_image.get_len()?;
        if disk_size % block_size as u64 != 0 {
            warn!(
                "Disk size {} is not a multiple of block size {}; \
                 the remainder will not be visible to the guest.",
                disk_size, block_size,
            );
        }
        let num_queues = num_queues.unwrap_or(DEFAULT_NUM_QUEUES);
        let multi_queue = match num_queues {
            0 => panic!("Number of queues cannot be zero for a block device"),
            1 => false,
            _ => true,
        };
        let q_size = queue_size.unwrap_or(DEFAULT_QUEUE_SIZE);
        if !q_size.is_power_of_two() {
            error!("queue size {} is not a power of 2.", q_size);
            return Err(SysError::new(libc::EINVAL));
        }
        let queue_sizes = vec![q_size; num_queues as usize];

        let avail_features =
            Self::build_avail_features(base_features, read_only, sparse, multi_queue, packed_queue);

        let seg_max = get_seg_max(q_size);
        let executor_kind = executor_kind.unwrap_or_default();

        Ok(BlockAsync {
            disk_image: Some(disk_image),
            disk_size: Arc::new(AtomicU64::new(disk_size)),
            avail_features,
            read_only,
            sparse,
            seg_max,
            block_size,
            id,
            queue_sizes,
            worker_threads: vec![],
            worker_per_queue: multiple_workers,
            control_tube,
            executor_kind,
            num_activated_queues: None,
            boot_index,
        })
    }

    /// Returns the feature flags given the specified attributes.
    fn build_avail_features(
        base_features: u64,
        read_only: bool,
        sparse: bool,
        multi_queue: bool,
        packed_queue: bool,
    ) -> u64 {
        let mut avail_features = base_features;
        if read_only {
            avail_features |= 1 << VIRTIO_BLK_F_RO;
        } else {
            if sparse {
                avail_features |= 1 << VIRTIO_BLK_F_DISCARD;
            }
            avail_features |= 1 << VIRTIO_BLK_F_FLUSH;
            avail_features |= 1 << VIRTIO_BLK_F_WRITE_ZEROES;
        }
        avail_features |= 1 << VIRTIO_BLK_F_SEG_MAX;
        avail_features |= 1 << VIRTIO_BLK_F_BLK_SIZE;
        if multi_queue {
            avail_features |= 1 << VIRTIO_BLK_F_MQ;
        }
        if packed_queue {
            avail_features |= 1 << VIRTIO_F_RING_PACKED;
        }
        avail_features
    }

    // Execute a single block device request.
    // `writer` includes the data region only; the status byte is not included.
    // It is up to the caller to convert the result of this function into a status byte
    // and write it to the expected location in guest memory.
    async fn execute_request(
        reader: &mut Reader,
        writer: &mut Writer,
        disk_state: &AsyncRwLock<DiskState>,
        flush_timer: &RefCell<TimerAsync<Timer>>,
        flush_timer_armed: &RefCell<bool>,
    ) -> result::Result<(), ExecuteError> {
        // Acquire immutable access to prevent tasks from resizing disk.
        let disk_state = disk_state.read_lock().await;
        // Acquire immutable access to prevent other worker threads from resizing disk.
        let worker_shared_state = disk_state.worker_shared_state.read_lock().await;

        let req_header: virtio_blk_req_header = reader.read_obj().map_err(ExecuteError::Read)?;

        let req_type = req_header.req_type.to_native();
        let sector = req_header.sector.to_native();

        if disk_state.read_only && req_type != VIRTIO_BLK_T_IN && req_type != VIRTIO_BLK_T_GET_ID {
            return Err(ExecuteError::ReadOnly {
                request_type: req_type,
            });
        }

        /// Check that a request accesses only data within the disk's current size.
        /// All parameters are in units of bytes.
        fn check_range(
            io_start: u64,
            io_length: u64,
            disk_size: u64,
        ) -> result::Result<(), ExecuteError> {
            let io_end = io_start
                .checked_add(io_length)
                .ok_or(ExecuteError::OutOfRange)?;
            if io_end > disk_size {
                Err(ExecuteError::OutOfRange)
            } else {
                Ok(())
            }
        }

        let disk_size = worker_shared_state.disk_size.load(Ordering::Relaxed);
        match req_type {
            VIRTIO_BLK_T_IN => {
                let data_len = writer.available_bytes();
                if data_len == 0 {
                    return Ok(());
                }
                let offset = sector
                    .checked_shl(u32::from(SECTOR_SHIFT))
                    .ok_or(ExecuteError::OutOfRange)?;
                check_range(offset, data_len as u64, disk_size)?;
                let disk_image = &disk_state.disk_image;
                writer
                    .write_all_from_at_fut(&**disk_image, data_len, offset)
                    .await
                    .map_err(|desc_error| ExecuteError::ReadIo {
                        length: data_len,
                        sector,
                        desc_error,
                    })?;
            }
            VIRTIO_BLK_T_OUT => {
                let data_len = reader.available_bytes();
                if data_len == 0 {
                    return Ok(());
                }
                let offset = sector
                    .checked_shl(u32::from(SECTOR_SHIFT))
                    .ok_or(ExecuteError::OutOfRange)?;
                check_range(offset, data_len as u64, disk_size)?;
                let disk_image = &disk_state.disk_image;
                reader
                    .read_exact_to_at_fut(&**disk_image, data_len, offset)
                    .await
                    .map_err(|desc_error| ExecuteError::WriteIo {
                        length: data_len,
                        sector,
                        desc_error,
                    })?;

                if !*flush_timer_armed.borrow() {
                    *flush_timer_armed.borrow_mut() = true;

                    let flush_delay = Duration::from_secs(60);
                    flush_timer
                        .borrow_mut()
                        .reset(flush_delay, None)
                        .map_err(ExecuteError::TimerReset)?;
                }
            }
            VIRTIO_BLK_T_DISCARD | VIRTIO_BLK_T_WRITE_ZEROES => {
                if req_type == VIRTIO_BLK_T_DISCARD && !disk_state.sparse {
                    // Discard is a hint; if this is a non-sparse disk, just ignore it.
                    return Ok(());
                }

                while reader.available_bytes() >= size_of::<virtio_blk_discard_write_zeroes>() {
                    let seg: virtio_blk_discard_write_zeroes =
                        reader.read_obj().map_err(ExecuteError::Read)?;

                    let sector = seg.sector.to_native();
                    let num_sectors = seg.num_sectors.to_native();
                    let flags = seg.flags.to_native();

                    let valid_flags = if req_type == VIRTIO_BLK_T_WRITE_ZEROES {
                        VIRTIO_BLK_DISCARD_WRITE_ZEROES_FLAG_UNMAP
                    } else {
                        0
                    };

                    if (flags & !valid_flags) != 0 {
                        return Err(ExecuteError::DiscardWriteZeroes {
                            ioerr: None,
                            sector,
                            num_sectors,
                            flags,
                        });
                    }

                    let offset = sector
                        .checked_shl(u32::from(SECTOR_SHIFT))
                        .ok_or(ExecuteError::OutOfRange)?;
                    let length = u64::from(num_sectors)
                        .checked_shl(u32::from(SECTOR_SHIFT))
                        .ok_or(ExecuteError::OutOfRange)?;
                    check_range(offset, length, disk_size)?;

                    if req_type == VIRTIO_BLK_T_DISCARD {
                        // Since Discard is just a hint and some filesystems may not implement
                        // FALLOC_FL_PUNCH_HOLE, ignore punch_hole errors.
                        let _ = disk_state.disk_image.punch_hole(offset, length).await;
                    } else {
                        disk_state
                            .disk_image
                            .write_zeroes_at(offset, length)
                            .await
                            .map_err(|e| ExecuteError::DiscardWriteZeroes {
                                ioerr: Some(e),
                                sector,
                                num_sectors,
                                flags,
                            })?;
                    }
                }
            }
            VIRTIO_BLK_T_FLUSH => {
                disk_state
                    .disk_image
                    .fdatasync()
                    .await
                    .map_err(ExecuteError::Flush)?;

                if *flush_timer_armed.borrow() {
                    flush_timer
                        .borrow_mut()
                        .clear()
                        .map_err(ExecuteError::TimerReset)?;
                    *flush_timer_armed.borrow_mut() = false;
                }
            }
            VIRTIO_BLK_T_GET_ID => {
                if let Some(id) = disk_state.id {
                    writer.write_all(&id).map_err(ExecuteError::CopyId)?;
                } else {
                    return Err(ExecuteError::Unsupported(req_type));
                }
            }
            t => return Err(ExecuteError::Unsupported(t)),
        };
        Ok(())
    }

    /// Builds and returns the config structure used to specify block features.
    pub fn build_config_space(
        disk_size: u64,
        seg_max: u32,
        block_size: u32,
        num_queues: u16,
    ) -> virtio_blk_config {
        virtio_blk_config {
            // If the image is not a multiple of the sector size, the tail bits are not exposed.
            capacity: Le64::from(disk_size >> SECTOR_SHIFT),
            seg_max: Le32::from(seg_max),
            blk_size: Le32::from(block_size),
            num_queues: Le16::from(num_queues),
            max_discard_sectors: Le32::from(MAX_DISCARD_SECTORS),
            discard_sector_alignment: Le32::from(DISCARD_SECTOR_ALIGNMENT),
            max_write_zeroes_sectors: Le32::from(MAX_WRITE_ZEROES_SECTORS),
            write_zeroes_may_unmap: 1,
            max_discard_seg: Le32::from(MAX_DISCARD_SEG),
            max_write_zeroes_seg: Le32::from(MAX_WRITE_ZEROES_SEG),
            ..Default::default()
        }
    }
}

impl VirtioDevice for BlockAsync {
    fn keep_rds(&self) -> Vec<RawDescriptor> {
        let mut keep_rds = Vec::new();

        if let Some(disk_image) = &self.disk_image {
            keep_rds.extend(disk_image.as_raw_descriptors());
        }

        if let Some(control_tube) = &self.control_tube {
            keep_rds.push(control_tube.as_raw_descriptor());
        }

        keep_rds
    }

    fn features(&self) -> u64 {
        self.avail_features
    }

    fn device_type(&self) -> DeviceType {
        DeviceType::Block
    }

    fn queue_max_sizes(&self) -> &[u16] {
        &self.queue_sizes
    }

    fn read_config(&self, offset: u64, data: &mut [u8]) {
        let config_space = {
            let disk_size = self.disk_size.load(Ordering::Acquire);
            Self::build_config_space(
                disk_size,
                self.seg_max,
                self.block_size,
                self.queue_sizes.len() as u16,
            )
        };
        copy_config(data, 0, config_space.as_bytes(), offset);
    }

    fn activate(
        &mut self,
        _mem: GuestMemory,
        interrupt: Interrupt,
        queues: BTreeMap<usize, Queue>,
    ) -> anyhow::Result<()> {
        assert!(self.num_activated_queues.is_none());
        self.num_activated_queues = Some(queues.len());

        let read_only = self.read_only;
        let sparse = self.sparse;
        let id = self.id;
        let executor_kind = self.executor_kind;
        let disk_image = self
            .disk_image
            .take()
            .context("Failed to take a disk image")?;

        // If worker_per_queue is enabled and disk_image supports cloning, run workers in parallel.
        let queues_per_worker = if self.worker_per_queue && disk_image.try_clone().is_ok() {
            // 1 queue per 1 worker
            queues
                .into_iter()
                .map(|entry| {
                    Ok((
                        BTreeMap::from([entry]),
                        disk_image
                            .try_clone()
                            .context("Failed to clone a disk image")?,
                    ))
                })
                .collect::<anyhow::Result<_>>()?
        } else {
            vec![(queues, disk_image)]
        };

        let shared_state = Arc::new(AsyncRwLock::new(WorkerSharedState {
            disk_size: self.disk_size.clone(),
        }));

        let mut worker_threads = vec![];
        for (queues, disk_image) in queues_per_worker.into_iter() {
            let shared_state = Arc::clone(&shared_state);
            let interrupt = interrupt.clone();
            let control_tube = self.control_tube.take();

            let (worker_tx, worker_rx) = mpsc::unbounded();
            // Add commands to start all the queues before starting the worker.
            for (index, queue) in queues.into_iter() {
                worker_tx
                    .unbounded_send(WorkerCmd::StartQueue {
                        index,
                        queue,
                        interrupt: interrupt.clone(),
                    })
                    .expect("worker channel closed early");
            }

            let worker_thread = WorkerThread::start("virtio_blk", move |kill_evt| {
                let ex = Executor::with_executor_kind(executor_kind)
                    .expect("Failed to create an executor");

                let async_control = control_tube
                    .map(|c| AsyncTube::new(&ex, c).expect("failed to create async tube"));
                let async_image = match disk_image.to_async_disk(&ex) {
                    Ok(d) => d,
                    Err(e) => panic!("Failed to create async disk {:#}", e),
                };
                let disk_state = Rc::new(AsyncRwLock::new(DiskState {
                    disk_image: async_image,
                    read_only,
                    sparse,
                    id,
                    worker_shared_state: shared_state,
                }));

                if let Err(err_string) = ex
                    .run_until(async {
                        let r = run_worker(
                            &ex,
                            ConfigChangeSignal::Interrupt(interrupt.clone()),
                            &disk_state,
                            &async_control,
                            worker_rx,
                            kill_evt,
                            async {
                                // Process any requests to resample the irq value.
                                async_utils::handle_irq_resample(&ex, interrupt.clone()).await
                            },
                        )
                        .await;
                        // Flush any in-memory disk image state to file.
                        if let Err(e) = disk_state.lock().await.disk_image.flush().await {
                            error!("failed to flush disk image when stopping worker: {e:?}");
                        }
                        r
                    })
                    .expect("run_until failed")
                {
                    error!("{:#}", err_string);
                }

                let disk_state = match Rc::try_unwrap(disk_state) {
                    Ok(d) => d.into_inner(),
                    Err(_) => panic!("too many refs to the disk"),
                };
                (
                    disk_state.disk_image.into_inner(),
                    async_control.map(Tube::from),
                )
            });
            worker_threads.push((worker_thread, worker_tx));
        }

        self.worker_threads = worker_threads;
        Ok(())
    }

    fn reset(&mut self) -> bool {
        let mut success = false;
        while let Some((worker_thread, _)) = self.worker_threads.pop() {
            let (disk_image, control_tube) = worker_thread.stop();
            self.disk_image = Some(disk_image);
            if let Some(control_tube) = control_tube {
                self.control_tube = Some(control_tube);
            }
            success = true;
        }
        self.num_activated_queues = None;
        success
    }

    fn virtio_sleep(&mut self) -> anyhow::Result<Option<BTreeMap<usize, Queue>>> {
        let num_activated_queues = match self.num_activated_queues {
            Some(x) => x,
            None => return Ok(None), // Not activated.
        };
        // Reclaim the queues from workers.
        let mut queues = BTreeMap::new();
        for index in 0..num_activated_queues {
            let worker_index = if self.worker_per_queue { index } else { 0 };
            let worker_tx = &self.worker_threads[worker_index].1;
            let (response_tx, response_rx) = oneshot::channel();
            worker_tx
                .unbounded_send(WorkerCmd::StopQueue { index, response_tx })
                .expect("worker channel closed early");
            let queue = cros_async::block_on(async {
                response_rx
                    .await
                    .expect("response_rx closed early")
                    .expect("missing queue")
            });
            queues.insert(index, queue);
        }
        // Shutdown the workers.
        while let Some((worker_thread, _)) = self.worker_threads.pop() {
            let (disk_image, control_tube) = worker_thread.stop();
            self.disk_image = Some(disk_image);
            if let Some(control_tube) = control_tube {
                self.control_tube = Some(control_tube);
            }
        }
        Ok(Some(queues))
    }

    fn virtio_wake(
        &mut self,
        queues_state: Option<(GuestMemory, Interrupt, BTreeMap<usize, Queue>)>,
    ) -> anyhow::Result<()> {
        if let Some((mem, interrupt, queues)) = queues_state {
            // TODO: activate is just what we want at the moment, but we should probably move
            // it into a "start workers" function to make it obvious that it isn't strictly
            // used for activate events.
            self.num_activated_queues = None;
            self.activate(mem, interrupt, queues)?;
        }
        Ok(())
    }

    fn virtio_snapshot(&self) -> anyhow::Result<serde_json::Value> {
        // `virtio_sleep` ensures there is no pending state, except for the `Queue`s, which are
        // handled at a higher layer.
        Ok(serde_json::Value::Null)
    }

    fn virtio_restore(&mut self, data: serde_json::Value) -> anyhow::Result<()> {
        anyhow::ensure!(
            data == serde_json::Value::Null,
            "unexpected snapshot data: should be null, got {}",
            data,
        );
        Ok(())
    }

    fn bootorder_fw_cfg(&self, pci_slot: u8) -> Option<(Vec<u8>, usize)> {
        self.boot_index
            .map(|s| (format!("scsi@{}/disk@0,0", pci_slot).as_bytes().to_vec(), s))
    }
}

#[cfg(test)]
mod tests {
    use std::fs::File;
    use std::mem::size_of_val;
    use std::sync::atomic::AtomicU64;

    use data_model::Le32;
    use data_model::Le64;
    use disk::SingleFileDisk;
    use hypervisor::ProtectionType;
    use tempfile::tempfile;
    use tempfile::TempDir;
    use vm_memory::GuestAddress;

    use super::*;
    use crate::suspendable_virtio_tests;
    use crate::virtio::base_features;
    use crate::virtio::descriptor_utils::create_descriptor_chain;
    use crate::virtio::descriptor_utils::DescriptorType;
    use crate::virtio::QueueConfig;
    use crate::virtio::VIRTIO_MSI_NO_VECTOR;
    use crate::IrqLevelEvent;

    #[test]
    fn read_size() {
        let f = tempfile().unwrap();
        f.set_len(0x1000).unwrap();

        let features = base_features(ProtectionType::Unprotected);
        let disk_option = DiskOption::default();
        let b = BlockAsync::new(features, Box::new(f), &disk_option, None, None, None).unwrap();
        let mut num_sectors = [0u8; 4];
        b.read_config(0, &mut num_sectors);
        // size is 0x1000, so num_sectors is 8 (4096/512).
        assert_eq!([0x08, 0x00, 0x00, 0x00], num_sectors);
        let mut msw_sectors = [0u8; 4];
        b.read_config(4, &mut msw_sectors);
        // size is 0x1000, so msw_sectors is 0.
        assert_eq!([0x00, 0x00, 0x00, 0x00], msw_sectors);
    }

    #[test]
    fn read_block_size() {
        let f = tempfile().unwrap();
        f.set_len(0x1000).unwrap();

        let features = base_features(ProtectionType::Unprotected);
        let disk_option = DiskOption {
            block_size: 4096,
            sparse: false,
            ..Default::default()
        };
        let b = BlockAsync::new(features, Box::new(f), &disk_option, None, None, None).unwrap();
        let mut blk_size = [0u8; 4];
        b.read_config(20, &mut blk_size);
        // blk_size should be 4096 (0x1000).
        assert_eq!([0x00, 0x10, 0x00, 0x00], blk_size);
    }

    #[test]
    fn read_features() {
        let tempdir = TempDir::new().unwrap();
        let mut path = tempdir.path().to_owned();
        path.push("disk_image");

        // read-write block device
        {
            let f = File::create(&path).unwrap();
            let features = base_features(ProtectionType::Unprotected);
            let disk_option = DiskOption::default();
            let b = BlockAsync::new(features, Box::new(f), &disk_option, None, None, None).unwrap();
            // writable device should set VIRTIO_BLK_F_FLUSH + VIRTIO_BLK_F_DISCARD
            // + VIRTIO_BLK_F_WRITE_ZEROES + VIRTIO_F_VERSION_1 + VIRTIO_BLK_F_BLK_SIZE
            // + VIRTIO_BLK_F_SEG_MAX + VIRTIO_BLK_F_MQ + VIRTIO_RING_F_EVENT_IDX
            assert_eq!(0x120007244, b.features());
        }

        // read-write block device, non-sparse
        {
            let f = File::create(&path).unwrap();
            let features = base_features(ProtectionType::Unprotected);
            let disk_option = DiskOption {
                sparse: false,
                ..Default::default()
            };
            let b = BlockAsync::new(features, Box::new(f), &disk_option, None, None, None).unwrap();
            // writable device should set VIRTIO_F_FLUSH + VIRTIO_BLK_F_RO
            // + VIRTIO_F_VERSION_1 + VIRTIO_BLK_F_BLK_SIZE + VIRTIO_BLK_F_SEG_MAX
            // + VIRTIO_BLK_F_MQ + VIRTIO_RING_F_EVENT_IDX
            assert_eq!(0x120005244, b.features());
        }

        // read-only block device
        {
            let f = File::create(&path).unwrap();
            let features = base_features(ProtectionType::Unprotected);
            let disk_option = DiskOption {
                read_only: true,
                ..Default::default()
            };
            let b = BlockAsync::new(features, Box::new(f), &disk_option, None, None, None).unwrap();
            // read-only device should set VIRTIO_BLK_F_RO
            // + VIRTIO_F_VERSION_1 + VIRTIO_BLK_F_BLK_SIZE + VIRTIO_BLK_F_SEG_MAX
            // + VIRTIO_BLK_F_MQ + VIRTIO_RING_F_EVENT_IDX
            assert_eq!(0x120001064, b.features());
        }
    }

    #[test]
    fn check_runtime_blk_queue_configurability() {
        let tempdir = TempDir::new().unwrap();
        let mut path = tempdir.path().to_owned();
        path.push("disk_image");
        let features = base_features(ProtectionType::Unprotected);

        // Default case
        let f = File::create(&path).unwrap();
        let disk_option = DiskOption::default();
        let b = BlockAsync::new(features, Box::new(f), &disk_option, None, None, None).unwrap();
        assert_eq!(
            [DEFAULT_QUEUE_SIZE; DEFAULT_NUM_QUEUES as usize],
            b.queue_max_sizes()
        );

        // Single queue of size 128
        let f = File::create(&path).unwrap();
        let disk_option = DiskOption::default();
        let b = BlockAsync::new(
            features,
            Box::new(f),
            &disk_option,
            None,
            Some(128),
            Some(1),
        )
        .unwrap();
        assert_eq!([128; 1], b.queue_max_sizes());
        // Single queue device should not set VIRTIO_BLK_F_MQ
        assert_eq!(0, b.features() & (1 << VIRTIO_BLK_F_MQ) as u64);
    }

    #[test]
    fn read_last_sector() {
        let ex = Executor::new().expect("creating an executor failed");

        let f = tempfile().unwrap();
        let disk_size = 0x1000;
        f.set_len(disk_size).unwrap();
        let af = SingleFileDisk::new(f, &ex).expect("Failed to create SFD");

        let mem = Rc::new(
            GuestMemory::new(&[(GuestAddress(0u64), 4 * 1024 * 1024)])
                .expect("Creating guest memory failed."),
        );

        let req_hdr = virtio_blk_req_header {
            req_type: Le32::from(VIRTIO_BLK_T_IN),
            reserved: Le32::from(0),
            sector: Le64::from(7), // Disk is 8 sectors long, so this is the last valid sector.
        };
        mem.write_obj_at_addr(req_hdr, GuestAddress(0x1000))
            .expect("writing req failed");

        let mut avail_desc = create_descriptor_chain(
            &mem,
            GuestAddress(0x100),  // Place descriptor chain at 0x100.
            GuestAddress(0x1000), // Describe buffer at 0x1000.
            vec![
                // Request header
                (DescriptorType::Readable, size_of_val(&req_hdr) as u32),
                // I/O buffer (1 sector of data)
                (DescriptorType::Writable, 512),
                // Request status
                (DescriptorType::Writable, 1),
            ],
            0,
        )
        .expect("create_descriptor_chain failed");

        let timer = Timer::new().expect("Failed to create a timer");
        let flush_timer = Rc::new(RefCell::new(
            TimerAsync::new(timer, &ex).expect("Failed to create an async timer"),
        ));
        let flush_timer_armed = Rc::new(RefCell::new(false));

        let disk_state = Rc::new(AsyncRwLock::new(DiskState {
            disk_image: Box::new(af),
            read_only: false,
            sparse: true,
            id: None,
            worker_shared_state: Arc::new(AsyncRwLock::new(WorkerSharedState {
                disk_size: Arc::new(AtomicU64::new(disk_size)),
            })),
        }));

        let fut = process_one_request(
            &mut avail_desc,
            &disk_state,
            &flush_timer,
            &flush_timer_armed,
        );

        ex.run_until(fut)
            .expect("running executor failed")
            .expect("execute failed");

        let status_offset = GuestAddress((0x1000 + size_of_val(&req_hdr) + 512) as u64);
        let status = mem.read_obj_from_addr::<u8>(status_offset).unwrap();
        assert_eq!(status, VIRTIO_BLK_S_OK);
    }

    #[test]
    fn read_beyond_last_sector() {
        let f = tempfile().unwrap();
        let disk_size = 0x1000;
        f.set_len(disk_size).unwrap();
        let mem = Rc::new(
            GuestMemory::new(&[(GuestAddress(0u64), 4 * 1024 * 1024)])
                .expect("Creating guest memory failed."),
        );

        let req_hdr = virtio_blk_req_header {
            req_type: Le32::from(VIRTIO_BLK_T_IN),
            reserved: Le32::from(0),
            sector: Le64::from(7), // Disk is 8 sectors long, so this is the last valid sector.
        };
        mem.write_obj_at_addr(req_hdr, GuestAddress(0x1000))
            .expect("writing req failed");

        let mut avail_desc = create_descriptor_chain(
            &mem,
            GuestAddress(0x100),  // Place descriptor chain at 0x100.
            GuestAddress(0x1000), // Describe buffer at 0x1000.
            vec![
                // Request header
                (DescriptorType::Readable, size_of_val(&req_hdr) as u32),
                // I/O buffer (2 sectors of data - overlap the end of the disk).
                (DescriptorType::Writable, 512 * 2),
                // Request status
                (DescriptorType::Writable, 1),
            ],
            0,
        )
        .expect("create_descriptor_chain failed");

        let ex = Executor::new().expect("creating an executor failed");

        let af = SingleFileDisk::new(f, &ex).expect("Failed to create SFD");
        let timer = Timer::new().expect("Failed to create a timer");
        let flush_timer = Rc::new(RefCell::new(
            TimerAsync::new(timer, &ex).expect("Failed to create an async timer"),
        ));
        let flush_timer_armed = Rc::new(RefCell::new(false));
        let disk_state = Rc::new(AsyncRwLock::new(DiskState {
            disk_image: Box::new(af),
            read_only: false,
            sparse: true,
            id: None,
            worker_shared_state: Arc::new(AsyncRwLock::new(WorkerSharedState {
                disk_size: Arc::new(AtomicU64::new(disk_size)),
            })),
        }));

        let fut = process_one_request(
            &mut avail_desc,
            &disk_state,
            &flush_timer,
            &flush_timer_armed,
        );

        ex.run_until(fut)
            .expect("running executor failed")
            .expect("execute failed");

        let status_offset = GuestAddress((0x1000 + size_of_val(&req_hdr) + 512 * 2) as u64);
        let status = mem.read_obj_from_addr::<u8>(status_offset).unwrap();
        assert_eq!(status, VIRTIO_BLK_S_IOERR);
    }

    #[test]
    fn get_id() {
        let ex = Executor::new().expect("creating an executor failed");

        let f = tempfile().unwrap();
        let disk_size = 0x1000;
        f.set_len(disk_size).unwrap();

        let mem = GuestMemory::new(&[(GuestAddress(0u64), 4 * 1024 * 1024)])
            .expect("Creating guest memory failed.");

        let req_hdr = virtio_blk_req_header {
            req_type: Le32::from(VIRTIO_BLK_T_GET_ID),
            reserved: Le32::from(0),
            sector: Le64::from(0),
        };
        mem.write_obj_at_addr(req_hdr, GuestAddress(0x1000))
            .expect("writing req failed");

        let mut avail_desc = create_descriptor_chain(
            &mem,
            GuestAddress(0x100),  // Place descriptor chain at 0x100.
            GuestAddress(0x1000), // Describe buffer at 0x1000.
            vec![
                // Request header
                (DescriptorType::Readable, size_of_val(&req_hdr) as u32),
                // I/O buffer (20 bytes for serial)
                (DescriptorType::Writable, 20),
                // Request status
                (DescriptorType::Writable, 1),
            ],
            0,
        )
        .expect("create_descriptor_chain failed");

        let af = SingleFileDisk::new(f, &ex).expect("Failed to create SFD");
        let timer = Timer::new().expect("Failed to create a timer");
        let flush_timer = Rc::new(RefCell::new(
            TimerAsync::new(timer, &ex).expect("Failed to create an async timer"),
        ));
        let flush_timer_armed = Rc::new(RefCell::new(false));

        let id = b"a20-byteserialnumber";

        let disk_state = Rc::new(AsyncRwLock::new(DiskState {
            disk_image: Box::new(af),
            read_only: false,
            sparse: true,
            id: Some(*id),
            worker_shared_state: Arc::new(AsyncRwLock::new(WorkerSharedState {
                disk_size: Arc::new(AtomicU64::new(disk_size)),
            })),
        }));

        let fut = process_one_request(
            &mut avail_desc,
            &disk_state,
            &flush_timer,
            &flush_timer_armed,
        );

        ex.run_until(fut)
            .expect("running executor failed")
            .expect("execute failed");

        let status_offset = GuestAddress((0x1000 + size_of_val(&req_hdr) + 512) as u64);
        let status = mem.read_obj_from_addr::<u8>(status_offset).unwrap();
        assert_eq!(status, VIRTIO_BLK_S_OK);

        let id_offset = GuestAddress(0x1000 + size_of_val(&req_hdr) as u64);
        let returned_id = mem.read_obj_from_addr::<[u8; 20]>(id_offset).unwrap();
        assert_eq!(returned_id, *id);
    }

    // TODO(b/270225199): enable this test on Windows once IoSource::into_source is implemented
    #[cfg(unix)]
    #[test]
    fn reset_and_reactivate_single_worker() {
        reset_and_reactivate(false);
    }

    // TODO(b/270225199): enable this test on Windows once IoSource::into_source is implemented
    #[cfg(unix)]
    #[test]
    fn reset_and_reactivate_multiple_workers() {
        reset_and_reactivate(true);
    }

    #[cfg(unix)]
    fn reset_and_reactivate(enables_multiple_workers: bool) {
        // Create an empty disk image
        let f = tempfile().unwrap();
        f.set_len(0x1000).unwrap();
        let disk_image: Box<dyn DiskFile> = Box::new(f);

        // Create an empty guest memory
        let mem = GuestMemory::new(&[(GuestAddress(0u64), 4 * 1024 * 1024)])
            .expect("Creating guest memory failed.");

        // Create a control tube.
        // NOTE: We don't want to drop the vmm half of the tube. That would cause the worker thread
        // will immediately fail, which isn't what we want to test in this case.
        let (_control_tube, control_tube_device) = Tube::pair().unwrap();

        // Create a BlockAsync to test
        let features = base_features(ProtectionType::Unprotected);
        let id = b"Block serial number\0";
        let disk_option = DiskOption {
            read_only: true,
            id: Some(*id),
            sparse: false,
            multiple_workers: enables_multiple_workers,
            ..Default::default()
        };
        let mut b = BlockAsync::new(
            features,
            disk_image.try_clone().unwrap(),
            &disk_option,
            Some(control_tube_device),
            None,
            None,
        )
        .unwrap();

        // activate with queues of an arbitrary size.
        let mut q0 = QueueConfig::new(DEFAULT_QUEUE_SIZE, 0);
        q0.set_ready(true);
        let q0 = q0
            .activate(&mem, Event::new().unwrap())
            .expect("QueueConfig::activate");

        let mut q1 = QueueConfig::new(DEFAULT_QUEUE_SIZE, 0);
        q1.set_ready(true);
        let q1 = q1
            .activate(&mem, Event::new().unwrap())
            .expect("QueueConfig::activate");

        b.activate(
            mem.clone(),
            Interrupt::new(IrqLevelEvent::new().unwrap(), None, VIRTIO_MSI_NO_VECTOR),
            BTreeMap::from([(0, q0), (1, q1)]),
        )
        .expect("activate should succeed");
        // assert resources are consumed
        assert!(
            b.disk_image.is_none(),
            "BlockAsync should not have a disk image"
        );
        assert!(
            b.control_tube.is_none(),
            "BlockAsync should not have a control tube"
        );

        // reset and assert resources are got back
        assert!(b.reset(), "reset should succeed");
        assert!(
            b.disk_image.is_some(),
            "BlockAsync should have a disk image"
        );
        assert!(
            b.control_tube.is_some(),
            "BlockAsync should have a control tube"
        );
        assert_eq!(b.id, Some(*b"Block serial number\0"));

        // re-activate should succeed
        let mut q0 = QueueConfig::new(DEFAULT_QUEUE_SIZE, 0);
        q0.set_ready(true);
        let q0 = q0
            .activate(&mem, Event::new().unwrap())
            .expect("QueueConfig::activate");

        let mut q1 = QueueConfig::new(DEFAULT_QUEUE_SIZE, 0);
        q1.set_ready(true);
        let q1 = q1
            .activate(&mem, Event::new().unwrap())
            .expect("QueueConfig::activate");

        b.activate(
            mem,
            Interrupt::new(IrqLevelEvent::new().unwrap(), None, VIRTIO_MSI_NO_VECTOR),
            BTreeMap::from([(0, q0), (1, q1)]),
        )
        .expect("re-activate should succeed");
    }

    // TODO(b/270225199): enable this test on Windows once IoSource::into_source is implemented,
    // or after finding a good way to prevent BlockAsync::drop() from panicking due to that.
    #[cfg(unix)]
    #[test]
    fn resize_with_single_worker() {
        resize(false);
    }

    // TODO(b/270225199): enable this test on Windows once IoSource::into_source is implemented,
    // or after finding a good way to prevent BlockAsync::drop() from panicking due to that.
    #[cfg(unix)]
    #[test]
    fn resize_with_multiple_workers() {
        // Test resize handled by one worker affect the whole state
        resize(true);
    }

    fn resize(enables_multiple_workers: bool) {
        // disk image size constants
        let original_size = 0x1000;
        let resized_size = 0x2000;

        // Create an empty disk image
        let f = tempfile().unwrap();
        f.set_len(original_size).unwrap();
        let disk_image: Box<dyn DiskFile> = Box::new(f);
        assert_eq!(disk_image.get_len().unwrap(), original_size);

        // Create an empty guest memory
        let mem = GuestMemory::new(&[(GuestAddress(0u64), 4 * 1024 * 1024)])
            .expect("Creating guest memory failed.");

        // Create a control tube
        let (control_tube, control_tube_device) = Tube::pair().unwrap();

        // Create a BlockAsync to test
        let features = base_features(ProtectionType::Unprotected);
        let disk_option = DiskOption {
            multiple_workers: enables_multiple_workers,
            ..Default::default()
        };
        let mut b = BlockAsync::new(
            features,
            disk_image.try_clone().unwrap(),
            &disk_option,
            Some(control_tube_device),
            None,
            None,
        )
        .unwrap();

        // activate with queues of an arbitrary size.
        let mut q0 = QueueConfig::new(DEFAULT_QUEUE_SIZE, 0);
        q0.set_ready(true);
        let q0 = q0
            .activate(&mem, Event::new().unwrap())
            .expect("QueueConfig::activate");

        let mut q1 = QueueConfig::new(DEFAULT_QUEUE_SIZE, 0);
        q1.set_ready(true);
        let q1 = q1
            .activate(&mem, Event::new().unwrap())
            .expect("QueueConfig::activate");

        let interrupt = Interrupt::new(IrqLevelEvent::new().unwrap(), None, VIRTIO_MSI_NO_VECTOR);
        b.activate(mem, interrupt.clone(), BTreeMap::from([(0, q0), (1, q1)]))
            .expect("activate should succeed");

        // assert the original size first
        assert_eq!(
            b.disk_size.load(Ordering::Acquire),
            original_size,
            "disk_size should be the original size first"
        );
        let mut capacity = [0u8; 8];
        b.read_config(0, &mut capacity);
        assert_eq!(
            capacity,
            // original_size (0x1000) >> SECTOR_SHIFT (9) = 0x8
            [0x8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
            "read_config should read the original capacity first"
        );

        // assert resize works
        control_tube
            .send(&DiskControlCommand::Resize {
                new_size: resized_size,
            })
            .unwrap();
        assert_eq!(
            control_tube.recv::<DiskControlResult>().unwrap(),
            DiskControlResult::Ok,
            "resize command should succeed"
        );
        assert_eq!(
            b.disk_size.load(Ordering::Acquire),
            resized_size,
            "disk_size should be resized to the new size"
        );
        assert_eq!(
            disk_image.get_len().unwrap(),
            resized_size,
            "underlying disk image should be resized to the new size"
        );
        let mut capacity = [0u8; 8];
        b.read_config(0, &mut capacity);
        assert_eq!(
            capacity,
            // resized_size (0x2000) >> SECTOR_SHIFT (9) = 0x10
            [0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
            "read_config should read the resized capacity"
        );
        assert_eq!(
            interrupt
                    .get_interrupt_evt()
                    // Wait a bit until the blk signals the interrupt
                    .wait_timeout(Duration::from_millis(300)),
            Ok(base::EventWaitResult::Signaled),
            "interrupt should be signaled"
        );
        assert_eq!(
            interrupt.read_interrupt_status(),
            crate::virtio::INTERRUPT_STATUS_CONFIG_CHANGED as u8,
            "INTERRUPT_STATUS_CONFIG_CHANGED should be signaled"
        );
    }

    // TODO(b/270225199): enable this test on Windows once IoSource::into_source is implemented,
    // or after finding a good way to prevent BlockAsync::drop() from panicking due to that.
    #[cfg(unix)]
    #[test]
    fn run_worker_threads() {
        // Create an empty duplicable disk image
        let f = tempfile().unwrap();
        f.set_len(0x1000).unwrap();
        let disk_image: Box<dyn DiskFile> = Box::new(f);

        // Create an empty guest memory
        let mem = GuestMemory::new(&[(GuestAddress(0u64), 4 * 1024 * 1024)])
            .expect("Creating guest memory failed.");

        // Create a BlockAsync to test with single worker thread
        let features = base_features(ProtectionType::Unprotected);
        let disk_option = DiskOption::default();
        let mut b = BlockAsync::new(
            features,
            disk_image.try_clone().unwrap(),
            &disk_option,
            None,
            None,
            None,
        )
        .unwrap();

        // activate with queues of an arbitrary size.
        let mut q0 = QueueConfig::new(DEFAULT_QUEUE_SIZE, 0);
        q0.set_ready(true);
        let q0 = q0
            .activate(&mem, Event::new().unwrap())
            .expect("QueueConfig::activate");

        let mut q1 = QueueConfig::new(DEFAULT_QUEUE_SIZE, 0);
        q1.set_ready(true);
        let q1 = q1
            .activate(&mem, Event::new().unwrap())
            .expect("QueueConfig::activate");

        b.activate(
            mem.clone(),
            Interrupt::new(IrqLevelEvent::new().unwrap(), None, VIRTIO_MSI_NO_VECTOR),
            BTreeMap::from([(0, q0), (1, q1)]),
        )
        .expect("activate should succeed");

        assert_eq!(b.worker_threads.len(), 1, "1 threads should be spawned.");
        drop(b);

        // Create a BlockAsync to test with multiple worker threads
        let features = base_features(ProtectionType::Unprotected);
        let disk_option = DiskOption {
            read_only: true,
            sparse: false,
            multiple_workers: true,
            ..DiskOption::default()
        };
        let mut b = BlockAsync::new(features, disk_image, &disk_option, None, None, None).unwrap();

        // activate should succeed
        let mut q0 = QueueConfig::new(DEFAULT_QUEUE_SIZE, 0);
        q0.set_ready(true);
        let q0 = q0
            .activate(&mem, Event::new().unwrap())
            .expect("QueueConfig::activate");

        let mut q1 = QueueConfig::new(DEFAULT_QUEUE_SIZE, 0);
        q1.set_ready(true);
        let q1 = q1
            .activate(&mem, Event::new().unwrap())
            .expect("QueueConfig::activate");

        b.activate(
            mem,
            Interrupt::new(IrqLevelEvent::new().unwrap(), None, VIRTIO_MSI_NO_VECTOR),
            BTreeMap::from([(0, q0), (1, q1)]),
        )
        .expect("activate should succeed");

        assert_eq!(b.worker_threads.len(), 2, "2 threads should be spawned.");
    }

    fn modify_device(b: &mut BlockAsync) {
        b.avail_features = !b.avail_features;
    }

    fn create_device() -> BlockAsync {
        // Create an empty disk image
        let f = tempfile().unwrap();
        f.set_len(0x1000).unwrap();
        let disk_image: Box<dyn DiskFile> = Box::new(f);

        // Create a BlockAsync to test
        let features = base_features(ProtectionType::Unprotected);
        let id = b"Block serial number\0";
        let disk_option = DiskOption {
            read_only: true,
            id: Some(*id),
            sparse: false,
            multiple_workers: true,
            ..Default::default()
        };
        BlockAsync::new(
            features,
            disk_image.try_clone().unwrap(),
            &disk_option,
            None,
            None,
            None,
        )
        .unwrap()
    }

    #[cfg(unix)]
    suspendable_virtio_tests!(asyncblock, create_device, 2, modify_device);
}
