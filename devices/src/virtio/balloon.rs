// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

mod sys;

use std::collections::BTreeMap as Map;
use std::collections::VecDeque;
use std::io::Write;
use std::sync::Arc;

use anyhow::anyhow;
use anyhow::Context;
use balloon_control::BalloonStats;
use balloon_control::BalloonTubeCommand;
use balloon_control::BalloonTubeResult;
use balloon_control::BalloonWSS;
use balloon_control::WSSBucket;
use balloon_control::VIRTIO_BALLOON_WS_MAX_NUM_BINS;
use balloon_control::VIRTIO_BALLOON_WS_MIN_NUM_BINS;
use base::error;
use base::info;
use base::warn;
use base::AsRawDescriptor;
use base::Event;
use base::RawDescriptor;
#[cfg(feature = "registered_events")]
use base::SendTube;
use base::Tube;
use base::WorkerThread;
use cros_async::block_on;
use cros_async::sync::RwLock as AsyncRwLock;
use cros_async::AsyncTube;
use cros_async::EventAsync;
use cros_async::Executor;
#[cfg(feature = "registered_events")]
use cros_async::SendTubeAsync;
use data_model::Le16;
use data_model::Le32;
use data_model::Le64;
use futures::channel::mpsc;
use futures::channel::oneshot;
use futures::pin_mut;
use futures::select;
use futures::select_biased;
use futures::FutureExt;
use futures::StreamExt;
use remain::sorted;
use serde::Deserialize;
use serde::Serialize;
use thiserror::Error as ThisError;
#[cfg(windows)]
use vm_control::api::VmMemoryClient;
#[cfg(feature = "registered_events")]
use vm_control::RegisteredEventWithData;
use vm_memory::GuestAddress;
use vm_memory::GuestMemory;
use zerocopy::AsBytes;
use zerocopy::FromBytes;

use super::async_utils;
use super::copy_config;
use super::create_stop_oneshot;
use super::DescriptorChain;
use super::DeviceType;
use super::Interrupt;
use super::Queue;
use super::Reader;
use super::SignalableInterrupt;
use super::VirtioDevice;
use crate::UnpinRequest;
use crate::UnpinResponse;

#[sorted]
#[derive(ThisError, Debug)]
pub enum BalloonError {
    /// Failed an async await
    #[error("failed async await: {0}")]
    AsyncAwait(cros_async::AsyncError),
    /// Failed an async await
    #[error("failed async await: {0}")]
    AsyncAwaitAnyhow(anyhow::Error),
    /// Failed to create event.
    #[error("failed to create event: {0}")]
    CreatingEvent(base::Error),
    /// Failed to create async message receiver.
    #[error("failed to create async message receiver: {0}")]
    CreatingMessageReceiver(base::TubeError),
    /// Failed to receive command message.
    #[error("failed to receive command message: {0}")]
    ReceivingCommand(base::TubeError),
    /// Failed to send command response.
    #[error("failed to send command response: {0}")]
    SendResponse(base::TubeError),
    /// Error while writing to virtqueue
    #[error("failed to write to virtqueue: {0}")]
    WriteQueue(std::io::Error),
    /// Failed to write config event.
    #[error("failed to write config event: {0}")]
    WritingConfigEvent(base::Error),
}
pub type Result<T> = std::result::Result<T, BalloonError>;

// Balloon implements six virt IO queues: Inflate, Deflate, Stats, Event, WssData, WssCmd.
const QUEUE_SIZE: u16 = 128;
const QUEUE_SIZES: &[u16] = &[
    QUEUE_SIZE, QUEUE_SIZE, QUEUE_SIZE, QUEUE_SIZE, QUEUE_SIZE, QUEUE_SIZE,
];

const VIRTIO_BALLOON_PFN_SHIFT: u32 = 12;
const VIRTIO_BALLOON_PF_SIZE: u64 = 1 << VIRTIO_BALLOON_PFN_SHIFT;

// The feature bitmap for virtio balloon
const VIRTIO_BALLOON_F_MUST_TELL_HOST: u32 = 0; // Tell before reclaiming pages
const VIRTIO_BALLOON_F_STATS_VQ: u32 = 1; // Stats reporting enabled
const VIRTIO_BALLOON_F_DEFLATE_ON_OOM: u32 = 2; // Deflate balloon on OOM
const VIRTIO_BALLOON_F_PAGE_REPORTING: u32 = 5; // Page reporting virtqueue
                                                // TODO(b/273973298): this should maybe be bit 6? to be changed later
const VIRTIO_BALLOON_F_WSS_REPORTING: u32 = 8; // Working Set Size reporting virtqueues

#[derive(Copy, Clone)]
#[repr(u32)]
// Balloon virtqueues
pub enum BalloonFeatures {
    // Page Reporting enabled
    PageReporting = VIRTIO_BALLOON_F_PAGE_REPORTING,
    // WSS Reporting enabled
    WSSReporting = VIRTIO_BALLOON_F_WSS_REPORTING,
}

// These feature bits are part of the proposal:
//  https://lists.oasis-open.org/archives/virtio-comment/202201/msg00139.html
const VIRTIO_BALLOON_F_RESPONSIVE_DEVICE: u32 = 6; // Device actively watching guest memory
const VIRTIO_BALLOON_F_EVENTS_VQ: u32 = 7; // Event vq is enabled

// virtio_balloon_config is the balloon device configuration space defined by the virtio spec.
#[derive(Copy, Clone, Debug, Default, AsBytes, FromBytes)]
#[repr(C)]
struct virtio_balloon_config {
    num_pages: Le32,
    actual: Le32,
    free_page_hint_cmd_id: Le32,
    poison_val: Le32,
    // WSS field is part of proposed spec extension (b/273973298).
    wss_num_bins: Le32,
}

// BalloonState is shared by the worker and device thread.
#[derive(Clone, Default, Serialize, Deserialize)]
struct BalloonState {
    num_pages: u32,
    actual_pages: u32,
    expecting_wss: bool,
    expected_wss_id: u64,
    // Flag indicating that the balloon is in the process of a failable update. This
    // is set by an Adjust command that has allow_failure set, and is cleared when the
    // Adjusted success/failure response is sent.
    failable_update: bool,
    pending_adjusted_responses: VecDeque<u32>,
}

// The constants defining stats types in virtio_baloon_stat
const VIRTIO_BALLOON_S_SWAP_IN: u16 = 0;
const VIRTIO_BALLOON_S_SWAP_OUT: u16 = 1;
const VIRTIO_BALLOON_S_MAJFLT: u16 = 2;
const VIRTIO_BALLOON_S_MINFLT: u16 = 3;
const VIRTIO_BALLOON_S_MEMFREE: u16 = 4;
const VIRTIO_BALLOON_S_MEMTOT: u16 = 5;
const VIRTIO_BALLOON_S_AVAIL: u16 = 6;
const VIRTIO_BALLOON_S_CACHES: u16 = 7;
const VIRTIO_BALLOON_S_HTLB_PGALLOC: u16 = 8;
const VIRTIO_BALLOON_S_HTLB_PGFAIL: u16 = 9;
const VIRTIO_BALLOON_S_NONSTANDARD_SHMEM: u16 = 65534;
const VIRTIO_BALLOON_S_NONSTANDARD_UNEVICTABLE: u16 = 65535;

// BalloonStat is used to deserialize stats from the stats_queue.
#[derive(Copy, Clone, FromBytes, AsBytes)]
#[repr(C, packed)]
struct BalloonStat {
    tag: Le16,
    val: Le64,
}

impl BalloonStat {
    fn update_stats(&self, stats: &mut BalloonStats) {
        let val = Some(self.val.to_native());
        match self.tag.to_native() {
            VIRTIO_BALLOON_S_SWAP_IN => stats.swap_in = val,
            VIRTIO_BALLOON_S_SWAP_OUT => stats.swap_out = val,
            VIRTIO_BALLOON_S_MAJFLT => stats.major_faults = val,
            VIRTIO_BALLOON_S_MINFLT => stats.minor_faults = val,
            VIRTIO_BALLOON_S_MEMFREE => stats.free_memory = val,
            VIRTIO_BALLOON_S_MEMTOT => stats.total_memory = val,
            VIRTIO_BALLOON_S_AVAIL => stats.available_memory = val,
            VIRTIO_BALLOON_S_CACHES => stats.disk_caches = val,
            VIRTIO_BALLOON_S_HTLB_PGALLOC => stats.hugetlb_allocations = val,
            VIRTIO_BALLOON_S_HTLB_PGFAIL => stats.hugetlb_failures = val,
            VIRTIO_BALLOON_S_NONSTANDARD_SHMEM => stats.shared_memory = val,
            VIRTIO_BALLOON_S_NONSTANDARD_UNEVICTABLE => stats.unevictable_memory = val,
            _ => (),
        }
    }
}

const VIRTIO_BALLOON_EVENT_PRESSURE: u32 = 1;
const VIRTIO_BALLOON_EVENT_PUFF_FAILURE: u32 = 2;

#[repr(C)]
#[derive(Copy, Clone, Default, AsBytes, FromBytes)]
struct virtio_balloon_event_header {
    evt_type: Le32,
}

// virtio_balloon_wss is used to deserialize from the wss data vq.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default, AsBytes, FromBytes)]
struct virtio_balloon_wss {
    tag: Le16,
    node_id: Le16,
    // virtio prefers field members to align on a word boundary so we must pad. see:
    // https://crsrc.org/o/src/third_party/kernel/v5.15/include/uapi/linux/virtio_balloon.h;l=105
    _reserved: [u8; 4],
    idle_age_ms: Le64,
    // TODO(b/273973298): these should become separate fields - bytes for ANON and FILE
    memory_size_bytes: [Le64; 2],
}

impl virtio_balloon_wss {
    fn update_wss(&self, wss: &mut BalloonWSS) {
        let bucket = WSSBucket {
            age: self.idle_age_ms.to_native(),
            bytes: [
                self.memory_size_bytes[0].to_native(),
                self.memory_size_bytes[1].to_native(),
            ],
        };
        wss.wss.push(bucket);
    }
}

const _VIRTIO_BALLOON_WSS_OP_INVALID: u16 = 0;
const VIRTIO_BALLOON_WSS_OP_REQUEST: u16 = 1;
const VIRTIO_BALLOON_WSS_OP_CONFIG: u16 = 2;
const _VIRTIO_BALLOON_WSS_OP_DISCARD: u16 = 3;

// virtio_balloon_op is used to serialize to the wss cmd vq.
#[repr(C, packed)]
#[derive(Copy, Clone, Debug, Default, AsBytes, FromBytes)]
struct virtio_balloon_op {
    type_: Le16,
}

fn invoke_desc_handler<F>(ranges: Vec<(u64, u64)>, desc_handler: &mut F)
where
    F: FnMut(GuestAddress, u64),
{
    for range in ranges {
        desc_handler(GuestAddress(range.0), range.1);
    }
}

// Release a list of guest memory ranges back to the host system.
// Unpin requests for each inflate range will be sent via `release_memory_tube`
// if provided, and then `desc_handler` will be called for each inflate range.
fn release_ranges<F>(
    release_memory_tube: Option<&Tube>,
    inflate_ranges: Vec<(u64, u64)>,
    desc_handler: &mut F,
) -> anyhow::Result<()>
where
    F: FnMut(GuestAddress, u64),
{
    if let Some(tube) = release_memory_tube {
        let unpin_ranges = inflate_ranges
            .iter()
            .map(|v| {
                (
                    v.0 >> VIRTIO_BALLOON_PFN_SHIFT,
                    v.1 / VIRTIO_BALLOON_PF_SIZE,
                )
            })
            .collect();
        let req = UnpinRequest {
            ranges: unpin_ranges,
        };
        if let Err(e) = tube.send(&req) {
            error!("failed to send unpin request: {}", e);
        } else {
            match tube.recv() {
                Ok(resp) => match resp {
                    UnpinResponse::Success => invoke_desc_handler(inflate_ranges, desc_handler),
                    UnpinResponse::Failed => error!("failed to handle unpin request"),
                },
                Err(e) => error!("failed to handle get unpin response: {}", e),
            }
        }
    } else {
        invoke_desc_handler(inflate_ranges, desc_handler);
    }

    Ok(())
}

// Processes one message's list of addresses.
fn handle_address_chain<F>(
    release_memory_tube: Option<&Tube>,
    avail_desc: &mut DescriptorChain,
    desc_handler: &mut F,
) -> anyhow::Result<()>
where
    F: FnMut(GuestAddress, u64),
{
    // In a long-running system, there is no reason to expect that
    // a significant number of freed pages are consecutive. However,
    // batching is relatively simple and can result in significant
    // gains in a newly booted system, so it's worth attempting.
    let mut range_start = 0;
    let mut range_size = 0;
    let mut inflate_ranges: Vec<(u64, u64)> = Vec::new();
    for res in avail_desc.reader.iter::<Le32>() {
        let pfn = match res {
            Ok(pfn) => pfn,
            Err(e) => {
                error!("error while reading unused pages: {}", e);
                break;
            }
        };
        let guest_address = (u64::from(pfn.to_native())) << VIRTIO_BALLOON_PFN_SHIFT;
        if range_start + range_size == guest_address {
            range_size += VIRTIO_BALLOON_PF_SIZE;
        } else if range_start == guest_address + VIRTIO_BALLOON_PF_SIZE {
            range_start = guest_address;
            range_size += VIRTIO_BALLOON_PF_SIZE;
        } else {
            // Discontinuity, so flush the previous range. Note range_size
            // will be 0 on the first iteration, so skip that.
            if range_size != 0 {
                inflate_ranges.push((range_start, range_size));
            }
            range_start = guest_address;
            range_size = VIRTIO_BALLOON_PF_SIZE;
        }
    }
    if range_size != 0 {
        inflate_ranges.push((range_start, range_size));
    }

    release_ranges(release_memory_tube, inflate_ranges, desc_handler)
}

// Async task that handles the main balloon inflate and deflate queues.
async fn handle_queue<F>(
    mem: &GuestMemory,
    mut queue: Queue,
    mut queue_event: EventAsync,
    release_memory_tube: Option<&Tube>,
    interrupt: Interrupt,
    mut desc_handler: F,
    mut stop_rx: oneshot::Receiver<()>,
) -> Queue
where
    F: FnMut(GuestAddress, u64),
{
    loop {
        let mut avail_desc = match queue
            .next_async_interruptable(mem, &mut queue_event, &mut stop_rx)
            .await
        {
            Ok(Some(res)) => res,
            Ok(None) => return queue,
            Err(e) => {
                error!("Failed to read descriptor {}", e);
                return queue;
            }
        };
        if let Err(e) =
            handle_address_chain(release_memory_tube, &mut avail_desc, &mut desc_handler)
        {
            error!("balloon: failed to process inflate addresses: {}", e);
        }
        queue.add_used(mem, avail_desc, 0);
        queue.trigger_interrupt(mem, &interrupt);
    }
}

// Processes one page-reporting descriptor.
fn handle_reported_buffer<F>(
    release_memory_tube: Option<&Tube>,
    avail_desc: &DescriptorChain,
    desc_handler: &mut F,
) -> anyhow::Result<()>
where
    F: FnMut(GuestAddress, u64),
{
    let reported_ranges: Vec<(u64, u64)> = avail_desc
        .reader
        .get_remaining_regions()
        .iter()
        .chain(avail_desc.writer.get_remaining_regions().iter())
        .map(|r| (r.offset, r.len as u64))
        .collect();

    release_ranges(release_memory_tube, reported_ranges, desc_handler)
}

// Async task that handles the page reporting queue.
async fn handle_reporting_queue<F>(
    mem: &GuestMemory,
    mut queue: Queue,
    mut queue_event: EventAsync,
    release_memory_tube: Option<&Tube>,
    interrupt: Interrupt,
    mut desc_handler: F,
    mut stop_rx: oneshot::Receiver<()>,
) -> Queue
where
    F: FnMut(GuestAddress, u64),
{
    loop {
        let avail_desc = match queue
            .next_async_interruptable(mem, &mut queue_event, &mut stop_rx)
            .await
        {
            Ok(Some(res)) => res,
            Ok(None) => return queue,
            Err(e) => {
                error!("Failed to read descriptor {}", e);
                return queue;
            }
        };
        if let Err(e) = handle_reported_buffer(release_memory_tube, &avail_desc, &mut desc_handler)
        {
            error!("balloon: failed to process reported buffer: {}", e);
        }
        queue.add_used(mem, avail_desc, 0);
        queue.trigger_interrupt(mem, &interrupt);
    }
}

fn parse_balloon_stats(reader: &mut Reader) -> BalloonStats {
    let mut stats: BalloonStats = Default::default();
    for res in reader.iter::<BalloonStat>() {
        match res {
            Ok(stat) => stat.update_stats(&mut stats),
            Err(e) => {
                error!("error while reading stats: {}", e);
                break;
            }
        };
    }
    stats
}

// Async task that handles the stats queue. Note that the cadence of this is driven by requests for
// balloon stats from the control pipe.
// The guests queues an initial buffer on boot, which is read and then this future will block until
// signaled from the command socket that stats should be collected again.
async fn handle_stats_queue(
    mem: &GuestMemory,
    mut queue: Queue,
    mut queue_event: EventAsync,
    mut stats_rx: mpsc::Receiver<u64>,
    command_tube: &AsyncTube,
    #[cfg(feature = "registered_events")] registered_evt_q: Option<&SendTubeAsync>,
    state: Arc<AsyncRwLock<BalloonState>>,
    interrupt: Interrupt,
    mut stop_rx: oneshot::Receiver<()>,
) -> Queue {
    let mut avail_desc = match queue
        .next_async_interruptable(mem, &mut queue_event, &mut stop_rx)
        .await
    {
        // Consume the first stats buffer sent from the guest at startup. It was not
        // requested by anyone, and the stats are stale.
        Ok(Some(res)) => res,
        Ok(None) => return queue,
        Err(e) => {
            error!("Failed to read descriptor {}", e);
            return queue;
        }
    };

    loop {
        let id = select_biased! {
            id_res = stats_rx.next() => {
                // Wait for a request to read the stats.
                match id_res {
                    Some(id) => id,
                    None => {
                        error!("stats signal tube was closed");
                        return queue;
                    }
                }
            }
            _ = stop_rx => return queue,
        };

        // Request a new stats_desc to the guest.
        queue.add_used(mem, avail_desc, 0);
        queue.trigger_interrupt(mem, &interrupt);

        avail_desc = match queue.next_async(mem, &mut queue_event).await {
            Err(e) => {
                error!("Failed to read descriptor {}", e);
                return queue;
            }
            Ok(d) => d,
        };
        let stats = parse_balloon_stats(&mut avail_desc.reader);

        let actual_pages = state.lock().await.actual_pages as u64;
        let result = BalloonTubeResult::Stats {
            balloon_actual: actual_pages << VIRTIO_BALLOON_PFN_SHIFT,
            stats,
            id,
        };
        let send_result = command_tube.send(result).await;
        if let Err(e) = send_result {
            error!("failed to send stats result: {}", e);
        }

        #[cfg(feature = "registered_events")]
        if let Some(registered_evt_q) = registered_evt_q {
            if let Err(e) = registered_evt_q
                .send(&RegisteredEventWithData::VirtioBalloonResize)
                .await
            {
                error!("failed to send VirtioBalloonResize event: {}", e);
            }
        }
    }
}

async fn send_adjusted_response(
    tube: &AsyncTube,
    num_pages: u32,
) -> std::result::Result<(), base::TubeError> {
    let num_bytes = (num_pages as u64) << VIRTIO_BALLOON_PFN_SHIFT;
    let result = BalloonTubeResult::Adjusted { num_bytes };
    tube.send(result).await
}

async fn handle_event(
    state: Arc<AsyncRwLock<BalloonState>>,
    interrupt: Interrupt,
    r: &mut Reader,
    command_tube: &AsyncTube,
) -> Result<()> {
    match r.read_obj::<virtio_balloon_event_header>() {
        Ok(hdr) => match hdr.evt_type.to_native() {
            VIRTIO_BALLOON_EVENT_PRESSURE => {
                // TODO(b/213962590): See how this can be integrated this into memory rebalancing
            }
            VIRTIO_BALLOON_EVENT_PUFF_FAILURE => {
                let mut state = state.lock().await;
                if state.failable_update {
                    state.num_pages = state.actual_pages;
                    interrupt.signal_config_changed();

                    state.failable_update = false;
                    send_adjusted_response(command_tube, state.actual_pages)
                        .await
                        .map_err(BalloonError::SendResponse)?;
                }
            }
            _ => {
                warn!("Unknown event {}", hdr.evt_type.to_native());
            }
        },
        Err(e) => error!("Failed to parse event header {:?}", e),
    }
    Ok(())
}

// Async task that handles the events queue.
async fn handle_events_queue(
    mem: &GuestMemory,
    mut queue: Queue,
    mut queue_event: EventAsync,
    state: Arc<AsyncRwLock<BalloonState>>,
    interrupt: Interrupt,
    command_tube: &AsyncTube,
    mut stop_rx: oneshot::Receiver<()>,
) -> Result<Queue> {
    while let Some(mut avail_desc) = queue
        .next_async_interruptable(mem, &mut queue_event, &mut stop_rx)
        .await
        .map_err(BalloonError::AsyncAwait)?
    {
        handle_event(
            state.clone(),
            interrupt.clone(),
            &mut avail_desc.reader,
            command_tube,
        )
        .await?;

        queue.add_used(mem, avail_desc, 0);
        queue.trigger_interrupt(mem, &interrupt);
    }
    Ok(queue)
}

enum WSSOp {
    WSSReport {
        id: u64,
    },
    WSSConfig {
        bins: Vec<u64>,
        refresh_threshold: u64,
        report_threshold: u64,
    },
}

async fn handle_wss_op_queue(
    mem: &GuestMemory,
    mut queue: Queue,
    mut queue_event: EventAsync,
    mut wss_op_rx: mpsc::Receiver<WSSOp>,
    state: Arc<AsyncRwLock<BalloonState>>,
    interrupt: Interrupt,
    mut stop_rx: oneshot::Receiver<()>,
) -> Result<Queue> {
    loop {
        let op = select_biased! {
            next_op = wss_op_rx.next().fuse() => {
                match next_op {
                    Some(op) => op,
                    None => {
                        error!("wss op tube was closed");
                        break;
                    }
                }
            }
            _ = stop_rx => {
                break;
            }
        };
        let mut avail_desc = queue
            .next_async(mem, &mut queue_event)
            .await
            .map_err(BalloonError::AsyncAwait)?;
        let writer = &mut avail_desc.writer;

        match op {
            WSSOp::WSSReport { id } => {
                {
                    let mut state = state.lock().await;
                    state.expecting_wss = true;
                    state.expected_wss_id = id;
                }

                let wss_r = virtio_balloon_op {
                    type_: VIRTIO_BALLOON_WSS_OP_REQUEST.into(),
                };

                writer.write_obj(wss_r).map_err(BalloonError::WriteQueue)?;
            }
            WSSOp::WSSConfig {
                bins,
                refresh_threshold,
                report_threshold,
            } => {
                let cmd = virtio_balloon_op {
                    type_: VIRTIO_BALLOON_WSS_OP_CONFIG.into(),
                };

                writer.write_obj(cmd).map_err(BalloonError::WriteQueue)?;
                writer
                    .write_all(bins.as_bytes())
                    .map_err(BalloonError::WriteQueue)?;
                writer
                    .write_obj(refresh_threshold)
                    .map_err(BalloonError::WriteQueue)?;
                writer
                    .write_obj(report_threshold)
                    .map_err(BalloonError::WriteQueue)?;
            }
        }

        let len = writer.bytes_written() as u32;
        queue.add_used(mem, avail_desc, len);
        queue.trigger_interrupt(mem, &interrupt);
    }

    Ok(queue)
}

fn parse_balloon_wss(reader: &mut Reader) -> BalloonWSS {
    let mut wss = BalloonWSS::new();
    for res in reader.iter::<virtio_balloon_wss>() {
        match res {
            Ok(wss_msg) => {
                wss_msg.update_wss(&mut wss);
            }
            Err(e) => {
                error!("error while reading wss: {}", e);
                break;
            }
        }
    }
    if wss.wss.len() < VIRTIO_BALLOON_WS_MIN_NUM_BINS
        || wss.wss.len() > VIRTIO_BALLOON_WS_MAX_NUM_BINS
    {
        error!("unexpected number of WSS buckets: {}", wss.wss.len());
    }
    wss
}

// Async task that handles the stats queue. Note that the arrival of events on
// the WSS vq may be the result of either a WSS request (WSS-R) command having
// been sent to the guest, or an unprompted send due to memory pressue in the
// guest. If the data was requested, we should also send that back on the
// command tube.
async fn handle_wss_data_queue(
    mem: &GuestMemory,
    mut queue: Queue,
    mut queue_event: EventAsync,
    command_tube: &AsyncTube,
    #[cfg(feature = "registered_events")] registered_evt_q: Option<&SendTubeAsync>,
    state: Arc<AsyncRwLock<BalloonState>>,
    interrupt: Interrupt,
    mut stop_rx: oneshot::Receiver<()>,
) -> Result<Queue> {
    loop {
        let mut avail_desc = match queue
            .next_async_interruptable(mem, &mut queue_event, &mut stop_rx)
            .await
            .map_err(BalloonError::AsyncAwait)?
        {
            Some(res) => res,
            None => return Ok(queue),
        };

        let wss = parse_balloon_wss(&mut avail_desc.reader);

        let mut state = state.lock().await;

        // update wss report with balloon pages now that we have a lock on state
        let balloon_actual = (state.actual_pages as u64) << VIRTIO_BALLOON_PFN_SHIFT;

        if state.expecting_wss {
            let result = BalloonTubeResult::WorkingSetSize {
                wss,
                balloon_actual,
                id: state.expected_wss_id,
            };
            let send_result = command_tube.send(result).await;
            if let Err(e) = send_result {
                error!("failed to send wss result: {}", e);
            }

            state.expecting_wss = false;
        } else {
            #[cfg(feature = "registered_events")]
            if let Some(registered_evt_q) = registered_evt_q {
                if let Err(e) = registered_evt_q
                    .send(RegisteredEventWithData::from_wss(&wss, balloon_actual))
                    .await
                {
                    error!("failed to send VirtioBalloonWSSReport event: {}", e);
                }
            }
        }

        queue.add_used(mem, avail_desc, 0);
        queue.trigger_interrupt(mem, &interrupt);
    }
}

// Async task that handles the command socket. The command socket handles messages from the host
// requesting that the guest balloon be adjusted or to report guest memory statistics.
async fn handle_command_tube(
    command_tube: &AsyncTube,
    interrupt: Interrupt,
    state: Arc<AsyncRwLock<BalloonState>>,
    mut stats_tx: mpsc::Sender<u64>,
    mut wss_op_tx: mpsc::Sender<WSSOp>,
) -> Result<()> {
    loop {
        match command_tube.next().await {
            Ok(command) => match command {
                BalloonTubeCommand::Adjust {
                    num_bytes,
                    allow_failure,
                } => {
                    let num_pages = (num_bytes >> VIRTIO_BALLOON_PFN_SHIFT) as u32;
                    let mut state = state.lock().await;

                    state.num_pages = num_pages;
                    interrupt.signal_config_changed();

                    if allow_failure {
                        if num_pages == state.actual_pages {
                            send_adjusted_response(command_tube, num_pages)
                                .await
                                .map_err(BalloonError::SendResponse)?;
                        } else {
                            state.failable_update = true;
                        }
                    }
                }
                BalloonTubeCommand::WorkingSetSizeConfig {
                    bins,
                    refresh_threshold,
                    report_threshold,
                } => {
                    if let Err(e) = wss_op_tx.try_send(WSSOp::WSSConfig {
                        bins,
                        refresh_threshold,
                        report_threshold,
                    }) {
                        error!("failed to send config to wss handler: {}", e);
                    }
                }
                BalloonTubeCommand::Stats { id } => {
                    if let Err(e) = stats_tx.try_send(id) {
                        error!("failed to signal the stat handler: {}", e);
                    }
                }
                BalloonTubeCommand::WorkingSetSize { id } => {
                    if let Err(e) = wss_op_tx.try_send(WSSOp::WSSReport { id }) {
                        error!("failed to send report request to wss handler: {}", e);
                    }
                }
            },
            Err(e) => {
                return Err(BalloonError::ReceivingCommand(e));
            }
        }
    }
}

async fn handle_pending_adjusted_responses(
    pending_adjusted_response_event: EventAsync,
    command_tube: &AsyncTube,
    state: Arc<AsyncRwLock<BalloonState>>,
) -> Result<()> {
    loop {
        pending_adjusted_response_event
            .next_val()
            .await
            .map_err(BalloonError::AsyncAwait)?;
        while let Some(num_pages) = state.lock().await.pending_adjusted_responses.pop_front() {
            send_adjusted_response(command_tube, num_pages)
                .await
                .map_err(BalloonError::SendResponse)?;
        }
    }
}

/// Represents queues & events for the balloon device.
struct BalloonQueues {
    inflate: (Queue, Event),
    deflate: (Queue, Event),
    stats: Option<(Queue, Event)>,
    reporting: Option<(Queue, Event)>,
    events: Option<(Queue, Event)>,
    wss: (Option<(Queue, Event)>, Option<(Queue, Event)>),
}

impl BalloonQueues {
    fn new(inflate: (Queue, Event), deflate: (Queue, Event)) -> Self {
        BalloonQueues {
            inflate,
            deflate,
            stats: None,
            reporting: None,
            events: None,
            wss: (None, None),
        }
    }
}

impl From<Map<usize, (Queue, Event)>> for BalloonQueues {
    fn from(mut queues: Map<usize, (Queue, Event)>) -> Self {
        BalloonQueues {
            inflate: queues.remove(&0).expect("the inflate queue is required"),
            deflate: queues.remove(&1).expect("the deflate queue is required"),
            stats: queues.remove(&2),
            reporting: queues.remove(&3),
            events: queues.remove(&4),
            wss: (queues.remove(&5), queues.remove(&6)),
        }
    }
}

/// When the worker is stopped, the queues are preserved here.
struct PausedQueues {
    inflate: Queue,
    deflate: Queue,
    stats: Option<Queue>,
    reporting: Option<Queue>,
    events: Option<Queue>,
    wss: (Option<Queue>, Option<Queue>),
}

impl PausedQueues {
    fn new(inflate: Queue, deflate: Queue) -> Self {
        PausedQueues {
            inflate,
            deflate,
            stats: None,
            reporting: None,
            events: None,
            wss: (None, None),
        }
    }
}

fn apply_if_some<F, R>(queue_opt: Option<Queue>, mut func: F)
where
    F: FnMut(Queue) -> R,
{
    if let Some(queue) = queue_opt {
        func(queue);
    }
}

impl From<Box<PausedQueues>> for Map<usize, Queue> {
    fn from(queues: Box<PausedQueues>) -> Map<usize, Queue> {
        let mut ret = Map::new();
        ret.insert(0, queues.inflate);
        ret.insert(1, queues.deflate);
        apply_if_some(queues.stats, |stats| ret.insert(2, stats));
        apply_if_some(queues.reporting, |reporting| ret.insert(3, reporting));
        apply_if_some(queues.events, |events| ret.insert(4, events));
        apply_if_some(queues.wss.0, |wss_data| ret.insert(5, wss_data));
        apply_if_some(queues.wss.1, |wss_op| ret.insert(6, wss_op));
        ret
    }
}

/// Stores data from the worker when it stops so that data can be re-used when
/// the worker is restarted.
struct WorkerReturn {
    release_memory_tube: Option<Tube>,
    command_tube: Tube,
    #[cfg(feature = "registered_events")]
    registered_evt_q: Option<SendTube>,
    paused_queues: Option<PausedQueues>,
    #[cfg(windows)]
    vm_memory_client: VmMemoryClient,
}

// The main worker thread. Initialized the asynchronous worker tasks and passes them to the executor
// to be processed.
fn run_worker(
    inflate_queue: (Queue, Event),
    deflate_queue: (Queue, Event),
    stats_queue: Option<(Queue, Event)>,
    reporting_queue: Option<(Queue, Event)>,
    events_queue: Option<(Queue, Event)>,
    wss_queues: (Option<(Queue, Event)>, Option<(Queue, Event)>),
    command_tube: Tube,
    #[cfg(windows)] vm_memory_client: VmMemoryClient,
    release_memory_tube: Option<Tube>,
    interrupt: Interrupt,
    kill_evt: Event,
    target_reached_evt: Event,
    pending_adjusted_response_event: Event,
    mem: GuestMemory,
    state: Arc<AsyncRwLock<BalloonState>>,
    #[cfg(feature = "registered_events")] registered_evt_q: Option<SendTube>,
) -> WorkerReturn {
    let ex = Executor::new().unwrap();
    let command_tube = AsyncTube::new(&ex, command_tube).unwrap();
    #[cfg(feature = "registered_events")]
    let registered_evt_q_async = registered_evt_q
        .as_ref()
        .map(|q| SendTubeAsync::new(q.try_clone().unwrap(), &ex).unwrap());

    let mut stop_queue_oneshots = Vec::new();

    // We need a block to release all references to command_tube at the end before returning it.
    let paused_queues = {
        // The first queue is used for inflate messages
        let stop_rx = create_stop_oneshot(&mut stop_queue_oneshots);
        let inflate = handle_queue(
            &mem,
            inflate_queue.0,
            EventAsync::new(inflate_queue.1, &ex).expect("failed to create async event"),
            release_memory_tube.as_ref(),
            interrupt.clone(),
            |guest_address, len| {
                sys::free_memory(
                    &guest_address,
                    len,
                    #[cfg(windows)]
                    &vm_memory_client,
                    #[cfg(unix)]
                    &mem,
                )
            },
            stop_rx,
        );
        let inflate = inflate.fuse();
        pin_mut!(inflate);

        // The second queue is used for deflate messages
        let stop_rx = create_stop_oneshot(&mut stop_queue_oneshots);
        let deflate = handle_queue(
            &mem,
            deflate_queue.0,
            EventAsync::new(deflate_queue.1, &ex).expect("failed to create async event"),
            None,
            interrupt.clone(),
            |guest_address, len| {
                sys::reclaim_memory(
                    &guest_address,
                    len,
                    #[cfg(windows)]
                    &vm_memory_client,
                )
            },
            stop_rx,
        );
        let deflate = deflate.fuse();
        pin_mut!(deflate);

        // The next queue is used for stats messages if VIRTIO_BALLOON_F_STATS_VQ is negotiated.
        // The message type is the id of the stats request, so we can detect if there are any stale
        // stats results that were queued during an error condition.
        let (stats_tx, stats_rx) = mpsc::channel::<u64>(1);
        let has_stats_queue = stats_queue.is_some();
        let stats = if let Some((stats_queue, stats_queue_evt)) = stats_queue {
            let stop_rx = create_stop_oneshot(&mut stop_queue_oneshots);
            handle_stats_queue(
                &mem,
                stats_queue,
                EventAsync::new(stats_queue_evt, &ex).expect("failed to create async event"),
                stats_rx,
                &command_tube,
                #[cfg(feature = "registered_events")]
                registered_evt_q_async.as_ref(),
                state.clone(),
                interrupt.clone(),
                stop_rx,
            )
            .left_future()
        } else {
            std::future::pending().right_future()
        };
        let stats = stats.fuse();
        pin_mut!(stats);

        // The next queue is used for reporting messages
        let has_reporting_queue = reporting_queue.is_some();
        let reporting = if let Some((reporting_queue, reporting_queue_evt)) = reporting_queue {
            let stop_rx = create_stop_oneshot(&mut stop_queue_oneshots);
            handle_reporting_queue(
                &mem,
                reporting_queue,
                EventAsync::new(reporting_queue_evt, &ex).expect("failed to create async event"),
                release_memory_tube.as_ref(),
                interrupt.clone(),
                |guest_address, len| {
                    sys::free_memory(
                        &guest_address,
                        len,
                        #[cfg(windows)]
                        &vm_memory_client,
                        #[cfg(unix)]
                        &mem,
                    )
                },
                stop_rx,
            )
            .left_future()
        } else {
            std::future::pending().right_future()
        };
        let reporting = reporting.fuse();
        pin_mut!(reporting);

        // If VIRTIO_BALLOON_F_WSS_REPORTING is set 2 queues must handled - one for WSS data and one
        // for WSS notifications.
        let has_wss_data_queue = wss_queues.0.is_some();
        let wss_data = if let Some((wss_data_queue, wss_data_queue_evt)) = wss_queues.0 {
            let stop_rx = create_stop_oneshot(&mut stop_queue_oneshots);
            handle_wss_data_queue(
                &mem,
                wss_data_queue,
                EventAsync::new(wss_data_queue_evt, &ex).expect("failed to create async event"),
                &command_tube,
                #[cfg(feature = "registered_events")]
                registered_evt_q_async.as_ref(),
                state.clone(),
                interrupt.clone(),
                stop_rx,
            )
            .left_future()
        } else {
            std::future::pending().right_future()
        };
        let wss_data = wss_data.fuse();
        pin_mut!(wss_data);

        let (wss_op_tx, wss_op_rx) = mpsc::channel::<WSSOp>(1);
        let has_wss_op_queue = wss_queues.1.is_some();
        let wss_op = if let Some((wss_op_queue, wss_op_queue_evt)) = wss_queues.1 {
            let stop_rx = create_stop_oneshot(&mut stop_queue_oneshots);
            handle_wss_op_queue(
                &mem,
                wss_op_queue,
                EventAsync::new(wss_op_queue_evt, &ex).expect("failed to create async event"),
                wss_op_rx,
                state.clone(),
                interrupt.clone(),
                stop_rx,
            )
            .left_future()
        } else {
            std::future::pending().right_future()
        };
        let wss_op = wss_op.fuse();
        pin_mut!(wss_op);

        // Future to handle command messages that resize the balloon.
        let command = handle_command_tube(
            &command_tube,
            interrupt.clone(),
            state.clone(),
            stats_tx,
            wss_op_tx,
        );
        pin_mut!(command);

        // Process any requests to resample the irq value.
        let resample = async_utils::handle_irq_resample(&ex, interrupt.clone());
        pin_mut!(resample);

        // Send a message if balloon target reached event is triggered.
        let target_reached = handle_target_reached(
            &ex,
            target_reached_evt,
            #[cfg(windows)]
            &vm_memory_client,
        );
        pin_mut!(target_reached);

        // Exit if the kill event is triggered.
        let kill = async_utils::await_and_exit(&ex, kill_evt);
        pin_mut!(kill);

        // The next queue is used for events if VIRTIO_BALLOON_F_EVENTS_VQ is negotiated.
        let has_events_queue = events_queue.is_some();
        let events = if let Some((events_queue, events_queue_evt)) = events_queue {
            let stop_rx = create_stop_oneshot(&mut stop_queue_oneshots);
            handle_events_queue(
                &mem,
                events_queue,
                EventAsync::new(events_queue_evt, &ex).expect("failed to create async event"),
                state.clone(),
                interrupt,
                &command_tube,
                stop_rx,
            )
            .left_future()
        } else {
            std::future::pending().right_future()
        };
        let events = events.fuse();
        pin_mut!(events);

        let pending_adjusted = handle_pending_adjusted_responses(
            EventAsync::new(pending_adjusted_response_event, &ex)
                .expect("failed to create async event"),
            &command_tube,
            state,
        );
        pin_mut!(pending_adjusted);

        let res = ex.run_until(async {
            select! {
                _ = kill.fuse() => (),
                _ = inflate => return Err(anyhow!("inflate stopped unexpectedly")),
                _ = deflate => return Err(anyhow!("deflate stopped unexpectedly")),
                _ = stats => return Err(anyhow!("stats stopped unexpectedly")),
                _ = reporting => return Err(anyhow!("reporting stopped unexpectedly")),
                _ = command.fuse() => return Err(anyhow!("command stopped unexpectedly")),
                _ = wss_op => return Err(anyhow!("wss_op stopped unexpectedly")),
                _ = resample.fuse() => return Err(anyhow!("resample stopped unexpectedly")),
                _ = events => return Err(anyhow!("events stopped unexpectedly")),
                _ = pending_adjusted.fuse() => return Err(anyhow!("pending_adjusted stopped unexpectedly")),
                _ = wss_data => return Err(anyhow!("wss_data stopped unexpectedly")),
                _ = target_reached.fuse() => return Err(anyhow!("target_reached stopped unexpectedly")),
            }

            // Worker is shutting down. To recover the queues, we have to signal
            // all the queue futures to exit.
            for stop_tx in stop_queue_oneshots {
                if stop_tx.send(()).is_err() {
                    return Err(anyhow!("failed to request stop for queue future"));
                }
            }

            // Collect all the queues (awaiting any queue future should now
            // return its Queue immediately).
            let mut paused_queues = PausedQueues::new(
                inflate.await,
                deflate.await,
            );
            if has_reporting_queue {
                paused_queues.reporting = Some(reporting.await);
            }
            if has_events_queue {
                paused_queues.events = Some(events.await.context("failed to stop events queue")?);
            }
            if has_stats_queue {
                paused_queues.stats = Some(stats.await);
            }
            if has_wss_op_queue {
                paused_queues.wss.0 = Some(wss_op.await.context("failed to stop wss_op queue")?);
            }
            if has_wss_data_queue {
                paused_queues.wss.1 = Some(wss_data.await.context("failed to stop wss_data queue")?);
            }
            Ok(paused_queues)
        });

        match res {
            Err(e) => {
                error!("error happened in executor: {}", e);
                None
            }
            Ok(main_future_res) => match main_future_res {
                Ok(paused_queues) => Some(paused_queues),
                Err(e) => {
                    error!("error happened in main balloon future: {}", e);
                    None
                }
            },
        }
    };

    WorkerReturn {
        command_tube: command_tube.into(),
        paused_queues,
        release_memory_tube,
        #[cfg(feature = "registered_events")]
        registered_evt_q,
        #[cfg(windows)]
        vm_memory_client,
    }
}

async fn handle_target_reached(
    ex: &Executor,
    target_reached_evt: Event,
    #[cfg(windows)] vm_memory_client: &VmMemoryClient,
) -> anyhow::Result<()> {
    let event_async =
        EventAsync::new(target_reached_evt, ex).context("failed to create EventAsync")?;
    loop {
        // Wait for target reached trigger.
        let _ = event_async.next_val().await;
        // Send the message to vm_control on the event. We don't have to read the current
        // size yet.
        sys::balloon_target_reached(
            0,
            #[cfg(windows)]
            vm_memory_client,
        );
    }
    // The above loop will never terminate and there is no reason to terminate it either. However,
    // the function is used in an executor that expects a Result<> return. Make sure that clippy
    // doesn't enforce the unreachable_code condition.
    #[allow(unreachable_code)]
    Ok(())
}

/// Virtio device for memory balloon inflation/deflation.
pub struct Balloon {
    command_tube: Option<Tube>,
    #[cfg(windows)]
    vm_memory_client: Option<VmMemoryClient>,
    release_memory_tube: Option<Tube>,
    pending_adjusted_response_event: Event,
    state: Arc<AsyncRwLock<BalloonState>>,
    features: u64,
    acked_features: u64,
    worker_thread: Option<WorkerThread<WorkerReturn>>,
    #[cfg(feature = "registered_events")]
    registered_evt_q: Option<SendTube>,
    wss_num_bins: u8,
    target_reached_evt: Option<Event>,
}

/// Snapshot of the [Balloon] state.
#[derive(Serialize, Deserialize)]
struct BalloonSnapshot {
    state: BalloonState,
    features: u64,
    acked_features: u64,
    wss_num_bins: u8,
}

/// Operation mode of the balloon.
#[derive(PartialEq, Eq)]
pub enum BalloonMode {
    /// The driver can access pages in the balloon (i.e. F_DEFLATE_ON_OOM)
    Relaxed,
    /// The driver cannot access pages in the balloon. Implies F_RESPONSIVE_DEVICE.
    Strict,
}

impl Balloon {
    /// Creates a new virtio balloon device.
    /// To let Balloon able to successfully release the memory which are pinned
    /// by CoIOMMU to host, the release_memory_tube will be used to send the inflate
    /// ranges to CoIOMMU with UnpinRequest/UnpinResponse messages, so that The
    /// memory in the inflate range can be unpinned first.
    pub fn new(
        base_features: u64,
        command_tube: Tube,
        #[cfg(windows)] vm_memory_client: VmMemoryClient,
        release_memory_tube: Option<Tube>,
        init_balloon_size: u64,
        mode: BalloonMode,
        enabled_features: u64,
        #[cfg(feature = "registered_events")] registered_evt_q: Option<SendTube>,
        wss_num_bins: u8,
    ) -> Result<Balloon> {
        let features = base_features
            | 1 << VIRTIO_BALLOON_F_MUST_TELL_HOST
            | 1 << VIRTIO_BALLOON_F_STATS_VQ
            | 1 << VIRTIO_BALLOON_F_EVENTS_VQ
            | enabled_features
            | if mode == BalloonMode::Strict {
                1 << VIRTIO_BALLOON_F_RESPONSIVE_DEVICE
            } else {
                1 << VIRTIO_BALLOON_F_DEFLATE_ON_OOM
            };

        Ok(Balloon {
            command_tube: Some(command_tube),
            #[cfg(windows)]
            vm_memory_client: Some(vm_memory_client),
            release_memory_tube,
            pending_adjusted_response_event: Event::new().map_err(BalloonError::CreatingEvent)?,
            state: Arc::new(AsyncRwLock::new(BalloonState {
                num_pages: (init_balloon_size >> VIRTIO_BALLOON_PFN_SHIFT) as u32,
                actual_pages: 0,
                failable_update: false,
                pending_adjusted_responses: VecDeque::new(),
                expecting_wss: false,
                expected_wss_id: 0,
            })),
            worker_thread: None,
            features,
            acked_features: 0,
            #[cfg(feature = "registered_events")]
            registered_evt_q,
            wss_num_bins,
            target_reached_evt: None,
        })
    }

    fn get_config(&self) -> virtio_balloon_config {
        let state = block_on(self.state.lock());
        virtio_balloon_config {
            num_pages: state.num_pages.into(),
            actual: state.actual_pages.into(),
            // crosvm does not (currently) use free_page_hint_cmd_id or
            // poison_val, but they must be present in the right order and size
            // for the virtio-balloon driver in the guest to deserialize the
            // config correctly.
            free_page_hint_cmd_id: 0.into(),
            poison_val: 0.into(),
            wss_num_bins: (self.wss_num_bins as u32).into(),
        }
    }

    fn num_expected_queues(acked_features: u64) -> usize {
        // at minimum we have inflate and deflate vqueues.
        let mut num_queues = 2;
        // stats vqueue
        if acked_features & (1 << VIRTIO_BALLOON_F_STATS_VQ) != 0 {
            num_queues += 1;
        }
        // events vqueue
        if acked_features & (1 << VIRTIO_BALLOON_F_EVENTS_VQ) != 0 {
            num_queues += 1;
        }
        // page reporting vqueue
        if acked_features & (1 << VIRTIO_BALLOON_F_PAGE_REPORTING) != 0 {
            num_queues += 1;
        }
        // working set size vqueues
        if acked_features & (1 << VIRTIO_BALLOON_F_WSS_REPORTING) != 0 {
            num_queues += 2;
        }

        num_queues
    }

    fn stop_worker(&mut self) -> StoppedWorker {
        if let Some(worker_thread) = self.worker_thread.take() {
            let worker_ret = worker_thread.stop();
            self.release_memory_tube = worker_ret.release_memory_tube;
            self.command_tube = Some(worker_ret.command_tube);
            #[cfg(feature = "registered_events")]
            {
                self.registered_evt_q = worker_ret.registered_evt_q;
            }
            #[cfg(windows)]
            {
                self.vm_memory_client = Some(worker_ret.vm_memory_client);
            }

            if let Some(queues) = worker_ret.paused_queues {
                StoppedWorker::WithQueues(Box::new(queues))
            } else {
                StoppedWorker::MissingQueues
            }
        } else {
            StoppedWorker::AlreadyStopped
        }
    }

    /// Given a filtered queue vector from [VirtioDevice::activate], extract
    /// the queues (accounting for queues that are missing because the features
    /// are not negotiated) into a structure that is easier to work with.
    fn get_queues_from_vec(
        &self,
        mut queues: Vec<(Queue, Event)>,
    ) -> anyhow::Result<BalloonQueues> {
        let expected_queues = Balloon::num_expected_queues(self.acked_features);
        if queues.len() != expected_queues {
            return Err(anyhow!(
                "expected {} queues, got {}",
                expected_queues,
                queues.len()
            ));
        }

        let inflate_queue = queues.remove(0);
        let deflate_queue = queues.remove(0);
        let mut queue_struct = BalloonQueues::new(inflate_queue, deflate_queue);

        if self.acked_features & (1 << VIRTIO_BALLOON_F_STATS_VQ) != 0 {
            queue_struct.stats = Some(queues.remove(0));
        }
        if self.acked_features & (1 << VIRTIO_BALLOON_F_PAGE_REPORTING) != 0 {
            queue_struct.reporting = Some(queues.remove(0));
        }
        if self.acked_features & (1 << VIRTIO_BALLOON_F_EVENTS_VQ) != 0 {
            queue_struct.events = Some(queues.remove(0));
        }
        if self.acked_features & (1 << VIRTIO_BALLOON_F_WSS_REPORTING) != 0 {
            queue_struct.wss = (Some(queues.remove(0)), Some(queues.remove(0)));
        }
        Ok(queue_struct)
    }

    fn start_worker(
        &mut self,
        mem: GuestMemory,
        interrupt: Interrupt,
        queues: BalloonQueues,
    ) -> anyhow::Result<()> {
        let (self_target_reached_evt, target_reached_evt) = Event::new()
            .and_then(|e| Ok((e.try_clone()?, e)))
            .context("failed to create target_reached Event pair: {}")?;
        self.target_reached_evt = Some(self_target_reached_evt);

        let state = self.state.clone();

        let command_tube = self.command_tube.take().unwrap();

        #[cfg(windows)]
        let vm_memory_client = self.vm_memory_client.take().unwrap();
        let release_memory_tube = self.release_memory_tube.take();
        #[cfg(feature = "registered_events")]
        let registered_evt_q = self.registered_evt_q.take();
        let pending_adjusted_response_event = self
            .pending_adjusted_response_event
            .try_clone()
            .context("failed to clone Event")?;

        self.worker_thread = Some(WorkerThread::start("v_balloon", move |kill_evt| {
            run_worker(
                queues.inflate,
                queues.deflate,
                queues.stats,
                queues.reporting,
                queues.events,
                queues.wss,
                command_tube,
                #[cfg(windows)]
                vm_memory_client,
                release_memory_tube,
                interrupt,
                kill_evt,
                target_reached_evt,
                pending_adjusted_response_event,
                mem,
                state,
                #[cfg(feature = "registered_events")]
                registered_evt_q,
            )
        }));

        Ok(())
    }
}

/// When we request to stop the worker, this represents the terminal state
/// for the thread (if it exists).
enum StoppedWorker {
    /// Worker stopped successfully & returned its queues.
    WithQueues(Box<PausedQueues>),

    /// Worker wasn't running when the stop was requested.
    AlreadyStopped,

    /// Worker was running but did not successfully return its queues. Something
    /// has gone wrong (and will be in the error log). In the case of a device
    /// reset this is fine since the next activation will replace the queues.
    MissingQueues,
}

impl VirtioDevice for Balloon {
    fn keep_rds(&self) -> Vec<RawDescriptor> {
        let mut rds = Vec::new();
        if let Some(command_tube) = &self.command_tube {
            rds.push(command_tube.as_raw_descriptor());
        }
        if let Some(release_memory_tube) = &self.release_memory_tube {
            rds.push(release_memory_tube.as_raw_descriptor());
        }
        #[cfg(feature = "registered_events")]
        if let Some(registered_evt_q) = &self.registered_evt_q {
            rds.push(registered_evt_q.as_raw_descriptor());
        }
        rds.push(self.pending_adjusted_response_event.as_raw_descriptor());
        rds
    }

    fn device_type(&self) -> DeviceType {
        DeviceType::Balloon
    }

    fn queue_max_sizes(&self) -> &[u16] {
        QUEUE_SIZES
    }

    fn read_config(&self, offset: u64, data: &mut [u8]) {
        copy_config(data, 0, self.get_config().as_bytes(), offset);
    }

    fn write_config(&mut self, offset: u64, data: &[u8]) {
        let mut config = self.get_config();
        copy_config(config.as_bytes_mut(), offset, data, 0);
        let mut state = block_on(self.state.lock());
        state.actual_pages = config.actual.to_native();

        // If balloon has updated to the requested memory, let the hypervisor know.
        if config.num_pages == config.actual {
            info!(
                "sending target reached event at {}",
                u32::from(config.num_pages)
            );
            self.target_reached_evt.as_ref().map(|e| e.signal());
        }
        if state.failable_update && state.actual_pages == state.num_pages {
            state.failable_update = false;
            let num_pages = state.num_pages;
            state.pending_adjusted_responses.push_back(num_pages);
            let _ = self.pending_adjusted_response_event.signal();
        }
    }

    fn features(&self) -> u64 {
        self.features
    }

    fn ack_features(&mut self, mut value: u64) {
        if value & !self.features != 0 {
            warn!("virtio_balloon got unknown feature ack {:x}", value);
            value &= self.features;
        }
        self.acked_features |= value;
    }

    fn activate(
        &mut self,
        mem: GuestMemory,
        interrupt: Interrupt,
        queues: Vec<(Queue, Event)>,
    ) -> anyhow::Result<()> {
        let queues = self.get_queues_from_vec(queues)?;
        self.start_worker(mem, interrupt, queues)
    }

    fn reset(&mut self) -> bool {
        if let StoppedWorker::AlreadyStopped = self.stop_worker() {
            return false;
        }
        true
    }

    fn virtio_sleep(&mut self) -> anyhow::Result<Option<Map<usize, Queue>>> {
        match self.stop_worker() {
            StoppedWorker::WithQueues(paused_queues) => Ok(Some(paused_queues.into())),
            StoppedWorker::MissingQueues => {
                anyhow::bail!("balloon queue workers did not stop cleanly.")
            }
            StoppedWorker::AlreadyStopped => {
                // Device hasn't been activated.
                Ok(None)
            }
        }
    }

    fn virtio_wake(
        &mut self,
        queues_state: Option<(GuestMemory, Interrupt, Map<usize, (Queue, Event)>)>,
    ) -> anyhow::Result<()> {
        if let Some((mem, interrupt, queues)) = queues_state {
            if queues.len() < 2 {
                anyhow::bail!("{} queues were found, but an activated balloon must have at least 2 active queues.", queues.len());
            }

            let balloon_queues = queues.into();
            self.start_worker(mem, interrupt, balloon_queues)?;
        }
        Ok(())
    }

    fn virtio_snapshot(&self) -> anyhow::Result<serde_json::Value> {
        let state = self
            .state
            .lock()
            .now_or_never()
            .context("failed to acquire balloon lock")?;
        serde_json::to_value(BalloonSnapshot {
            features: self.features,
            acked_features: self.acked_features,
            state: state.clone(),
            wss_num_bins: self.wss_num_bins,
        })
        .context("failed to serialize balloon state")
    }

    fn virtio_restore(&mut self, data: serde_json::Value) -> anyhow::Result<()> {
        let snap: BalloonSnapshot = serde_json::from_value(data).context("error deserializing")?;
        if snap.features != self.features {
            anyhow::bail!(
                "expected features to match, but they did not. Live: {:?}, snapshot {:?}",
                self.features,
                snap.features,
            );
        }

        let mut state = self
            .state
            .lock()
            .now_or_never()
            .context("failed to acquire balloon lock")?;
        *state = snap.state;
        self.wss_num_bins = snap.wss_num_bins;
        self.acked_features = snap.acked_features;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::virtio::descriptor_utils::create_descriptor_chain;
    use crate::virtio::descriptor_utils::DescriptorType;

    #[test]
    fn desc_parsing_inflate() {
        // Check that the memory addresses are parsed correctly by 'handle_address_chain' and passed
        // to the closure.
        let memory_start_addr = GuestAddress(0x0);
        let memory = GuestMemory::new(&[(memory_start_addr, 0x10000)]).unwrap();
        memory
            .write_obj_at_addr(0x10u32, GuestAddress(0x100))
            .unwrap();
        memory
            .write_obj_at_addr(0xaa55aa55u32, GuestAddress(0x104))
            .unwrap();

        let mut chain = create_descriptor_chain(
            &memory,
            GuestAddress(0x0),
            GuestAddress(0x100),
            vec![(DescriptorType::Readable, 8)],
            0,
        )
        .expect("create_descriptor_chain failed");

        let mut addrs = Vec::new();
        let res = handle_address_chain(None, &mut chain, &mut |guest_address, len| {
            addrs.push((guest_address, len));
        });
        assert!(res.is_ok());
        assert_eq!(addrs.len(), 2);
        assert_eq!(
            addrs[0].0,
            GuestAddress(0x10u64 << VIRTIO_BALLOON_PFN_SHIFT)
        );
        assert_eq!(
            addrs[1].0,
            GuestAddress(0xaa55aa55u64 << VIRTIO_BALLOON_PFN_SHIFT)
        );
    }

    #[test]
    fn num_expected_queues() {
        let to_feature_bits =
            |features: &[u32]| -> u64 { features.iter().fold(0, |acc, f| acc | (1_u64 << f)) };

        assert_eq!(2, Balloon::num_expected_queues(0));
        assert_eq!(
            2,
            Balloon::num_expected_queues(to_feature_bits(&[VIRTIO_BALLOON_F_MUST_TELL_HOST]))
        );
        assert_eq!(
            3,
            Balloon::num_expected_queues(to_feature_bits(&[VIRTIO_BALLOON_F_STATS_VQ]))
        );
        assert_eq!(
            5,
            Balloon::num_expected_queues(to_feature_bits(&[
                VIRTIO_BALLOON_F_STATS_VQ,
                VIRTIO_BALLOON_F_EVENTS_VQ,
                VIRTIO_BALLOON_F_PAGE_REPORTING
            ]))
        );
        assert_eq!(
            7,
            Balloon::num_expected_queues(to_feature_bits(&[
                VIRTIO_BALLOON_F_STATS_VQ,
                VIRTIO_BALLOON_F_EVENTS_VQ,
                VIRTIO_BALLOON_F_PAGE_REPORTING,
                VIRTIO_BALLOON_F_WSS_REPORTING
            ]))
        );
    }
}
