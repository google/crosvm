// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Virtio version of a linux pvclock clocksource.
//!
//! See the driver source here:
//! <https://android.googlesource.com/kernel/common/+/ebaa2c516811825b141de844cee7a38653058ef5/drivers/virtio/virtio_pvclock.c>
//!
//! For more information about this device, please visit <go/virtio-pvclock>.

use std::arch::x86_64::_rdtsc;
use std::collections::BTreeMap;
use std::mem::size_of;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use anyhow::anyhow;
use anyhow::bail;
use anyhow::Context;
use anyhow::Result;
use base::error;
use base::info;
use base::warn;
use base::AsRawDescriptor;
#[cfg(windows)]
use base::CloseNotifier;
use base::Error;
use base::Event;
use base::EventToken;
use base::RawDescriptor;
use base::ReadNotifier;
use base::Tube;
use base::WaitContext;
use base::WorkerThread;
use chrono::DateTime;
use chrono::Utc;
use data_model::Le32;
use data_model::Le64;
use serde::Deserialize;
use serde::Serialize;
use vm_control::PvClockCommand;
use vm_control::PvClockCommandResponse;
use vm_memory::GuestAddress;
use vm_memory::GuestMemory;
use vm_memory::GuestMemoryError;
use zerocopy::AsBytes;
use zerocopy::FromBytes;

use super::copy_config;
use super::DeviceType;
use super::Interrupt;
use super::Queue;
use super::VirtioDevice;

// Pvclock has one virtio queue: set_pvclock_page
const QUEUE_SIZE: u16 = 1;
const QUEUE_SIZES: &[u16] = &[QUEUE_SIZE];

// pvclock flag bits
const PVCLOCK_TSC_STABLE_BIT: u8 = 1;
const PVCLOCK_GUEST_STOPPED: u8 = 2;

// The feature bitmap for virtio pvclock
const VIRTIO_PVCLOCK_F_TSC_STABLE: u64 = 0; // TSC is stable
const VIRTIO_PVCLOCK_F_INJECT_SLEEP: u64 = 1; // Inject sleep for suspend
const VIRTIO_PVCLOCK_F_CLOCKSOURCE_RATING: u64 = 2; // Use device clocksource rating

// Status values for a virtio_pvclock request.
const VIRTIO_PVCLOCK_S_OK: u8 = 0;
const VIRTIO_PVCLOCK_S_IOERR: u8 = 1;

const VIRTIO_PVCLOCK_CLOCKSOURCE_RATING: u32 = 450;

#[derive(Debug, Clone, Copy, Default, AsBytes, FromBytes)]
#[repr(C)]
struct virtio_pvclock_config {
    // Number of nanoseconds the VM has been suspended without guest suspension.
    suspend_time_ns: Le64,
    // Device-suggested rating of the pvclock clocksource.
    clocksource_rating: Le32,
    padding: u32,
}

#[derive(Debug, Clone, Copy, Default, FromBytes, AsBytes)]
#[repr(C)]
struct virtio_pvclock_set_pvclock_page_req {
    // Physical address of pvclock page.
    pvclock_page_pa: Le64,
    // Current system time.
    system_time: Le64,
    // Current tsc value.
    tsc_timestamp: Le64,
    // Status of this request, one of VIRTIO_PVCLOCK_S_*.
    status: u8,
    padding: [u8; 7],
}

// Data structure for interacting with pvclock shared memory.
struct PvclockSharedData {
    mem: GuestMemory,
    seqlock_addr: GuestAddress,
    tsc_suspended_delta_addr: GuestAddress,
    tsc_frequency_multiplier_addr: GuestAddress,
    tsc_frequency_shift_addr: GuestAddress,
    flags_addr: GuestAddress,
}

impl PvclockSharedData {
    pub fn new(mem: GuestMemory, addr: GuestAddress) -> Self {
        PvclockSharedData {
            mem,
            // The addresses of the various fields that we need to modify are relative to the
            // base of the pvclock page. For reference, see the pvclock_vcpu_time_info struct.
            seqlock_addr: addr,
            tsc_suspended_delta_addr: addr.unchecked_add(8),
            tsc_frequency_multiplier_addr: addr.unchecked_add(24),
            tsc_frequency_shift_addr: addr.unchecked_add(28),
            flags_addr: addr.unchecked_add(29),
        }
    }

    /// Only the seqlock_addr is needed to re-create this struct at restore
    /// time, so that is all our snapshot contains.
    fn snapshot(&self) -> GuestAddress {
        self.seqlock_addr
    }

    /// Set all fields to zero.
    pub fn zero_fill(&mut self) -> Result<()> {
        // The pvclock data structure is 32 bytes long, so we write 32 bytes of 0s
        self.mem
            .write_all_at_addr(&[0u8; 32], self.seqlock_addr)
            .context("failed to zero fill the pvclock shared data")
    }

    pub fn increment_seqlock(&mut self) -> Result<()> {
        // TODO (b/264931437): reads and writes using read/write_obj_from/at_addr are not
        //  guaranteed to be atomic. Although this should not be a problem for the seqlock
        //  or the other fields in the pvclock shared data (whch are protected via the seqlock)
        //  we might want to update these calls to be as atomic as possible if/when we have
        //  the ability to do so, just as a general cleanup and to be consistent.
        let value = self
            .mem
            .read_obj_from_addr::<u32>(self.seqlock_addr)
            .context("failed to read seqlock value")?;
        self.mem
            .write_obj_at_addr(value.wrapping_add(1), self.seqlock_addr)
            .context("failed to write seqlock value")
    }

    pub fn set_tsc_suspended_delta(&mut self, delta: u64) -> Result<()> {
        self.mem
            .write_obj_at_addr(delta, self.tsc_suspended_delta_addr)
            .context("failed to write tsc suspended delta")
    }

    pub fn set_tsc_frequency(&mut self, frequency: u64) -> Result<()> {
        // TSC values are converted to timestamps using the following algorithm:
        //   delta = _rdtsc() - tsc_suspended_delta
        //   if tsc_frequency_shift > 0:
        //     delta <<= tsc_frequency_shift
        //   else:
        //     delta >>= -tsc_frequency_shift
        //   return (delta * tsc_frequency_multiplier) >> 32
        //
        // So, tsc_frequency_multiplier needs to be something like 1e9/tsc_frquency, in which case
        // tsc_frequency_shift would be 32 (to counteract the final 32 right shift). But
        // 1e9/tsc_frequency is <1 so we actually need to scale that value up and scale down
        // the tsc_frequency_shift so we don't lose precision in the frequency. Our tsc_frequency
        // isn't *that* precise, so we scale it up by 16 and scale down the tsc_frequency_shift by
        // 16 (so it's also 16).
        let shift = 16i8;
        let multiplier: u32 = ((1_000_000_000u128 << shift) / frequency as u128)
            .try_into()
            .context(format!(
                "tsc frequency multiplier overflow, frequency {}Hz is too small",
                frequency
            ))?;

        self.mem
            .write_obj_at_addr(multiplier, self.tsc_frequency_multiplier_addr)
            .context("failed to write tsc frequency mlutiplier")?;
        self.mem
            .write_obj_at_addr(shift, self.tsc_frequency_shift_addr)
            .context("failed to write tsc frequency shift")
    }

    pub fn enable_pvclock_flags(&mut self, flags: u8) -> Result<()> {
        let value = self
            .mem
            .read_obj_from_addr::<u8>(self.flags_addr)
            .context("failed to read flags")?;
        self.mem
            .write_obj_at_addr(value | flags, self.flags_addr)
            .context("failed to write flags")
    }
}

/// Entry struct for the virtio-pvclock device.
///
/// Handles MMIO communication, and activating the PvClockWorker thread.
pub struct PvClock {
    tsc_frequency: u64,
    suspend_tube: Option<Tube>,
    /// The total time the vm has been suspended, this is in an `Arc<AtomicU64>>` because it's set
    /// by the PvClockWorker thread but read by PvClock from the mmio bus in the main thread.
    total_suspend_ns: Arc<AtomicU64>,
    features: u64,
    acked_features: u64,
    worker_thread: Option<WorkerThread<WorkerReturn>>,
    /// If the device is sleeping, a [PvClockWorkerSnapshot] that can re-create the worker
    /// will be stored here. (We can't just store the worker itself as it contains an object
    /// tree with references to [GuestMemory].)
    paused_worker: Option<PvClockWorkerSnapshot>,
}

/// Snapshotted form of the [PvClock] device.
#[derive(Serialize, Deserialize)]
struct PvClockSnapshot {
    tsc_frequency: u64,
    paused_worker: Option<PvClockWorkerSnapshot>,
    total_suspend_ns: u64,
    features: u64,
    acked_features: u64,
}

impl PvClock {
    pub fn new(base_features: u64, tsc_frequency: u64, suspend_tube: Tube) -> Self {
        PvClock {
            tsc_frequency,
            suspend_tube: Some(suspend_tube),
            total_suspend_ns: Arc::new(AtomicU64::new(0)),
            features: base_features
                | 1 << VIRTIO_PVCLOCK_F_TSC_STABLE
                | 1 << VIRTIO_PVCLOCK_F_INJECT_SLEEP
                | 1 << VIRTIO_PVCLOCK_F_CLOCKSOURCE_RATING,
            acked_features: 0,
            worker_thread: None,
            paused_worker: None,
        }
    }

    fn get_config(&self) -> virtio_pvclock_config {
        virtio_pvclock_config {
            suspend_time_ns: self.total_suspend_ns.load(Ordering::SeqCst).into(),
            clocksource_rating: VIRTIO_PVCLOCK_CLOCKSOURCE_RATING.into(),
            padding: 0,
        }
    }

    fn start_worker(
        &mut self,
        interrupt: Interrupt,
        mut queues: BTreeMap<usize, Queue>,
        pvclock_worker: PvClockWorker,
    ) -> anyhow::Result<()> {
        if queues.len() != QUEUE_SIZES.len() {
            return Err(anyhow!(
                "expected {} queues, got {}",
                QUEUE_SIZES.len(),
                queues.len()
            ));
        }

        let set_pvclock_page_queue = queues.remove(&0).unwrap();

        let suspend_tube = self
            .suspend_tube
            .take()
            .ok_or(anyhow!("suspend tube should not be None"))?;

        self.worker_thread = Some(WorkerThread::start(
            "virtio_pvclock".to_string(),
            move |kill_evt| {
                run_worker(
                    pvclock_worker,
                    set_pvclock_page_queue,
                    suspend_tube,
                    interrupt,
                    kill_evt,
                )
            },
        ));

        Ok(())
    }
}

/// Represents a moment in time including the TSC counter value at that time.
#[derive(Serialize, Deserialize, Clone)]
struct PvclockInstant {
    time: DateTime<Utc>,
    tsc_value: u64,
}

/// The unique data retained by [PvClockWorker] which can be used to re-create
/// an identical worker.
#[derive(Serialize, Deserialize, Clone)]
struct PvClockWorkerSnapshot {
    suspend_time: Option<PvclockInstant>,
    total_suspend_tsc_delta: u64,
    pvclock_shared_data_base_address: Option<GuestAddress>,
}

impl From<PvClockWorker> for PvClockWorkerSnapshot {
    fn from(worker: PvClockWorker) -> Self {
        PvClockWorkerSnapshot {
            suspend_time: worker.suspend_time,
            total_suspend_tsc_delta: worker.total_suspend_tsc_delta,
            pvclock_shared_data_base_address: worker
                .pvclock_shared_data
                .map(|pvclock| pvclock.snapshot()),
        }
    }
}

/// Worker struct for the virtio-pvclock device.
///
/// Handles virtio requests, storing information about suspend/resume, adjusting the
/// pvclock data in shared memory, and injecting suspend durations via config
/// changes.
struct PvClockWorker {
    tsc_frequency: u64,
    // The moment the last suspend occurred.
    suspend_time: Option<PvclockInstant>,
    // The total time the vm has been suspended, this is in an Arc<AtomicU64>> because it's set
    // by the PvClockWorker thread but read by PvClock from the mmio bus in the main thread.
    total_suspend_ns: Arc<AtomicU64>,
    // The total change in the TSC value over suspensions.
    total_suspend_tsc_delta: u64,
    // Pvclock shared data.
    pvclock_shared_data: Option<PvclockSharedData>,
    mem: GuestMemory,
}

impl PvClockWorker {
    pub fn new(tsc_frequency: u64, total_suspend_ns: Arc<AtomicU64>, mem: GuestMemory) -> Self {
        PvClockWorker {
            tsc_frequency,
            suspend_time: None,
            total_suspend_ns,
            total_suspend_tsc_delta: 0,
            pvclock_shared_data: None,
            mem,
        }
    }

    fn from_snapshot(
        tsc_frequency: u64,
        total_suspend_ns: Arc<AtomicU64>,
        snap: PvClockWorkerSnapshot,
        mem: GuestMemory,
    ) -> Self {
        PvClockWorker {
            tsc_frequency,
            suspend_time: snap.suspend_time,
            total_suspend_ns,
            total_suspend_tsc_delta: snap.total_suspend_tsc_delta,
            pvclock_shared_data: snap
                .pvclock_shared_data_base_address
                .map(|addr| PvclockSharedData::new(mem.clone(), addr)),
            mem,
        }
    }

    /// Initialize the pvclock for initial boot. We assume that the systemtime of 0 corresponds
    /// to the tsc time of 0, so we do not set these. We set the tsc frequency based on the vcpu
    /// tsc frequency and we set PVCLOCK_TSC_STABLE_BIT in flags to tell the guest that it's
    /// safe to use vcpu0's pvclock page for use by the vdso. The order of writing the different
    /// fields doesn't matter at this point, but does matter when updating.
    fn set_pvclock_page(&mut self, addr: u64) -> Result<()> {
        if self.pvclock_shared_data.is_some() {
            return Err(Error::new(libc::EALREADY)).context("pvclock page already set");
        }

        let mut shared_data = PvclockSharedData::new(self.mem.clone(), GuestAddress(addr));

        // set all fields to 0 first
        shared_data.zero_fill()?;

        shared_data.set_tsc_frequency(self.tsc_frequency)?;
        shared_data.enable_pvclock_flags(PVCLOCK_TSC_STABLE_BIT)?;

        self.pvclock_shared_data = Some(shared_data);
        Ok(())
    }

    pub fn suspend(&mut self) {
        if self.suspend_time.is_some() {
            warn!("Suspend time already set, ignoring new suspend time");
            return;
        }
        // Safe because _rdtsc takes no arguments, and we trust _rdtsc to not modify any other
        // memory.
        self.suspend_time = Some(PvclockInstant {
            time: Utc::now(),
            tsc_value: unsafe { _rdtsc() },
        });
    }

    pub fn resume(&mut self) -> Result<()> {
        // First, increment the sequence lock by 1 before writing to the pvclock page.
        self.increment_pvclock_seqlock()?;

        // The guest makes sure there are memory barriers in between reads of the seqlock and other
        // fields, we should make sure there are memory barriers in between writes of seqlock and
        // writes to other fields.
        std::sync::atomic::fence(Ordering::SeqCst);

        // Set the tsc suspended delta and guest_stopped_bit in pvclock struct. We only need to set
        // the bit, the guest will unset it once the guest has handled the stoppage.
        // We get the result here because we want to call increment_pvclock_seqlock regardless of
        // the result of these calls.
        let result = self
            .set_suspended_time()
            .and_then(|_| self.set_guest_stopped_bit());

        // The guest makes sure there are memory barriers in between reads of the seqlock and other
        // fields, we should make sure there are memory barriers in between writes of seqlock and
        // writes to other fields.
        std::sync::atomic::fence(Ordering::SeqCst);

        // Do a final increment once changes are done.
        self.increment_pvclock_seqlock()?;

        result
    }

    fn get_suspended_duration(suspend_time: &PvclockInstant) -> Duration {
        match Utc::now().signed_duration_since(suspend_time.time).to_std() {
            Ok(duration) => duration,
            Err(e) => {
                error!(
                    "pvclock found suspend time in the future (was the host \
                    clock adjusted?). Guest boot/realtime clock may now be \
                    incorrect. Details: {}",
                    e
                );
                Duration::ZERO
            }
        }
    }

    fn set_suspended_time(&mut self) -> Result<()> {
        let (this_suspend_duration, this_suspend_tsc_delta) =
            if let Some(suspend_time) = self.suspend_time.take() {
                // Safe because _rdtsc takes no arguments, and we trust _rdtsc to not modify any
                // other memory.
                (
                    Self::get_suspended_duration(&suspend_time),
                    unsafe { _rdtsc() } - suspend_time.tsc_value,
                )
            } else {
                return Err(Error::new(libc::ENOTSUP))
                    .context("Cannot set suspend time because suspend was never called");
            };

        // update the total tsc delta during all suspends
        self.total_suspend_tsc_delta += this_suspend_tsc_delta;

        // save tsc_suspended_delta to shared memory
        self.pvclock_shared_data
            .as_mut()
            .ok_or(
                anyhow::Error::new(Error::new(libc::ENODATA)).context("pvclock page is not set"),
            )?
            .set_tsc_suspended_delta(self.total_suspend_tsc_delta)?;

        info!(
            "set total suspend tsc delta to {}",
            self.total_suspend_tsc_delta
        );

        // update total suspend ns
        self.total_suspend_ns
            .fetch_add(this_suspend_duration.as_nanos() as u64, Ordering::SeqCst);

        Ok(())
    }

    fn increment_pvclock_seqlock(&mut self) -> Result<()> {
        self.pvclock_shared_data
            .as_mut()
            .ok_or(
                anyhow::Error::new(Error::new(libc::ENODATA)).context("pvclock page is not set"),
            )?
            .increment_seqlock()
    }

    fn set_guest_stopped_bit(&mut self) -> Result<()> {
        self.pvclock_shared_data
            .as_mut()
            .ok_or(
                anyhow::Error::new(Error::new(libc::ENODATA)).context("pvclock page is not set"),
            )?
            .enable_pvclock_flags(PVCLOCK_GUEST_STOPPED)
    }
}

fn pvclock_response_error_from_anyhow(error: anyhow::Error) -> base::Error {
    for cause in error.chain() {
        if let Some(e) = cause.downcast_ref::<base::Error>() {
            return *e;
        }

        if let Some(e) = cause.downcast_ref::<GuestMemoryError>() {
            return match e {
                // Two kinds of GuestMemoryError contain base::Error
                GuestMemoryError::MemoryAddSealsFailed(e) => *e,
                GuestMemoryError::MemoryCreationFailed(e) => *e,
                // Otherwise return EINVAL
                _ => Error::new(libc::EINVAL),
            };
        }
    }
    // Unknown base error
    Error::new(libc::EFAULT)
}

struct WorkerReturn {
    worker: PvClockWorker,
    set_pvclock_page_queue: Queue,
    suspend_tube: Tube,
}

// TODO(b/237300012): asyncify this device.
fn run_worker(
    mut worker: PvClockWorker,
    mut set_pvclock_page_queue: Queue,
    suspend_tube: Tube,
    interrupt: Interrupt,
    kill_evt: Event,
) -> WorkerReturn {
    #[derive(EventToken)]
    enum Token {
        SetPvClockPageQueue,
        SuspendResume,
        InterruptResample,
        Kill,
    }

    let wait_ctx: WaitContext<Token> = match WaitContext::build_with(&[
        (set_pvclock_page_queue.event(), Token::SetPvClockPageQueue),
        (suspend_tube.get_read_notifier(), Token::SuspendResume),
        // TODO(b/242743502): Can also close on Tube closure for Unix once CloseNotifier is
        // implemented for Tube.
        #[cfg(windows)]
        (suspend_tube.get_close_notifier(), Token::Kill),
        (&kill_evt, Token::Kill),
    ]) {
        Ok(pc) => pc,
        Err(e) => {
            error!("failed creating WaitContext: {}", e);
            return WorkerReturn {
                suspend_tube,
                set_pvclock_page_queue,
                worker,
            };
        }
    };
    if let Some(resample_evt) = interrupt.get_resample_evt() {
        if wait_ctx
            .add(resample_evt, Token::InterruptResample)
            .is_err()
        {
            error!("failed creating WaitContext");
            return WorkerReturn {
                suspend_tube,
                set_pvclock_page_queue,
                worker,
            };
        }
    }

    'wait: loop {
        let events = match wait_ctx.wait() {
            Ok(v) => v,
            Err(e) => {
                error!("failed polling for events: {}", e);
                break;
            }
        };

        for event in events.iter().filter(|e| e.is_readable) {
            match event.token {
                Token::SetPvClockPageQueue => {
                    let _ = set_pvclock_page_queue.event().wait();
                    let desc_chain = match set_pvclock_page_queue.pop() {
                        Some(desc_chain) => desc_chain,
                        None => {
                            error!("set_pvclock_page queue was empty");
                            continue;
                        }
                    };

                    // This device does not follow the virtio spec requirements for device-readable
                    // vs. device-writable descriptors, so we can't use `Reader`/`Writer`. Pick the
                    // first descriptor from the chain and assume the whole req structure is
                    // contained within it.
                    let desc = desc_chain
                        .reader
                        .get_remaining_regions()
                        .chain(desc_chain.writer.get_remaining_regions())
                        .next()
                        .unwrap();

                    let len = if desc.len < size_of::<virtio_pvclock_set_pvclock_page_req>() {
                        error!("pvclock descriptor too short");
                        0
                    } else {
                        let addr = GuestAddress(desc.offset);
                        let mut req: virtio_pvclock_set_pvclock_page_req = match worker
                            .mem
                            .read_obj_from_addr(addr)
                        {
                            Ok(req) => req,
                            Err(e) => {
                                error!("failed to read request from set_pvclock_page queue: {}", e);
                                continue;
                            }
                        };

                        req.status = match worker.set_pvclock_page(req.pvclock_page_pa.into()) {
                            Err(e) => {
                                error!("failed to set pvclock page: {:#}", e);
                                VIRTIO_PVCLOCK_S_IOERR
                            }
                            Ok(_) => VIRTIO_PVCLOCK_S_OK,
                        };

                        if let Err(e) = worker.mem.write_obj_at_addr(req, addr) {
                            error!("failed to write set_pvclock_page status: {}", e);
                            continue;
                        }

                        desc.len as u32
                    };

                    set_pvclock_page_queue.add_used(desc_chain, len);
                    set_pvclock_page_queue.trigger_interrupt(&interrupt);
                }
                Token::SuspendResume => {
                    let req = match suspend_tube.recv::<PvClockCommand>() {
                        Ok(req) => req,
                        Err(e) => {
                            error!("failed to receive request: {}", e);
                            continue;
                        }
                    };

                    let resp = match req {
                        PvClockCommand::Suspend => {
                            worker.suspend();
                            PvClockCommandResponse::Ok
                        }
                        PvClockCommand::Resume => {
                            if let Err(e) = worker.resume() {
                                error!("Failed to resume pvclock: {:#}", e);
                                PvClockCommandResponse::Err(pvclock_response_error_from_anyhow(e))
                            } else {
                                // signal to the driver that the total_suspend_ns has changed
                                interrupt.signal_config_changed();
                                PvClockCommandResponse::Ok
                            }
                        }
                    };

                    if let Err(e) = suspend_tube.send(&resp) {
                        error!("error sending PvClockCommandResponse: {}", e);
                    }
                }

                Token::InterruptResample => {
                    interrupt.interrupt_resample();
                }
                Token::Kill => {
                    break 'wait;
                }
            }
        }
    }

    WorkerReturn {
        suspend_tube,
        set_pvclock_page_queue,
        worker,
    }
}

impl VirtioDevice for PvClock {
    fn keep_rds(&self) -> Vec<RawDescriptor> {
        vec![self.suspend_tube.as_ref().unwrap().as_raw_descriptor()]
    }

    fn device_type(&self) -> DeviceType {
        DeviceType::Pvclock
    }

    fn queue_max_sizes(&self) -> &[u16] {
        QUEUE_SIZES
    }

    fn features(&self) -> u64 {
        self.features
    }

    fn ack_features(&mut self, mut value: u64) {
        if value & !self.features != 0 {
            warn!("virtio-pvclock got unknown feature ack {:x}", value);
            value &= self.features;
        }
        self.acked_features |= value;
    }

    fn read_config(&self, offset: u64, data: &mut [u8]) {
        copy_config(data, 0, self.get_config().as_bytes(), offset);
    }

    fn write_config(&mut self, offset: u64, data: &[u8]) {
        // Pvclock device doesn't expect a guest write to config
        warn!(
            "Unexpected write to virtio-pvclock config at offset {}: {:?}",
            offset, data
        );
    }

    fn activate(
        &mut self,
        mem: GuestMemory,
        interrupt: Interrupt,
        queues: BTreeMap<usize, Queue>,
    ) -> anyhow::Result<()> {
        let tsc_frequency = self.tsc_frequency;
        let total_suspend_ns = self.total_suspend_ns.clone();
        let worker = PvClockWorker::new(tsc_frequency, total_suspend_ns, mem);
        self.start_worker(interrupt, queues, worker)
    }

    fn reset(&mut self) -> bool {
        if let Some(worker_thread) = self.worker_thread.take() {
            let worker_ret = worker_thread.stop();
            self.suspend_tube = Some(worker_ret.suspend_tube);
            return true;
        }
        false
    }

    fn virtio_sleep(&mut self) -> anyhow::Result<Option<BTreeMap<usize, Queue>>> {
        if let Some(worker_thread) = self.worker_thread.take() {
            let worker_ret = worker_thread.stop();
            let mut queues = BTreeMap::new();
            queues.insert(0, worker_ret.set_pvclock_page_queue);
            self.suspend_tube = Some(worker_ret.suspend_tube);
            self.paused_worker = Some(worker_ret.worker.into());
            Ok(Some(queues))
        } else {
            Ok(None)
        }
    }

    fn virtio_wake(
        &mut self,
        queues_state: Option<(GuestMemory, Interrupt, BTreeMap<usize, Queue>)>,
    ) -> anyhow::Result<()> {
        if let Some((mem, interrupt, queues)) = queues_state {
            let worker_snap = self
                .paused_worker
                .take()
                .ok_or(anyhow!("a sleeping pvclock must have a paused worker"))?;
            let worker = PvClockWorker::from_snapshot(
                self.tsc_frequency,
                self.total_suspend_ns.clone(),
                worker_snap,
                mem,
            );
            self.start_worker(interrupt, queues, worker)?;
        }
        Ok(())
    }

    fn virtio_snapshot(&self) -> anyhow::Result<serde_json::Value> {
        serde_json::to_value(PvClockSnapshot {
            features: self.features,
            acked_features: self.acked_features,
            total_suspend_ns: self.total_suspend_ns.load(Ordering::SeqCst),
            tsc_frequency: self.tsc_frequency,
            paused_worker: self.paused_worker.clone(),
        })
        .context("failed to serialize PvClockSnapshot")
    }

    fn virtio_restore(&mut self, data: serde_json::Value) -> anyhow::Result<()> {
        let snap: PvClockSnapshot = serde_json::from_value(data).context("error deserializing")?;
        if snap.features != self.features {
            bail!(
                "expected virtio_features to match, but they did not. Live: {:?}, snapshot {:?}",
                self.features,
                snap.features,
            );
        }
        self.acked_features = snap.acked_features;
        self.total_suspend_ns
            .store(snap.total_suspend_ns, Ordering::SeqCst);
        self.paused_worker = snap.paused_worker;

        // TODO(b/291346907): we assume that the TSC frequency has NOT changed
        // since the snapshot was made. Assuming we have not moved machines,
        // this is a reasonable assumption. We don't verify the frequency
        // because TSC calibration noisy.
        self.tsc_frequency = snap.tsc_frequency;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::virtio::QueueConfig;
    use crate::virtio::VIRTIO_MSI_NO_VECTOR;
    use crate::IrqLevelEvent;

    const TEST_QUEUE_SIZE: u16 = 2048;

    fn make_interrupt() -> Interrupt {
        Interrupt::new(IrqLevelEvent::new().unwrap(), None, VIRTIO_MSI_NO_VECTOR)
    }

    fn create_sleeping_device() -> (PvClock, GuestMemory, Tube) {
        let mem = GuestMemory::new(&[(GuestAddress(0), 0x10000)]).unwrap();
        let (_host_tube, device_tube) = Tube::pair().unwrap();
        let mut pvclock_device = PvClock::new(0, 1e9 as u64, device_tube);

        // The queue won't actually be used, so passing one that isn't
        // fully configured is fine.
        let mut fake_queue = QueueConfig::new(TEST_QUEUE_SIZE, 0);
        fake_queue.set_ready(true);

        pvclock_device
            .activate(
                mem.clone(),
                make_interrupt(),
                BTreeMap::from([(0, fake_queue.activate(&mem, Event::new().unwrap()).unwrap())]),
            )
            .expect("activate should succeed");

        let queues = pvclock_device
            .virtio_sleep()
            .expect("sleep should succeed")
            .expect("sleep should yield queues");
        assert_eq!(queues.len(), 1);
        assert_eq!(
            queues.get(&0).expect("queue must be present").size(),
            TEST_QUEUE_SIZE
        );
        assert!(pvclock_device.paused_worker.is_some());

        (pvclock_device, mem, _host_tube)
    }

    fn assert_wake_successful(pvclock_device: &mut PvClock, mem: &GuestMemory) {
        // We just create a new queue here, because it isn't actually accessed
        // by the device in these tests.
        let mut wake_queues = BTreeMap::new();
        let mut fake_queue = QueueConfig::new(TEST_QUEUE_SIZE, 0);
        fake_queue.set_ready(true);
        wake_queues.insert(0, fake_queue.activate(mem, Event::new().unwrap()).unwrap());
        let queues_state = (mem.clone(), make_interrupt(), wake_queues);
        pvclock_device
            .virtio_wake(Some(queues_state))
            .expect("wake should succeed");
        assert!(pvclock_device.paused_worker.is_none());
    }

    #[test]
    fn test_sleep_wake_smoke() {
        let (mut pvclock_device, mem, _tube) = create_sleeping_device();
        assert_wake_successful(&mut pvclock_device, &mem);
    }

    #[test]
    fn test_save_restore() {
        let (mut pvclock_device, mem, _tube) = create_sleeping_device();
        let test_suspend_ns = 9999;

        // Store a test value we can look for later in the test to verify
        // we're restoring properties.
        pvclock_device
            .total_suspend_ns
            .store(test_suspend_ns, Ordering::SeqCst);

        let snap = pvclock_device.virtio_snapshot().unwrap();
        pvclock_device.total_suspend_ns.store(0, Ordering::SeqCst);
        pvclock_device.virtio_restore(snap).unwrap();
        assert_eq!(
            pvclock_device.total_suspend_ns.load(Ordering::SeqCst),
            test_suspend_ns
        );

        assert_wake_successful(&mut pvclock_device, &mem);
    }
}
