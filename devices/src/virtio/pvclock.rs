// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Virtio version of a linux pvclock clocksource.
//!
//! Driver source is here:
//! <https://android.googlesource.com/kernel/common/+/ebaa2c516811825b141de844cee7a38653058ef5/drivers/virtio/virtio_pvclock.c>
//!
//! # Background
//!
//! Userland applications often rely on CLOCK_MONOTONIC to be relatively continuous.
//! Large jumps can signal problems (e.g., triggering Android watchdogs).
//! This assumption breaks down in virtualized environments, where a VM's suspension isn't
//! inherently linked to the guest kernel's concept of "suspend".
//! Since fixing all userland code is impractical, virtio-pvclock allows the VMM and guest kernel
//! to collaborate on emulating the expected clock behavior around suspend/resume.
//!
//! # How it works
//!
//! ## Core functions of virtio-pvclock device:
//!
//! 1. Adjusts hardware clocksource offsets to make the guest clocks appear suspended when the VM is
//!    suspended.
//!   - This is achieved through the pvclock mechanism implemented in x86 KVM used by kvm-clock.
//! 2. Provides the guest kernel with the duration of VM suspension, allowing the guest to adjust
//!    its clocks accordingly.
//!   - Since the offset between the CLOCK_MONOTONIC and CLOCK_BOOTTIME is maintained by the guest
//!     kernel, applying the adjustment is the guest driver's responsibility.
//!
//! ## Expected guest clock behaviors under virtio-pvclock is enabled
//!
//! - Monotonicity of CLOCK_MONOTONIC and CLOCK_BOOTTIME is maintained.
//! - CLOCK_MONOTONIC will not include the time passed during crosvm is suspended from its run mode
//!   perspective.
//! - CLOCK_BOOTTIME will be adjusted to include the time passed during crosvm is suspended.
//!
//! # Why it is needed
//!
//! Because the existing solution does not cover some expectations we need.
//!
//! kvm-clock is letting the host to manage the offsets of CLOCK_MONOTONIC.
//! However, it doesn't address the difference between CLOCK_BOOTTIME and CLOCK_MONOTONIC related
//! to host's suspend/resume, as it is designed to maintain the CLOCK_REALTIME in sync mainly.

#[cfg(target_arch = "aarch64")]
use std::arch::asm;
use std::collections::BTreeMap;
use std::mem::replace;
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
use snapshot::AnySnapshot;
use vm_control::PvClockCommand;
use vm_control::PvClockCommandResponse;
use vm_memory::GuestAddress;
use vm_memory::GuestMemory;
use vm_memory::GuestMemoryError;
use zerocopy::FromBytes;
use zerocopy::Immutable;
use zerocopy::IntoBytes;
use zerocopy::KnownLayout;

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

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
fn read_clock_counter() -> u64 {
    // SAFETY: rdtsc is unprivileged and have no side effects.
    unsafe { std::arch::x86_64::_rdtsc() }
}

#[cfg(target_arch = "aarch64")]
fn read_clock_counter() -> u64 {
    let mut x: u64;
    // SAFETY: This instruction have no side effect apart from storing the current timestamp counter
    //         into the specified register.
    unsafe {
        asm!("mrs {x}, cntvct_el0",
            x = out(reg) x,
        );
    }
    x
}

/// Calculate a (multiplier, shift) pair for scaled math of clocks.
/// The values are passed on to `pvclock_scale_delta` in the guest kernel and satisfy the following
/// (approximate) equality:
/// `n * scaled_hz / base_hz ~= ((n << shift) * multiplier) >> 32`
/// The logic here is roughly based on `kvm_get_time_scale` (but simplified as we can use u128).
/// # Arguments
/// * `scaled_hz` - Frequency to convert to. When dealing with clocksources, this is NSEC_PER_SEC.
/// * `base_hz` - Frequency to convert from. When dealing with clocksources, this is the counter
///   frequency.
fn freq_scale_shift(scaled_hz: u64, base_hz: u64) -> (u32, i8) {
    assert!(scaled_hz > 0 && base_hz > 0);
    // We treat `multiplier` as a 0.32 fixed-point number by folding the >> 32 into its definition.
    // With this definition, `multiplier` can be calculated as `(scaled_hz / base_hz) >> shift`
    // with a corresponding `shift`.
    //
    // The value of `shift` should satisfy a few constraints:
    // 1. `multiplier` needs to be < 1.0 due to the representable range of 0.32 fixed-point (maximum
    //    (2^32-1)/2^32).
    // 2. `shift` should be minimized because `pvclock_scale_delta` applies `shift` on the 64-bit
    //    TSC value before extending to 128-bit and large positive shifts reduce the TSC rollover
    //    time.
    //
    // Minimizing `shift` means maximizing `multiplier`. From the < 1.0 constraint, this is
    // equivalent to having a multiplier within [0.5, 1.0). The logic below picks a multiplier
    // satisfying that, while updating `shift` accordingly when we double or halve the multiplier.
    let mut shift = 0;
    // Convert to u128 so that overflow handling becomes much easier.
    let mut scaled_hz = scaled_hz as u128;
    let mut base_hz = base_hz as u128;
    if scaled_hz >= base_hz {
        while scaled_hz >= base_hz {
            // `multiplier` >= 1.0; iteratively scale it down
            // scaled_hz is at most 64 bits, so after this loop base_hz is at most 65 bits.
            base_hz <<= 1;
            shift += 1;
        }
    } else {
        while base_hz > 2 * scaled_hz {
            // `multiplier` < 0.5; iteratively scale it up
            // base_hz is at most 64 bits. If the loop condition passes then scaled_hz is at most 63
            // bits, otherwise at most 64 bits. Post-loop scaled_hz is at most 64 bits.
            scaled_hz <<= 1;
            shift -= 1;
        }
    }
    // From above, we know that the values are at most 65 bits. This provides sufficient headroom
    // for scaled_hz << 32 below.
    assert!(base_hz < (1u128 << 65) && scaled_hz < (1u128 << 65));
    let mult: u32 = ((scaled_hz << 32) / base_hz)
        .try_into()
        .expect("should not overflow");
    (mult, shift)
}

// The config structure being exposed to the guest to tell them how much suspend time should be
// injected to the guest's CLOCK_BOOTTIME.
#[derive(Debug, Clone, Copy, Default, FromBytes, Immutable, IntoBytes, KnownLayout)]
#[allow(non_camel_case_types)]
#[repr(C)]
struct virtio_pvclock_config {
    // Total duration the VM has been paused while the guest kernel is not in the suspended state
    // (from the power management and timekeeping perspective).
    suspend_time_ns: Le64,
    // Device-suggested rating of the pvclock clocksource.
    clocksource_rating: Le32,
    padding: u32,
}

#[derive(Debug, Clone, Copy, Default, FromBytes, Immutable, IntoBytes, KnownLayout)]
#[allow(non_camel_case_types)]
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
        let (multiplier, shift): (u32, i8) = freq_scale_shift(1_000_000_000, frequency);

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

/// Serializable part of the [PvClock] struct which will be used by the virtio_snapshot / restore.
#[derive(Serialize, Deserialize)]
struct PvClockState {
    tsc_frequency: u64,
    /// If the device is sleeping, a [PvClockWorkerSnapshot] that can re-create the worker
    /// will be stored here. (We can't just store the worker itself as it contains an object
    /// tree with references to [GuestMemory].)
    paused_main_worker: Option<PvClockWorkerSnapshot>,
    /// The total time the vm has been suspended, this is in an `Arc<AtomicU64>>` because it's set
    /// by the PvClockWorker thread but read by PvClock from the mmio bus in the main thread.
    total_suspend_ns: Arc<AtomicU64>,
    features: u64,
    acked_features: u64,
}

/// An enum to keep dynamic state of pvclock workers in a type safe manner.
enum PvClockWorkerState {
    /// Idle means no worker is running.
    /// This tube is for communicating with this device from the crosvm threads.
    Idle(Tube),
    /// A stub worker to respond pvclock commands when the device is not activated yet.
    Stub(WorkerThread<StubWorkerReturn>),
    /// A main worker to respond pvclock commands while the device is active.
    Main(WorkerThread<MainWorkerReturn>),
    /// None is used only for handling transitional state between the states above.
    None,
}

/// A struct that represents virtio-pvclock device.
pub struct PvClock {
    state: PvClockState,
    worker_state: PvClockWorkerState,
}

impl PvClock {
    pub fn new(base_features: u64, tsc_frequency: u64, suspend_tube: Tube) -> Self {
        let state = PvClockState {
            tsc_frequency,
            paused_main_worker: None,
            total_suspend_ns: Arc::new(AtomicU64::new(0)),
            features: base_features
                | 1 << VIRTIO_PVCLOCK_F_TSC_STABLE
                | 1 << VIRTIO_PVCLOCK_F_INJECT_SLEEP
                | 1 << VIRTIO_PVCLOCK_F_CLOCKSOURCE_RATING,
            acked_features: 0,
        };
        PvClock {
            state,
            worker_state: PvClockWorkerState::Idle(suspend_tube),
        }
    }

    fn get_config(&self) -> virtio_pvclock_config {
        virtio_pvclock_config {
            suspend_time_ns: self.state.total_suspend_ns.load(Ordering::SeqCst).into(),
            clocksource_rating: VIRTIO_PVCLOCK_CLOCKSOURCE_RATING.into(),
            padding: 0,
        }
    }

    /// Use switch_to_*_worker unless needed to keep the state transition consistent
    fn start_main_worker(
        &mut self,
        interrupt: Interrupt,
        pvclock_worker: PvClockWorker,
        mut queues: BTreeMap<usize, Queue>,
    ) -> anyhow::Result<()> {
        let last_state = replace(&mut self.worker_state, PvClockWorkerState::None);
        if let PvClockWorkerState::Idle(suspend_tube) = last_state {
            if queues.len() != QUEUE_SIZES.len() {
                self.worker_state = PvClockWorkerState::Idle(suspend_tube);
                return Err(anyhow!(
                    "expected {} queues, got {}",
                    QUEUE_SIZES.len(),
                    queues.len()
                ));
            }
            let set_pvclock_page_queue = queues.remove(&0).unwrap();
            self.worker_state = PvClockWorkerState::Main(WorkerThread::start(
                "virtio_pvclock".to_string(),
                move |kill_evt| {
                    run_main_worker(
                        pvclock_worker,
                        set_pvclock_page_queue,
                        suspend_tube,
                        interrupt,
                        kill_evt,
                    )
                },
            ));
        } else {
            panic!("Invalid state transition");
        }
        Ok(())
    }

    /// Use switch_to_*_worker unless needed to keep the state transition consistent
    fn start_stub_worker(&mut self) {
        let last_state = replace(&mut self.worker_state, PvClockWorkerState::None);
        self.worker_state = if let PvClockWorkerState::Idle(suspend_tube) = last_state {
            PvClockWorkerState::Stub(WorkerThread::start(
                "virtio_pvclock_stub".to_string(),
                move |kill_evt| run_stub_worker(suspend_tube, kill_evt),
            ))
        } else {
            panic!("Invalid state transition");
        };
    }

    /// Use switch_to_*_worker unless needed to keep the state transition consistent
    fn stop_stub_worker(&mut self) {
        let last_state = replace(&mut self.worker_state, PvClockWorkerState::None);
        self.worker_state = if let PvClockWorkerState::Stub(stub_worker_thread) = last_state {
            let stub_worker_ret = stub_worker_thread.stop();
            PvClockWorkerState::Idle(stub_worker_ret.suspend_tube)
        } else {
            panic!("Invalid state transition");
        }
    }

    /// Use switch_to_*_worker unless needed to keep the state transition consistent
    fn stop_main_worker(&mut self) {
        let last_state = replace(&mut self.worker_state, PvClockWorkerState::None);
        if let PvClockWorkerState::Main(main_worker_thread) = last_state {
            let main_worker_ret = main_worker_thread.stop();
            self.worker_state = PvClockWorkerState::Idle(main_worker_ret.suspend_tube);
            let mut queues = BTreeMap::new();
            queues.insert(0, main_worker_ret.set_pvclock_page_queue);
            self.state.paused_main_worker = Some(main_worker_ret.worker.into());
        } else {
            panic!("Invalid state transition");
        }
    }

    fn switch_to_stub_worker(&mut self) {
        self.stop_main_worker();
        self.start_stub_worker();
    }

    fn switch_to_main_worker(
        &mut self,
        interrupt: Interrupt,
        pvclock_worker: PvClockWorker,
        queues: BTreeMap<usize, Queue>,
    ) -> anyhow::Result<()> {
        self.stop_stub_worker();
        self.start_main_worker(interrupt, pvclock_worker, queues)
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
    total_injected_ns: Arc<AtomicU64>,
    // The total change in the TSC value over suspensions.
    total_suspend_tsc_delta: u64,
    // Pvclock shared data.
    pvclock_shared_data: Option<PvclockSharedData>,
    mem: GuestMemory,
}

impl PvClockWorker {
    pub fn new(tsc_frequency: u64, total_injected_ns: Arc<AtomicU64>, mem: GuestMemory) -> Self {
        PvClockWorker {
            tsc_frequency,
            suspend_time: None,
            total_injected_ns,
            total_suspend_tsc_delta: 0,
            pvclock_shared_data: None,
            mem,
        }
    }

    fn from_snapshot(
        tsc_frequency: u64,
        total_injected_ns: Arc<AtomicU64>,
        snap: PvClockWorkerSnapshot,
        mem: GuestMemory,
    ) -> Self {
        PvClockWorker {
            tsc_frequency,
            suspend_time: snap.suspend_time,
            total_injected_ns,
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
        self.suspend_time = Some(PvclockInstant {
            time: Utc::now(),
            tsc_value: read_clock_counter(),
        });
    }

    pub fn resume(&mut self) -> Result<u64> {
        // First, increment the sequence lock by 1 before writing to the pvclock page.
        self.increment_pvclock_seqlock()?;

        // The guest makes sure there are memory barriers in between reads of the seqlock and other
        // fields, we should make sure there are memory barriers in between writes of seqlock and
        // writes to other fields.
        std::sync::atomic::fence(Ordering::SeqCst);

        // Set the guest_stopped_bit and tsc suspended delta in pvclock struct. We only need to set
        // the bit, the guest will unset it once the guest has handled the stoppage.
        // We get the result here because we want to call increment_pvclock_seqlock regardless of
        // the result of these calls.
        let result = self
            .set_guest_stopped_bit()
            .and_then(|_| self.set_suspended_time());

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

    fn set_suspended_time(&mut self) -> Result<u64> {
        let (this_suspend_duration, this_suspend_tsc_delta) =
            if let Some(suspend_time) = self.suspend_time.take() {
                (
                    Self::get_suspended_duration(&suspend_time),
                    // NB: This calculation may wrap around, as TSC can be reset to zero when
                    // the device has resumed from the "deep" suspend state (it may not happen for
                    // s2idle cases). It also happens when the tsc value itself wraps.
                    read_clock_counter().wrapping_sub(suspend_time.tsc_value),
                )
            } else {
                return Err(Error::new(libc::ENOTSUP))
                    .context("Cannot set suspend time because suspend was never called");
            };

        // update the total tsc delta during all suspends
        // NB: This calculation may wrap around, as the suspend time can be bigger than u64 range.
        self.total_suspend_tsc_delta = self
            .total_suspend_tsc_delta
            .wrapping_add(this_suspend_tsc_delta);

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
        self.total_injected_ns
            .fetch_add(this_suspend_duration.as_nanos() as u64, Ordering::SeqCst);

        Ok(self.total_suspend_tsc_delta)
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

struct StubWorkerReturn {
    suspend_tube: Tube,
}

/// A stub worker to respond any requests when the device is inactive.
fn run_stub_worker(suspend_tube: Tube, kill_evt: Event) -> StubWorkerReturn {
    #[derive(EventToken, Debug)]
    enum Token {
        SomePvClockRequest,
        Kill,
    }
    let wait_ctx: WaitContext<Token> = match WaitContext::build_with(&[
        (suspend_tube.get_read_notifier(), Token::SomePvClockRequest),
        // TODO(b/242743502): Can also close on Tube closure for Unix once CloseNotifier is
        // implemented for Tube.
        #[cfg(windows)]
        (suspend_tube.get_close_notifier(), Token::Kill),
        (&kill_evt, Token::Kill),
    ]) {
        Ok(wait_ctx) => wait_ctx,
        Err(e) => {
            error!("failed creating WaitContext: {}", e);
            return StubWorkerReturn { suspend_tube };
        }
    };
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
                Token::SomePvClockRequest => {
                    match suspend_tube.recv::<PvClockCommand>() {
                        Ok(req) => req,
                        Err(e) => {
                            error!("failed to receive request: {}", e);
                            continue;
                        }
                    };
                    if let Err(e) = suspend_tube.send(&PvClockCommandResponse::DeviceInactive) {
                        error!("error sending PvClockCommandResponse: {}", e);
                    }
                }
                Token::Kill => {
                    break 'wait;
                }
            }
        }
    }
    StubWorkerReturn { suspend_tube }
}

struct MainWorkerReturn {
    worker: PvClockWorker,
    set_pvclock_page_queue: Queue,
    suspend_tube: Tube,
}

// TODO(b/237300012): asyncify this device.
/// A worker to process PvClockCommand requests
fn run_main_worker(
    mut worker: PvClockWorker,
    mut set_pvclock_page_queue: Queue,
    suspend_tube: Tube,
    interrupt: Interrupt,
    kill_evt: Event,
) -> MainWorkerReturn {
    #[derive(EventToken)]
    enum Token {
        SetPvClockPageQueue,
        SuspendResume,
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
            return MainWorkerReturn {
                suspend_tube,
                set_pvclock_page_queue,
                worker,
            };
        }
    };

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
                            // Spurious doorbells from the driver are permitted
                            // by the virtio spec (v1.3; section 2.9).
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

                    set_pvclock_page_queue.add_used_with_bytes_written(desc_chain, len);
                    set_pvclock_page_queue.trigger_interrupt();
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
                            match worker.resume() {
                                Ok(total_suspended_ticks) => {
                                    // signal to the driver that the total_suspend_ns has changed
                                    interrupt.signal_config_changed();
                                    PvClockCommandResponse::Resumed {
                                        total_suspended_ticks,
                                    }
                                }
                                Err(e) => {
                                    error!("Failed to resume pvclock: {:#}", e);
                                    PvClockCommandResponse::Err(pvclock_response_error_from_anyhow(
                                        e,
                                    ))
                                }
                            }
                        }
                    };

                    if let Err(e) = suspend_tube.send(&resp) {
                        error!("error sending PvClockCommandResponse: {}", e);
                    }
                }
                Token::Kill => {
                    break 'wait;
                }
            }
        }
    }

    MainWorkerReturn {
        suspend_tube,
        set_pvclock_page_queue,
        worker,
    }
}

impl VirtioDevice for PvClock {
    fn keep_rds(&self) -> Vec<RawDescriptor> {
        if let PvClockWorkerState::Idle(suspend_tube) = &self.worker_state {
            vec![suspend_tube.as_raw_descriptor()]
        } else {
            Vec::new()
        }
    }

    fn device_type(&self) -> DeviceType {
        DeviceType::Pvclock
    }

    fn queue_max_sizes(&self) -> &[u16] {
        QUEUE_SIZES
    }

    fn features(&self) -> u64 {
        self.state.features
    }

    fn ack_features(&mut self, mut value: u64) {
        if value & !self.features() != 0 {
            warn!("virtio-pvclock got unknown feature ack {:x}", value);
            value &= self.features();
        }
        self.state.acked_features |= value;
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
        let tsc_frequency = self.state.tsc_frequency;
        let total_suspend_ns = self.state.total_suspend_ns.clone();
        let worker = PvClockWorker::new(tsc_frequency, total_suspend_ns, mem);
        self.switch_to_main_worker(interrupt, worker, queues)
    }

    fn reset(&mut self) -> Result<()> {
        self.switch_to_stub_worker();
        Ok(())
    }

    fn virtio_sleep(&mut self) -> anyhow::Result<Option<BTreeMap<usize, Queue>>> {
        let last_state = replace(&mut self.worker_state, PvClockWorkerState::None);
        match last_state {
            PvClockWorkerState::Main(main_worker_thread) => {
                let main_worker_ret = main_worker_thread.stop();
                let mut queues = BTreeMap::new();
                queues.insert(0, main_worker_ret.set_pvclock_page_queue);
                self.worker_state = PvClockWorkerState::Idle(main_worker_ret.suspend_tube);
                self.state.paused_main_worker = Some(main_worker_ret.worker.into());
                Ok(Some(queues))
            }
            PvClockWorkerState::Stub(stub_worker_thread) => {
                let stub_ret = stub_worker_thread.stop();
                self.worker_state = PvClockWorkerState::Idle(stub_ret.suspend_tube);
                Ok(None)
            }
            PvClockWorkerState::Idle(suspend_tube) => {
                self.worker_state = PvClockWorkerState::Idle(suspend_tube);
                Ok(None)
            }
            PvClockWorkerState::None => panic!("invalid state transition"),
        }
    }

    fn virtio_wake(
        &mut self,
        queues_state: Option<(GuestMemory, Interrupt, BTreeMap<usize, Queue>)>,
    ) -> anyhow::Result<()> {
        if let Some((mem, interrupt, queues)) = queues_state {
            let worker_snap = self
                .state
                .paused_main_worker
                .take()
                .ok_or(anyhow!("a sleeping pvclock must have a paused worker"))?;
            let worker = PvClockWorker::from_snapshot(
                self.state.tsc_frequency,
                self.state.total_suspend_ns.clone(),
                worker_snap,
                mem,
            );
            // Use unchecked as no worker is running at this point
            self.start_main_worker(interrupt, worker, queues)?;
        } else {
            // If the device wasn't activated, we should bring up the stub worker since that's
            // what is supposed to be running for an un-activated device.
            self.start_stub_worker();
        }
        Ok(())
    }

    fn virtio_snapshot(&mut self) -> anyhow::Result<AnySnapshot> {
        AnySnapshot::to_any(&self.state).context("failed to serialize PvClockState")
    }

    fn virtio_restore(&mut self, data: AnySnapshot) -> anyhow::Result<()> {
        let state: PvClockState = AnySnapshot::from_any(data).context("error deserializing")?;
        if state.features != self.features() {
            bail!(
                "expected virtio_features to match, but they did not. Live: {:?}, snapshot {:?}",
                self.features(),
                state.features,
            );
        }
        // TODO(b/291346907): we assume that the TSC frequency has NOT changed
        // since the snapshot was made. Assuming we have not moved machines,
        // this is a reasonable assumption. We don't verify the frequency
        // because TSC calibration noisy.
        self.state = state;
        Ok(())
    }

    fn on_device_sandboxed(&mut self) {
        self.start_stub_worker();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::virtio::QueueConfig;

    const TEST_QUEUE_SIZE: u16 = 2048;

    fn make_interrupt() -> Interrupt {
        Interrupt::new_for_test()
    }

    fn create_pvclock_device() -> (Tube, PvClock) {
        let (host_tube, device_tube) = Tube::pair().unwrap();
        let mut pvclock_device = PvClock::new(0, 1e9 as u64, device_tube);

        // Simulate the device initialization to start the stub thread.
        // In the real case, on_device_sandboxed will be called after the device is sandboxed
        // (or at some point during the device initializtion when the sandbox is disabled) to
        // allow devices to use multi-threads (as spawning new threads before sandboxing is
        // prohibited because of the minijail's restriction).
        pvclock_device.on_device_sandboxed();

        (host_tube, pvclock_device)
    }

    fn create_sleeping_device() -> (PvClock, GuestMemory, Tube) {
        let (_host_tube, mut pvclock_device) = create_pvclock_device();

        // The queue won't actually be used, so passing one that isn't
        // fully configured is fine.
        let mut fake_queue = QueueConfig::new(TEST_QUEUE_SIZE, 0);
        fake_queue.set_ready(true);
        let mem = GuestMemory::new(&[(GuestAddress(0), 0x10000)]).unwrap();
        let interrupt = make_interrupt();
        pvclock_device
            .activate(
                mem.clone(),
                interrupt.clone(),
                BTreeMap::from([(
                    0,
                    fake_queue
                        .activate(&mem, Event::new().unwrap(), interrupt)
                        .unwrap(),
                )]),
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
        assert!(pvclock_device.state.paused_main_worker.is_some());
        (pvclock_device, mem, _host_tube)
    }

    fn assert_wake_successful(pvclock_device: &mut PvClock, mem: &GuestMemory) {
        // We just create a new queue here, because it isn't actually accessed
        // by the device in these tests.
        let mut wake_queues = BTreeMap::new();
        let mut fake_queue = QueueConfig::new(TEST_QUEUE_SIZE, 0);
        let interrupt = make_interrupt();
        fake_queue.set_ready(true);
        wake_queues.insert(
            0,
            fake_queue
                .activate(mem, Event::new().unwrap(), interrupt.clone())
                .unwrap(),
        );
        let queues_state = (mem.clone(), interrupt, wake_queues);
        pvclock_device
            .virtio_wake(Some(queues_state))
            .expect("wake should succeed");
        assert!(pvclock_device.state.paused_main_worker.is_none());
    }

    #[test]
    fn test_command_response_when_inactive() {
        let (host_tube, _pvclock_device) = create_pvclock_device();
        assert!(host_tube.send(&PvClockCommand::Suspend).is_ok());
        let res = host_tube.recv::<PvClockCommandResponse>();
        assert!(matches!(res, Ok(PvClockCommandResponse::DeviceInactive)));
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
            .state
            .total_suspend_ns
            .store(test_suspend_ns, Ordering::SeqCst);

        let snap = pvclock_device.virtio_snapshot().unwrap();
        pvclock_device
            .state
            .total_suspend_ns
            .store(0, Ordering::SeqCst);
        pvclock_device.virtio_restore(snap).unwrap();
        assert_eq!(
            pvclock_device.state.total_suspend_ns.load(Ordering::SeqCst),
            test_suspend_ns
        );

        assert_wake_successful(&mut pvclock_device, &mem);
    }

    /// A simplified clone of `pvclock_scale_delta` from Linux kernel to emulate
    /// what the kernel does when converting TSC to ktime.
    fn pvclock_scale_tsc(mult: u32, shift: i8, tsc: u64) -> u64 {
        let shifted = if shift < 0 {
            tsc >> -shift
        } else {
            tsc << shift
        };
        let product = shifted as u128 * mult as u128;
        (product >> 32).try_into().expect("should not overflow")
    }

    /// Helper function for checking the behavior of `freq_scale_shift`.
    fn check_freq_scale(f: u64, input: u64) {
        // We only test `scaled_hz` = 1GHz because that is the only value used in the code base.
        let (mult, shift) = freq_scale_shift(1_000_000_000, f);

        let scaled = pvclock_scale_tsc(mult, shift, input);

        // Use relative error <= 1e-8 as the target. TSC can be huge so this isn't really a super
        // accurate target, and our goal is to simply sanity check the math without adding too many
        // requirements about rounding errors.
        let expected: u64 = (input as u128 * 1_000_000_000u128 / f as u128) as u64;
        let expected_lo: u64 = (input as u128 * 999_999_990u128 / f as u128) as u64;
        let expected_hi: u64 = (input as u128 * 1_000_000_010u128 / f as u128) as u64;
        assert!(
            (expected_lo..=expected_hi).contains(&scaled),
            "{scaled} should be close to {expected} (base_hz={f}, mult={mult}, shift={shift})"
        );
    }

    #[test]
    fn test_freq_scale_shift_accuracy() {
        // Basic check for formula correctness: scaling `scaled_hz` to `base_hz` should yield
        // `base_hz`.
        for f in (1..=50).map(|n| n * 100_000_000) {
            check_freq_scale(f, f);
        }
    }

    #[test]
    fn test_freq_scale_shift_overflow_high_freq() {
        // For scale factors < 1.0, test that we can correctly convert the maximum TSC value without
        // overflow. We must be able to handle values as large as it realistically can be, as the
        // kernel clock breaks if the calculated ktime goes backwards (b/342168920).
        for f in (11..=50).map(|n| n * 100_000_000) {
            check_freq_scale(f, u64::MAX);
        }
    }

    #[test]
    fn test_freq_scale_shift_overflow_low_freq() {
        fn prev_power_of_two(n: u64) -> u64 {
            assert_ne!(n, 0);
            let highest_bit_set = 63 - n.leading_zeros();
            1 << highest_bit_set
        }
        // Same test as above, but for scale factors >= 1.0. The difference is that for scale
        // factors >= 1.0 we first round up the factor, then apply a multiplier (< 1.0). We reflect
        // this limitation in our tested maximum value.
        for f in (1..=10).map(|n| n * 100_000_000) {
            // Truncate the remainder since prev_power_of_two rounds down anyway.
            let factor = 1_000_000_000 / f;
            // This is like (exp2(floor(log2(factor)) + 1)).
            let target = u64::MAX / (prev_power_of_two(factor) << 1);
            check_freq_scale(f, target);
        }
    }
}
