// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! vmwdt is a virtual watchdog memory mapped device which detects stalls
//! on the vCPUs and resets the guest when no 'pet' events are received.
//! <https://docs.google.com/document/d/1DYmk2roxlwHZsOfcJi8xDMdWOHAmomvs2SDh7KPud3Y/edit?usp=sharing&resourcekey=0-oSNabc-t040a1q0K4cyI8Q>

use std::collections::BTreeMap;
use std::convert::TryFrom;
use std::fs;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use base::custom_serde::serialize_arc_mutex;
use base::debug;
use base::error;
use base::warn;
use base::AsRawDescriptor;
use base::Descriptor;
use base::Error as SysError;
use base::Event;
use base::EventToken;
use base::SendTube;
use base::Timer;
use base::TimerTrait;
use base::Tube;
use base::VmEventType;
use base::WaitContext;
use base::WorkerThread;
use serde::Deserialize;
use serde::Serialize;
use sync::Mutex;
use vm_control::VmResponse;

use crate::pci::CrosvmDeviceId;
use crate::BusAccessInfo;
use crate::BusDevice;
use crate::DeviceId;
use crate::IrqEdgeEvent;
use crate::Suspendable;

// Registers offsets
const VMWDT_REG_STATUS: u32 = 0x00;
const VMWDT_REG_LOAD_CNT: u32 = 0x04;
const VMWDT_REG_CURRENT_CNT: u32 = 0x08;
const VMWDT_REG_CLOCK_FREQ_HZ: u32 = 0x0C;

// Length of the registers
const VMWDT_REG_LEN: u64 = 0x10;

pub const VMWDT_DEFAULT_TIMEOUT_SEC: u32 = 10;
pub const VMWDT_DEFAULT_CLOCK_HZ: u32 = 2;

// Proc stat indexes
const PROCSTAT_GUEST_TIME_INDX: usize = 42;

#[derive(Serialize)]
pub struct VmwdtPerCpu {
    // Flag which indicated if the watchdog is started
    is_enabled: bool,
    // Timer used to generate periodic events at `timer_freq_hz` frequency
    #[serde(skip_serializing)]
    timer: Timer,
    // The frequency of the `timer`
    timer_freq_hz: u64,
    // Timestamp measured in miliseconds of the last guest activity
    last_guest_time_ms: i64,
    // The thread_id of the thread this vcpu belongs to
    thread_id: u32,
    // The process id of the task this vcpu belongs to
    process_id: u32,
    // The pre-programmed one-shot expiration interval. If the guest runs in this
    // interval but we don't receive a periodic event, the guest is stalled.
    next_expiration_interval_ms: i64,
    // Keep track if the watchdog PPI raised.
    stall_evt_ppi_triggered: bool,
    // Keep track if the time was armed with oneshot mode or with repeating interval
    repeating_interval: Option<Duration>,
}

#[derive(Deserialize)]
struct VmwdtPerCpuRestore {
    is_enabled: bool,
    timer_freq_hz: u64,
    last_guest_time_ms: i64,
    next_expiration_interval_ms: i64,
    repeating_interval: Option<Duration>,
}

pub struct Vmwdt {
    vm_wdts: Arc<Mutex<Vec<VmwdtPerCpu>>>,
    // The worker thread that waits on the timer fd
    worker_thread: Option<WorkerThread<Tube>>,
    // TODO: @sebastianene add separate reset event for the watchdog
    // Reset source if the device is not responding
    reset_evt_wrtube: SendTube,
    activated: bool,
    // Event to be used to interrupt the guest on detected stalls
    stall_evt: IrqEdgeEvent,
    vm_ctrl_tube: Option<Tube>,
}

#[derive(Serialize)]
struct VmwdtSnapshot {
    #[serde(serialize_with = "serialize_arc_mutex")]
    vm_wdts: Arc<Mutex<Vec<VmwdtPerCpu>>>,
    activated: bool,
}

#[derive(Deserialize)]
struct VmwdtRestore {
    vm_wdts: Vec<VmwdtPerCpuRestore>,
    activated: bool,
}

impl Vmwdt {
    pub fn new(
        cpu_count: usize,
        reset_evt_wrtube: SendTube,
        evt: IrqEdgeEvent,
        vm_ctrl_tube: Tube,
    ) -> anyhow::Result<Vmwdt> {
        let mut vec = Vec::new();
        for _ in 0..cpu_count {
            vec.push(VmwdtPerCpu {
                last_guest_time_ms: 0,
                thread_id: 0,
                process_id: 0,
                is_enabled: false,
                stall_evt_ppi_triggered: false,
                timer: Timer::new().context("failed to create Timer")?,
                timer_freq_hz: 0,
                next_expiration_interval_ms: 0,
                repeating_interval: None,
            });
        }
        let vm_wdts = Arc::new(Mutex::new(vec));

        Ok(Vmwdt {
            vm_wdts,
            worker_thread: None,
            reset_evt_wrtube,
            activated: false,
            stall_evt: evt,
            vm_ctrl_tube: Some(vm_ctrl_tube),
        })
    }

    pub fn vmwdt_worker_thread(
        vm_wdts: Arc<Mutex<Vec<VmwdtPerCpu>>>,
        kill_evt: Event,
        reset_evt_wrtube: SendTube,
        stall_evt: IrqEdgeEvent,
        vm_ctrl_tube: Tube,
        worker_started_send: Option<SendTube>,
    ) -> anyhow::Result<Tube> {
        let msg = vm_control::VmRequest::VcpuPidTid;
        vm_ctrl_tube
            .send(&msg)
            .context("failed to send request to fetch Vcpus PID and TID")?;
        let vcpus_pid_tid: BTreeMap<usize, (u32, u32)> = match vm_ctrl_tube
            .recv()
            .context("failed to receive vmwdt pids and tids")?
        {
            VmResponse::VcpuPidTidResponse { pid_tid_map } => pid_tid_map,
            _ => {
                return Err(anyhow::anyhow!(
                    "Receive incorrect message type when trying to get vcpu pid tid map"
                ));
            }
        };
        {
            let mut vm_wdts = vm_wdts.lock();
            for (i, vmwdt) in (*vm_wdts).iter_mut().enumerate() {
                let pid_tid = vcpus_pid_tid
                    .get(&i)
                    .context("vmwdts empty, which could indicate no vcpus are initialized")?;
                vmwdt.process_id = pid_tid.0;
                vmwdt.thread_id = pid_tid.1;
            }
        }
        if let Some(worker_started_send) = worker_started_send {
            worker_started_send
                .send(&())
                .context("failed to send vmwdt worker started")?;
        }
        #[derive(EventToken)]
        enum Token {
            Kill,
            Timer(usize),
        }

        let wait_ctx: WaitContext<Token> =
            WaitContext::new().context("Failed to create wait_ctx")?;
        wait_ctx
            .add(&kill_evt, Token::Kill)
            .context("Failed to add Tokens to wait_ctx")?;

        let len = vm_wdts.lock().len();
        for clock_id in 0..len {
            let timer_fd = vm_wdts.lock()[clock_id].timer.as_raw_descriptor();
            wait_ctx
                .add(&Descriptor(timer_fd), Token::Timer(clock_id))
                .context("Failed to link FDs to Tokens")?;
        }

        loop {
            let events = wait_ctx.wait().context("Failed to wait for events")?;
            for event in events.iter().filter(|e| e.is_readable) {
                match event.token {
                    Token::Kill => {
                        return Ok(vm_ctrl_tube);
                    }
                    Token::Timer(cpu_id) => {
                        let mut wdts_locked = vm_wdts.lock();
                        let watchdog = &mut wdts_locked[cpu_id];
                        if let Err(_e) = watchdog.timer.wait() {
                            error!("error waiting for timer event on vcpu {}", cpu_id);
                        }

                        let current_guest_time_ms =
                            Vmwdt::get_guest_time_ms(watchdog.process_id, watchdog.thread_id)
                                .context("get_guest_time_ms failed")?;
                        let remaining_time_ms = watchdog.next_expiration_interval_ms
                            - (current_guest_time_ms - watchdog.last_guest_time_ms);

                        if remaining_time_ms > 0 {
                            watchdog.next_expiration_interval_ms = remaining_time_ms;
                            if let Err(e) = watchdog
                                .timer
                                .reset_oneshot(Duration::from_millis(remaining_time_ms as u64))
                            {
                                error!(
                                    "failed to reset internal timer on vcpu {}: {:#}",
                                    cpu_id, e
                                );
                            }
                            watchdog.repeating_interval = None;
                        } else {
                            if watchdog.stall_evt_ppi_triggered {
                                if let Err(e) = reset_evt_wrtube
                                    .send::<VmEventType>(&VmEventType::WatchdogReset)
                                {
                                    error!("{} failed to send reset event from vcpu {}", e, cpu_id)
                                }
                            }

                            stall_evt
                                .trigger()
                                .context("Failed to trigger stall event")?;
                            watchdog.stall_evt_ppi_triggered = true;
                            watchdog.last_guest_time_ms = current_guest_time_ms;
                        }
                    }
                }
            }
        }
    }

    fn start(&mut self, worker_started_send: Option<SendTube>) -> anyhow::Result<()> {
        let vm_wdts = self.vm_wdts.clone();
        let reset_evt_wrtube = self.reset_evt_wrtube.try_clone().unwrap();
        let stall_event = self.stall_evt.try_clone().unwrap();
        let vm_ctrl_tube = self
            .vm_ctrl_tube
            .take()
            .context("missing vm control tube")?;

        self.activated = true;
        self.worker_thread = Some(WorkerThread::start("vmwdt worker", |kill_evt| {
            Vmwdt::vmwdt_worker_thread(
                vm_wdts,
                kill_evt,
                reset_evt_wrtube,
                stall_event,
                vm_ctrl_tube,
                worker_started_send,
            )
            .expect("failed to start vmwdt worker thread")
        }));
        Ok(())
    }

    fn ensure_started(&mut self) {
        if self.worker_thread.is_some() {
            return;
        }

        let (worker_started_send, worker_started_recv) =
            Tube::directional_pair().expect("failed to create vmwdt worker started tubes");
        self.start(Some(worker_started_send))
            .expect("failed to start Vmwdt");
        worker_started_recv
            .recv::<()>()
            .expect("failed to receive vmwdt worker started");
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    pub fn get_guest_time_ms(process_id: u32, thread_id: u32) -> Result<i64, SysError> {
        // TODO: @sebastianene check if we can avoid open-read-close on each call
        let stat_path = format!("/proc/{}/task/{}/stat", process_id, thread_id);
        let contents = fs::read_to_string(stat_path)?;

        let gtime_ticks = contents
            .split_whitespace()
            .nth(PROCSTAT_GUEST_TIME_INDX)
            .and_then(|guest_time| guest_time.parse::<u64>().ok())
            .unwrap_or(0);

        // SAFETY:
        // Safe because this just returns an integer
        let ticks_per_sec = unsafe { libc::sysconf(libc::_SC_CLK_TCK) } as u64;
        Ok((gtime_ticks * 1000 / ticks_per_sec) as i64)
    }

    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    pub fn get_guest_time_ms(process_id: u32, thread_id: u32) -> Result<i64, SysError> {
        Ok(0)
    }
}

impl BusDevice for Vmwdt {
    fn debug_label(&self) -> String {
        "Vmwdt".to_owned()
    }

    fn device_id(&self) -> DeviceId {
        CrosvmDeviceId::VmWatchdog.into()
    }

    fn read(&mut self, _offset: BusAccessInfo, _data: &mut [u8]) {}

    fn write(&mut self, info: BusAccessInfo, data: &[u8]) {
        let data_array = match <&[u8; 4]>::try_from(data) {
            Ok(array) => array,
            _ => {
                error!("Bad write size: {} for vmwdt", data.len());
                return;
            }
        };

        let reg_val = u32::from_ne_bytes(*data_array);
        let cpu_index: usize = (info.offset / VMWDT_REG_LEN) as usize;
        let reg_offset = (info.offset % VMWDT_REG_LEN) as u32;

        if cpu_index > self.vm_wdts.lock().len() {
            error!("Bad write cpu_index {}", cpu_index);
            return;
        }

        match reg_offset {
            VMWDT_REG_STATUS => {
                self.ensure_started();
                let mut wdts_locked = self.vm_wdts.lock();
                let cpu_watchdog = &mut wdts_locked[cpu_index];

                cpu_watchdog.is_enabled = reg_val != 0;

                if reg_val != 0 {
                    let interval = Duration::from_millis(1000 / cpu_watchdog.timer_freq_hz);
                    cpu_watchdog.repeating_interval = Some(interval);
                    cpu_watchdog
                        .timer
                        .reset_repeating(interval)
                        .expect("Failed to reset timer repeating interval");
                } else {
                    cpu_watchdog.repeating_interval = None;
                    cpu_watchdog
                        .timer
                        .clear()
                        .expect("Failed to clear cpu watchdog timer");
                }
            }
            VMWDT_REG_LOAD_CNT => {
                self.ensure_started();
                let (process_id, thread_id) = {
                    let mut wdts_locked = self.vm_wdts.lock();
                    let cpu_watchdog = &mut wdts_locked[cpu_index];
                    (cpu_watchdog.process_id, cpu_watchdog.thread_id)
                };
                let guest_time_ms = Vmwdt::get_guest_time_ms(process_id, thread_id)
                    .expect("get_guest_time_ms failed");

                let mut wdts_locked = self.vm_wdts.lock();
                let cpu_watchdog = &mut wdts_locked[cpu_index];
                let next_expiration_interval_ms =
                    reg_val as u64 * 1000 / cpu_watchdog.timer_freq_hz;

                cpu_watchdog.last_guest_time_ms = guest_time_ms;
                cpu_watchdog.stall_evt_ppi_triggered = false;
                cpu_watchdog.next_expiration_interval_ms = next_expiration_interval_ms as i64;

                if cpu_watchdog.is_enabled {
                    if let Err(_e) = cpu_watchdog
                        .timer
                        .reset_oneshot(Duration::from_millis(next_expiration_interval_ms))
                    {
                        error!("failed to reset one-shot vcpu time {}", cpu_index);
                    }
                    cpu_watchdog.repeating_interval = None;
                }
            }
            VMWDT_REG_CURRENT_CNT => {
                warn!("invalid write to read-only VMWDT_REG_CURRENT_CNT register");
            }
            VMWDT_REG_CLOCK_FREQ_HZ => {
                let mut wdts_locked = self.vm_wdts.lock();
                let cpu_watchdog = &mut wdts_locked[cpu_index];

                debug!(
                    "CPU:{:x} wrote VMWDT_REG_CLOCK_FREQ_HZ {:x}",
                    cpu_index, reg_val
                );
                cpu_watchdog.timer_freq_hz = reg_val as u64;
            }
            _ => unreachable!(),
        }
    }
}

impl Suspendable for Vmwdt {
    fn sleep(&mut self) -> anyhow::Result<()> {
        if let Some(worker) = self.worker_thread.take() {
            self.vm_ctrl_tube = Some(worker.stop());
        }
        Ok(())
    }

    fn wake(&mut self) -> anyhow::Result<()> {
        if self.activated {
            // We do not pass a tube to notify that the worker thread has started on wake.
            // At this stage, vm_control is blocked on resuming devices and cannot provide the vcpu
            // PIDs/TIDs yet.
            // At the same time, the Vcpus are still frozen, which means no MMIO will get
            // processed, and write will not get triggered.
            // The request to get PIDs/TIDs should get processed before any MMIO request occurs.
            self.start(None)?;
            let mut vm_wdts = self.vm_wdts.lock();
            for vmwdt in vm_wdts.iter_mut() {
                if let Some(interval) = &vmwdt.repeating_interval {
                    vmwdt
                        .timer
                        .reset_repeating(*interval)
                        .context("failed to write repeating interval")?;
                } else if vmwdt.is_enabled {
                    vmwdt
                        .timer
                        .reset_oneshot(Duration::from_millis(
                            vmwdt.next_expiration_interval_ms as u64,
                        ))
                        .context("failed to write oneshot interval")?;
                }
            }
        }
        Ok(())
    }

    fn snapshot(&mut self) -> anyhow::Result<serde_json::Value> {
        serde_json::to_value(&VmwdtSnapshot {
            vm_wdts: self.vm_wdts.clone(),
            activated: self.activated,
        })
        .context("failed to snapshot Vmwdt")
    }

    fn restore(&mut self, data: serde_json::Value) -> anyhow::Result<()> {
        let deser: VmwdtRestore =
            serde_json::from_value(data).context("failed to deserialize Vmwdt")?;
        let mut vm_wdts = self.vm_wdts.lock();
        for (vmwdt_restore, vmwdt) in deser.vm_wdts.iter().zip(vm_wdts.iter_mut()) {
            vmwdt.is_enabled = vmwdt_restore.is_enabled;
            vmwdt.timer_freq_hz = vmwdt_restore.timer_freq_hz;
            vmwdt.last_guest_time_ms = vmwdt_restore.last_guest_time_ms;
            vmwdt.next_expiration_interval_ms = vmwdt_restore.next_expiration_interval_ms;
            vmwdt.repeating_interval = vmwdt_restore.repeating_interval;
        }
        self.activated = deser.activated;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::process;
    use std::thread::sleep;

    #[cfg(any(target_os = "linux", target_os = "android"))]
    use base::gettid;
    use base::poll_assert;
    use base::Tube;

    use super::*;

    const AARCH64_VMWDT_ADDR: u64 = 0x3000;
    const TEST_VMWDT_CPU_NO: usize = 0x1;

    fn vmwdt_bus_address(offset: u64) -> BusAccessInfo {
        BusAccessInfo {
            offset,
            address: AARCH64_VMWDT_ADDR,
            id: 0,
        }
    }

    #[test]
    fn test_watchdog_internal_timer() {
        let (vm_evt_wrtube, _vm_evt_rdtube) = Tube::directional_pair().unwrap();
        let (vm_ctrl_wrtube, vm_ctrl_rdtube) = Tube::pair().unwrap();
        let irq = IrqEdgeEvent::new().unwrap();
        #[cfg(any(target_os = "linux", target_os = "android"))]
        {
            vm_ctrl_wrtube
                .send(&VmResponse::VcpuPidTidResponse {
                    pid_tid_map: BTreeMap::from([(0, (process::id(), gettid() as u32))]),
                })
                .unwrap();
        }
        let mut device = Vmwdt::new(TEST_VMWDT_CPU_NO, vm_evt_wrtube, irq, vm_ctrl_rdtube).unwrap();

        // Configure the watchdog device, 2Hz internal clock
        device.write(
            vmwdt_bus_address(VMWDT_REG_CLOCK_FREQ_HZ as u64),
            &[10, 0, 0, 0],
        );
        device.write(vmwdt_bus_address(VMWDT_REG_LOAD_CNT as u64), &[1, 0, 0, 0]);
        device.write(vmwdt_bus_address(VMWDT_REG_STATUS as u64), &[1, 0, 0, 0]);
        let next_expiration_ms = {
            let mut vmwdt_locked = device.vm_wdts.lock();
            // In the test scenario the guest does not interpret the /proc/stat::guest_time, thus
            // the function get_guest_time() returns 0
            vmwdt_locked[0].last_guest_time_ms = 10;
            vmwdt_locked[0].next_expiration_interval_ms
        };

        // Poll multiple times as we don't get a signal when the watchdog thread has run.
        poll_assert!(10, || {
            sleep(Duration::from_millis(50));
            let vmwdt_locked = device.vm_wdts.lock();
            // Verify that our timer expired and the next_expiration_interval_ms changed
            vmwdt_locked[0].next_expiration_interval_ms != next_expiration_ms
        });
    }

    #[test]
    fn test_watchdog_expiration() {
        let (vm_evt_wrtube, vm_evt_rdtube) = Tube::directional_pair().unwrap();
        let (vm_ctrl_wrtube, vm_ctrl_rdtube) = Tube::pair().unwrap();
        let irq = IrqEdgeEvent::new().unwrap();
        #[cfg(any(target_os = "linux", target_os = "android"))]
        {
            vm_ctrl_wrtube
                .send(&VmResponse::VcpuPidTidResponse {
                    pid_tid_map: BTreeMap::from([(0, (process::id(), gettid() as u32))]),
                })
                .unwrap();
        }
        let mut device = Vmwdt::new(TEST_VMWDT_CPU_NO, vm_evt_wrtube, irq, vm_ctrl_rdtube).unwrap();

        // Configure the watchdog device, 2Hz internal clock
        device.write(
            vmwdt_bus_address(VMWDT_REG_CLOCK_FREQ_HZ as u64),
            &[10, 0, 0, 0],
        );
        device.write(vmwdt_bus_address(VMWDT_REG_LOAD_CNT as u64), &[1, 0, 0, 0]);
        device.write(vmwdt_bus_address(VMWDT_REG_STATUS as u64), &[1, 0, 0, 0]);
        // In the test scenario the guest does not interpret the /proc/stat::guest_time, thus
        // the function get_guest_time() returns 0
        device.vm_wdts.lock()[0].last_guest_time_ms = -100;

        // Check that the interrupt has raised
        poll_assert!(10, || {
            sleep(Duration::from_millis(50));
            let vmwdt_locked = device.vm_wdts.lock();
            vmwdt_locked[0].stall_evt_ppi_triggered
        });

        // Simulate that the time has passed since the last expiration
        device.vm_wdts.lock()[0].last_guest_time_ms = -100;

        // Poll multiple times as we don't get a signal when the watchdog thread has run.
        poll_assert!(10, || {
            sleep(Duration::from_millis(50));
            match vm_evt_rdtube.recv::<VmEventType>() {
                Ok(vm_event) => vm_event == VmEventType::WatchdogReset,
                Err(_e) => false,
            }
        });
    }
}
