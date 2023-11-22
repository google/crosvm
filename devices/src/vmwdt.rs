// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! vmwdt is a virtual watchdog memory mapped device which detects stalls
//! on the vCPUs and resets the guest when no 'pet' events are received.
//! <https://docs.google.com/document/d/1DYmk2roxlwHZsOfcJi8xDMdWOHAmomvs2SDh7KPud3Y/edit?usp=sharing&resourcekey=0-oSNabc-t040a1q0K4cyI8Q>

use std::convert::TryFrom;
use std::fs;
use std::process;
use std::sync::Arc;
use std::time::Duration;

use base::debug;
use base::error;
use base::gettid;
use base::warn;
use base::AsRawDescriptor;
use base::Descriptor;
use base::Error as SysError;
use base::Event;
use base::EventToken;
use base::SendTube;
use base::Timer;
use base::TimerTrait;
use base::VmEventType;
use base::WaitContext;
use base::WorkerThread;
use sync::Mutex;

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

pub struct VmwdtPerCpu {
    // Flag which indicated if the watchdog is started
    is_enabled: bool,
    // Timer used to generate periodic events at `timer_freq_hz` frequency
    timer: Timer,
    // The frequency of the `timer`
    timer_freq_hz: u64,
    // Timestamp measured in miliseconds of the last guest activity
    last_guest_time_ms: i64,
    // The pid of the thread this vcpu belongs to
    pid: u32,
    // The process id of the task this vcpu belongs to
    ppid: u32,
    // The pre-programmed one-shot expiration interval. If the guest runs in this
    // interval but we don't receive a periodic event, the guest is stalled.
    next_expiration_interval_ms: i64,
    // Keep track if the watchdog PPI raised.
    stall_evt_ppi_triggered: bool,
}

pub struct Vmwdt {
    vm_wdts: Arc<Mutex<Vec<VmwdtPerCpu>>>,
    // The worker thread that waits on the timer fd
    worker_thread: Option<WorkerThread<()>>,
    // TODO: @sebastianene add separate reset event for the watchdog
    // Reset source if the device is not responding
    reset_evt_wrtube: SendTube,
    activated: bool,
    // Event to be used to interrupt the guest on detected stalls
    stall_evt: IrqEdgeEvent,
}

impl Vmwdt {
    pub fn new(cpu_count: usize, reset_evt_wrtube: SendTube, evt: IrqEdgeEvent) -> Vmwdt {
        let mut vec = Vec::new();
        for _ in 0..cpu_count {
            vec.push(VmwdtPerCpu {
                last_guest_time_ms: 0,
                pid: 0,
                ppid: 0,
                is_enabled: false,
                stall_evt_ppi_triggered: false,
                timer: Timer::new().unwrap(),
                timer_freq_hz: 0,
                next_expiration_interval_ms: 0,
            });
        }
        let vm_wdts = Arc::new(Mutex::new(vec));

        Vmwdt {
            vm_wdts,
            worker_thread: None,
            reset_evt_wrtube,
            activated: false,
            stall_evt: evt,
        }
    }

    pub fn vmwdt_worker_thread(
        vm_wdts: Arc<Mutex<Vec<VmwdtPerCpu>>>,
        kill_evt: Event,
        reset_evt_wrtube: SendTube,
        stall_evt: IrqEdgeEvent,
    ) {
        #[derive(EventToken)]
        enum Token {
            Kill,
            Timer(usize),
        }

        let wait_ctx: WaitContext<Token> = WaitContext::new().unwrap();
        wait_ctx.add(&kill_evt, Token::Kill).unwrap();

        let len = vm_wdts.lock().len();
        for clock_id in 0..len {
            let timer_fd = vm_wdts.lock()[clock_id].timer.as_raw_descriptor();
            wait_ctx
                .add(&Descriptor(timer_fd), Token::Timer(clock_id))
                .unwrap();
        }

        loop {
            let events = wait_ctx.wait().unwrap();
            for event in events.iter().filter(|e| e.is_readable) {
                match event.token {
                    Token::Kill => {
                        return;
                    }
                    Token::Timer(cpu_id) => {
                        let mut wdts_locked = vm_wdts.lock();
                        let watchdog = &mut wdts_locked[cpu_id];
                        if let Err(_e) = watchdog.timer.wait() {
                            error!("error waiting for timer event on vcpu {}", cpu_id);
                        }

                        let current_guest_time_ms_result =
                            Vmwdt::get_guest_time_ms(watchdog.ppid, watchdog.pid);
                        let current_guest_time_ms = match current_guest_time_ms_result {
                            Ok(value) => value,
                            Err(_e) => return,
                        };
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
                        } else {
                            if watchdog.stall_evt_ppi_triggered {
                                if let Err(e) = reset_evt_wrtube
                                    .send::<VmEventType>(&VmEventType::WatchdogReset)
                                {
                                    error!("{} failed to send reset event from vcpu {}", e, cpu_id)
                                }
                            }

                            stall_evt.trigger().unwrap();
                            watchdog.stall_evt_ppi_triggered = true;
                            watchdog.last_guest_time_ms = current_guest_time_ms;
                        }
                    }
                }
            }
        }
    }

    fn start(&mut self) {
        let vm_wdts = self.vm_wdts.clone();
        let reset_evt_wrtube = self.reset_evt_wrtube.try_clone().unwrap();
        let stall_event = self.stall_evt.try_clone().unwrap();

        self.activated = true;
        self.worker_thread = Some(WorkerThread::start("vmwdt worker", |kill_evt| {
            Vmwdt::vmwdt_worker_thread(vm_wdts, kill_evt, reset_evt_wrtube, stall_event)
        }));
    }

    fn ensure_started(&mut self) {
        if self.worker_thread.is_some() {
            return;
        }

        self.start();
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    pub fn get_guest_time_ms(ppid: u32, pid: u32) -> Result<i64, SysError> {
        // TODO: @sebastianene check if we can avoid open-read-close on each call
        let stat_path = format!("/proc/{}/task/{}/stat", ppid, pid);
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
    pub fn get_guest_time_ms(ppid: u32, pid: u32) -> Result<i64, SysError> {
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
                    cpu_watchdog.timer.reset_repeating(interval).unwrap();
                } else {
                    cpu_watchdog.timer.clear().unwrap();
                }
            }
            VMWDT_REG_LOAD_CNT => {
                let ppid = process::id();
                let pid = gettid();
                let guest_time_ms_result = Vmwdt::get_guest_time_ms(ppid, pid as u32);
                let guest_time_ms = match guest_time_ms_result {
                    Ok(time) => time,
                    Err(_e) => return,
                };

                let mut wdts_locked = self.vm_wdts.lock();
                let cpu_watchdog = &mut wdts_locked[cpu_index];
                let next_expiration_interval_ms =
                    reg_val as u64 * 1000 / cpu_watchdog.timer_freq_hz;

                cpu_watchdog.pid = pid as u32;
                cpu_watchdog.ppid = ppid;
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
            worker.stop();
        }
        Ok(())
    }

    fn wake(&mut self) -> anyhow::Result<()> {
        if self.activated {
            self.start();
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::thread::sleep;

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
        let irq = IrqEdgeEvent::new().unwrap();
        let mut device = Vmwdt::new(TEST_VMWDT_CPU_NO, vm_evt_wrtube, irq);

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
        let irq = IrqEdgeEvent::new().unwrap();
        let mut device = Vmwdt::new(TEST_VMWDT_CPU_NO, vm_evt_wrtube, irq);

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
