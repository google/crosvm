// Copyright 2022 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! vmwdt is a virtual watchdog memory mapped device which detects stalls
//! on the vCPUs and resets the guest when no 'pet' events are received.
//! <https://docs.google.com/document/d/1DYmk2roxlwHZsOfcJi8xDMdWOHAmomvs2SDh7KPud3Y/edit?usp=sharing&resourcekey=0-oSNabc-t040a1q0K4cyI8Q>

use crate::pci::CrosvmDeviceId;
use crate::DeviceId;
use crate::{BusAccessInfo, BusDevice};
use base::{
    debug, error, gettid, warn, AsRawDescriptor, Descriptor, Error as SysError, Event, EventToken,
    SendTube, Timer, VmEventType, WaitContext,
};

use remain::sorted;
use std::convert::TryFrom;
use std::io::Error as IoError;
use std::process;
use std::sync::Arc;
use std::time::Duration;
use std::{fs, thread};
use sync::Mutex;
use thiserror::Error;

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
const PROCSTAT_UTIME_INDX: usize = 13;
const PROCSTAT_GUEST_TIME_INDX: usize = 42;

#[sorted]
#[derive(Error, Debug)]
pub enum VmwdtError {
    /// Error while creating event.
    #[error("failed to create event: {0}")]
    CreateEvent(SysError),
    /// Error while trying to create worker thread.
    #[error("failed to spawn thread: {0}")]
    SpawnThread(IoError),
    /// Error while trying to create timer.
    #[error("failed to create vmwdt counter due to timer fd: {0}")]
    TimerCreateError(SysError),
    #[error("failed to wait for events: {0}")]
    WaitError(SysError),
}

type VmwdtResult<T> = std::result::Result<T, VmwdtError>;

pub struct VmwdtPerCpu {
    // Flag which indicated if the watchdog is started
    is_enabled: bool,
    // Counter value decremented periodically by the timer
    counter: i32,
    // Timer used to generate periodic events at `timer_freq_hz` frequency
    timer: Timer,
    // The frequency of the `timer`
    timer_freq_hz: u64,
    // Timestamp measured in systicks which is updated with every `pet` event
    // that tells how many ticks were lost while guest is not running
    not_running_last_timestamp: u64,
}

pub struct Vmwdt {
    vm_wdts: Arc<Mutex<Vec<VmwdtPerCpu>>>,
    // The worker thread that waits on the timer fd
    worker_thread: Option<thread::JoinHandle<()>>,
    // An event used to signal background thread cancellation
    kill_evt: Event,
    // TODO: @sebastianene add separate reset event for the watchdog
    // Reset source if the device is not responding
    reset_evt_wrtube: SendTube,
}

impl Vmwdt {
    pub fn new(cpu_count: usize, reset_evt_wrtube: SendTube) -> VmwdtResult<Vmwdt> {
        let mut vec = Vec::new();
        for _ in 0..cpu_count {
            vec.push(VmwdtPerCpu {
                counter: 0,
                not_running_last_timestamp: 0,
                is_enabled: false,
                timer: Timer::new().unwrap(),
                timer_freq_hz: 0,
            });
        }
        let vm_wdts = Arc::new(Mutex::new(vec));

        // Create a new event that will be used to notify the bg thread for exit
        let kill_evt = Event::new().unwrap();
        Ok(Vmwdt {
            vm_wdts,
            worker_thread: None,
            kill_evt,
            reset_evt_wrtube,
        })
    }

    pub fn vmwdt_worker_thread(
        vm_wdts: Arc<Mutex<Vec<VmwdtPerCpu>>>,
        kill_evt: Event,
        reset_evt_wrtube: SendTube,
    ) {
        #[derive(EventToken)]
        enum Token {
            Kill,
            Timer(usize),
        }

        let wait_ctx: WaitContext<Token> = WaitContext::new().unwrap();
        wait_ctx.add(&kill_evt, Token::Kill).unwrap();
        let mut interrupt_active = false;

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
                    Token::Timer(clock_id) => {
                        let cnt = {
                            let mut wdts_locked = vm_wdts.lock();
                            let mut watchdog = &mut wdts_locked[clock_id];
                            if let Err(_e) = watchdog.timer.wait() {
                                error!("error waiting for timer event");
                            }
                            watchdog.counter -= 1;
                            watchdog.counter
                        };

                        if cnt <= 0 {
                            // vCPU is not petting the watchdog fast enough, reset vm
                            warn!("clock {} detected stall {}", clock_id, cnt);

                            if !interrupt_active {
                                if let Err(_e) =
                                    reset_evt_wrtube.send::<VmEventType>(&VmEventType::Reset)
                                {
                                    error!("failed to send reset event")
                                }
                                interrupt_active = true;
                            }
                        }
                    }
                }
            }
        }
    }

    fn start(&mut self) {
        let vm_wdts = self.vm_wdts.clone();
        let kill_evt = self.kill_evt.try_clone().unwrap();
        let reset_evt_wrtube = self.reset_evt_wrtube.try_clone().unwrap();

        self.worker_thread = Some(
            thread::Builder::new()
                .name("vmwdt worker".into())
                .spawn(|| Vmwdt::vmwdt_worker_thread(vm_wdts, kill_evt, reset_evt_wrtube))
                .map_err(VmwdtError::SpawnThread)
                .unwrap(),
        );
    }

    fn ensure_started(&mut self) {
        if self.worker_thread.is_some() {
            return;
        }

        self.start();
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    fn get_nonrunning_time_ms(&mut self, cpu_id: usize) -> u64 {
        let ppid = process::id();
        let pid = gettid();

        // TODO: @sebastianene check if we can avoid open-read-close on each call
        let stat_path = format!("/proc/{}/task/{}/stat", ppid, pid);
        let contents = fs::read_to_string(stat_path).expect("error reading the stat");

        let coll: Vec<_> = contents.split_whitespace().collect();
        let utime = coll[PROCSTAT_UTIME_INDX].parse::<u64>();
        let guest_time = coll[PROCSTAT_GUEST_TIME_INDX].parse::<u64>();

        // The lost time since the last tick event
        let mut non_guest_time_delta: u64 = 0;
        let utime_ticks = match utime {
            Err(_e) => return 0,
            Ok(f) => f,
        };
        let gtime_ticks = match guest_time {
            Err(_e) => return 0,
            Ok(f) => f,
        };

        if utime_ticks > gtime_ticks {
            // Time that the guest is not running measured in systicks
            let non_guest_time = utime_ticks - gtime_ticks;
            non_guest_time_delta = {
                let mut vm_wdts_locked = self.vm_wdts.lock();
                let not_running_last_timestamp = vm_wdts_locked[cpu_id].not_running_last_timestamp;

                if non_guest_time > not_running_last_timestamp {
                    // Save the current timestamp
                    vm_wdts_locked[cpu_id].not_running_last_timestamp = non_guest_time;
                    non_guest_time - not_running_last_timestamp
                } else {
                    0
                }
            };
        }

        // Safe because this just returns an integer
        let ticks_per_sec = unsafe { libc::sysconf(libc::_SC_CLK_TCK) } as u64;
        non_guest_time_delta * 1000 / ticks_per_sec
    }

    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    fn get_nonrunning_time_ms(&mut self, cpu_id: usize) -> u64 {
        0
    }
}

impl Drop for Vmwdt {
    fn drop(&mut self) {
        if let Err(e) = self.kill_evt.write(1) {
            error!("Failed to stop the bg thread: {}", e);
            return;
        }

        if let Some(thread) = self.worker_thread.take() {
            match thread.join() {
                Ok(_) => {
                    debug!("Stopped the bg thread\n");
                }
                Err(_) => {
                    error!("Failed to stop the bg thread");
                }
            }
        }
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

        let mut reg_val = u32::from_ne_bytes(*data_array);
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
                let mut cpu_watchdog = &mut wdts_locked[cpu_index];

                cpu_watchdog.is_enabled = reg_val != 0;

                if reg_val != 0 {
                    let due = Duration::from_nanos(1);
                    let interval =
                        Duration::from_millis((1000 / cpu_watchdog.timer_freq_hz) as u64);
                    cpu_watchdog.timer.reset(due, Some(interval)).unwrap();
                } else {
                    cpu_watchdog.timer.clear().unwrap();
                }
            }
            VMWDT_REG_LOAD_CNT => {
                // Account for lost time(Time that the guest is not running)
                let not_running_time_ms = self.get_nonrunning_time_ms(cpu_index);
                let mut wdts_locked = self.vm_wdts.lock();
                let mut cpu_watchdog = &mut wdts_locked[cpu_index];

                if not_running_time_ms > 0 {
                    reg_val += (not_running_time_ms * cpu_watchdog.timer_freq_hz / 1000) as u32;
                }

                cpu_watchdog.counter = reg_val as i32;
                if cpu_watchdog.is_enabled {
                    let due = Duration::from_nanos(1);
                    let interval =
                        Duration::from_millis((1000 / cpu_watchdog.timer_freq_hz) as u64);
                    cpu_watchdog.timer.reset(due, Some(interval)).unwrap();
                }
            }
            VMWDT_REG_CURRENT_CNT => {
                warn!("invalid write to read-only VMWDT_REG_CURRENT_CNT register");
            }
            VMWDT_REG_CLOCK_FREQ_HZ => {
                let mut wdts_locked = self.vm_wdts.lock();
                let mut cpu_watchdog = &mut wdts_locked[cpu_index];

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
