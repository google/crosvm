// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! vmwdt is a virtual watchdog memory mapped device which detects stalls
//! on the vCPUs and resets the guest when no 'pet' events are received.
//! <https://docs.google.com/document/d/1DYmk2roxlwHZsOfcJi8xDMdWOHAmomvs2SDh7KPud3Y/edit?usp=sharing&resourcekey=0-oSNabc-t040a1q0K4cyI8Q>

use std::convert::TryFrom;
use std::fs;
use std::io::Error as IoError;
use std::process;
use std::sync::Arc;
use std::thread;
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
use base::VmEventType;
use base::WaitContext;
use remain::sorted;
use sync::Mutex;
use thiserror::Error;

use crate::pci::CrosvmDeviceId;
use crate::BusAccessInfo;
use crate::BusDevice;
use crate::DeviceId;

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
                last_guest_time_ms: 0,
                pid: 0,
                ppid: 0,
                is_enabled: false,
                timer: Timer::new().unwrap(),
                timer_freq_hz: 0,
                next_expiration_interval_ms: 0,
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
                        let mut watchdog = &mut wdts_locked[cpu_id];
                        if let Err(_e) = watchdog.timer.wait() {
                            error!("error waiting for timer event on vcpu {}", cpu_id);
                        }

                        let current_guest_time_ms =
                            Vmwdt::get_guest_time_ms(watchdog.ppid, watchdog.pid);
                        let remaining_time_ms = watchdog.next_expiration_interval_ms
                            - (current_guest_time_ms - watchdog.last_guest_time_ms);

                        if remaining_time_ms > 0 {
                            watchdog.next_expiration_interval_ms = remaining_time_ms;
                            if let Err(_e) = watchdog
                                .timer
                                .reset(Duration::from_millis(remaining_time_ms as u64), None)
                            {
                                error!("failed to reset internal timer on vcpu {}", cpu_id);
                            }
                        } else {
                            // The guest ran but it did not send the periodic event
                            if let Err(_e) =
                                reset_evt_wrtube.send::<VmEventType>(&VmEventType::WatchdogReset)
                            {
                                error!("failed to send reset event from vcpu {}", cpu_id)
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
    pub fn get_guest_time_ms(ppid: u32, pid: u32) -> i64 {
        // TODO: @sebastianene check if we can avoid open-read-close on each call
        let stat_path = format!("/proc/{}/task/{}/stat", ppid, pid);
        let contents = fs::read_to_string(stat_path).expect("error reading the stat");

        let coll: Vec<_> = contents.split_whitespace().collect();
        let guest_time = coll[PROCSTAT_GUEST_TIME_INDX].parse::<u64>();
        let gtime_ticks = match guest_time {
            Err(_e) => 0,
            Ok(f) => f,
        };

        // Safe because this just returns an integer
        let ticks_per_sec = unsafe { libc::sysconf(libc::_SC_CLK_TCK) } as u64;
        (gtime_ticks * 1000 / ticks_per_sec) as i64
    }

    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    pub fn get_guest_time_ms(ppid: u32, pid: u32) -> i64 {
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
                let ppid = process::id();
                let pid = gettid();
                let guest_time_ms = Vmwdt::get_guest_time_ms(ppid, pid as u32);
                let mut wdts_locked = self.vm_wdts.lock();
                let mut cpu_watchdog = &mut wdts_locked[cpu_index];
                let next_expiration_interval_ms =
                    reg_val as u64 * 1000 / cpu_watchdog.timer_freq_hz;

                cpu_watchdog.pid = pid as u32;
                cpu_watchdog.ppid = ppid;
                cpu_watchdog.last_guest_time_ms = guest_time_ms;
                cpu_watchdog.next_expiration_interval_ms = next_expiration_interval_ms as i64;

                if cpu_watchdog.is_enabled {
                    if let Err(_e) = cpu_watchdog
                        .timer
                        .reset(Duration::from_millis(next_expiration_interval_ms), None)
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
#[cfg(test)]
mod tests {
    use std::thread::sleep;

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
        let mut device = Vmwdt::new(TEST_VMWDT_CPU_NO, vm_evt_wrtube).unwrap();

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

        sleep(Duration::from_secs(1));

        // Verify that our timer expired and the next_expiration_interval_ms changed
        let vmwdt_locked = device.vm_wdts.lock();
        assert_eq!(
            vmwdt_locked[0].next_expiration_interval_ms != next_expiration_ms,
            true
        );
    }

    #[test]
    fn test_watchdog_expiration() {
        let (vm_evt_wrtube, vm_evt_rdtube) = Tube::directional_pair().unwrap();
        let mut device = Vmwdt::new(TEST_VMWDT_CPU_NO, vm_evt_wrtube).unwrap();

        // Configure the watchdog device, 2Hz internal clock
        device.write(
            vmwdt_bus_address(VMWDT_REG_CLOCK_FREQ_HZ as u64),
            &[10, 0, 0, 0],
        );
        device.write(vmwdt_bus_address(VMWDT_REG_LOAD_CNT as u64), &[1, 0, 0, 0]);
        device.write(vmwdt_bus_address(VMWDT_REG_STATUS as u64), &[1, 0, 0, 0]);
        // In the test scenario the guest does not interpret the /proc/stat::guest_time, thus
        // the function get_guest_time() returns 0
        device.vm_wdts.lock()[0].last_guest_time_ms = -1000;

        sleep(Duration::from_secs(1));

        // Verify that our timer expired and the next_expiration_interval_ms changed
        match vm_evt_rdtube.recv::<VmEventType>() {
            Ok(vm_event) => {
                assert!(vm_event == VmEventType::WatchdogReset);
            }
            Err(_e) => {
                panic!();
            }
        };
    }
}
