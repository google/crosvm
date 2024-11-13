// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::collections::BTreeMap;
use std::fs::File;
use std::path::PathBuf;
use std::sync::atomic::AtomicU32;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use base::sched_attr;
use base::sched_setattr;
use base::set_cpu_affinity;
use base::warn;
use base::Error;
use base::Event;
use base::EventToken;
use base::Timer;
use base::TimerTrait;
use base::Tube;
use base::WaitContext;
use base::WorkerThread;
use sync::Mutex;

use crate::pci::CrosvmDeviceId;
use crate::BusAccessInfo;
use crate::BusDevice;
use crate::DeviceId;
use crate::Suspendable;

const CPUFREQ_GOV_SCALE_FACTOR_DEFAULT: u32 = 100;
const CPUFREQ_GOV_SCALE_FACTOR_SCHEDUTIL: u32 = 80;

const SCHED_FLAG_RESET_ON_FORK: u64 = 0x1;
const SCHED_FLAG_KEEP_POLICY: u64 = 0x08;
const SCHED_FLAG_KEEP_PARAMS: u64 = 0x10;
const SCHED_FLAG_UTIL_CLAMP_MIN: u64 = 0x20;
const SCHED_FLAG_UTIL_CLAMP_MAX: u64 = 0x40;

const VCPUFREQ_CUR_PERF: u32 = 0x0;
const VCPUFREQ_SET_PERF: u32 = 0x4;
const VCPUFREQ_FREQTBL_LEN: u32 = 0x8;
const VCPUFREQ_FREQTBL_SEL: u32 = 0xc;
const VCPUFREQ_FREQTBL_RD: u32 = 0x10;
const VCPUFREQ_PERF_DOMAIN: u32 = 0x14;

const SCHED_FLAG_KEEP_ALL: u64 = SCHED_FLAG_KEEP_POLICY | SCHED_FLAG_KEEP_PARAMS;
const SCHED_CAPACITY_SCALE: u32 = 1024;

// Timer values in microseconds
const MIN_TIMER_US: u32 = 75;
const TIMER_OVERHEAD_US: u32 = 15;

/// Upstream linux compatible version of the virtual cpufreq interface
pub struct VirtCpufreqV2 {
    vcpu_freq_table: Vec<u32>,
    pcpu_fmax: u32,
    pcpu_capacity: u32,
    pcpu: u32,
    util_factor: u32,
    freqtbl_sel: u32,
    vcpu_domain: u32,
    domain_uclamp_min: Option<File>,
    domain_uclamp_max: Option<File>,
    vcpu_fmax: u32,
    vcpu_capacity: u32,
    vcpu_relative_capacity: u32,
    worker: Option<WorkerThread<()>>,
    timer: Arc<Mutex<Timer>>,
    vm_ctrl: Arc<Mutex<Tube>>,
    pcpu_min_cap: u32,
    /// The largest(or the last) pCPU index to be used by all the vCPUs. This index is used to
    /// figure out the proper placement of the throttle workers which are placed on pCPUs right
    /// after the last pCPU being used the vCPUs. Throttle workers require their own exclusive
    /// pCPU allocation and this ensure that the workers are placed contiguously and makes it
    /// easier for user to manage pCPU allocations when running multiple instances on a large
    /// server.
    largest_pcpu_idx: usize,
    //TODO: Put the shared_domain_members in a struct
    shared_domain_vcpus: Vec<usize>,
    shared_domain_perf: Arc<AtomicU32>,
}

fn get_cpu_info(cpu_id: u32, property: &str) -> Result<u32, Error> {
    let path = format!("/sys/devices/system/cpu/cpu{cpu_id}/{property}");
    std::fs::read_to_string(path)?
        .trim()
        .parse()
        .map_err(|_| Error::new(libc::EINVAL))
}

fn get_cpu_info_str(cpu_id: u32, property: &str) -> Result<String, Error> {
    let path = format!("/sys/devices/system/cpu/cpu{cpu_id}/{property}");
    std::fs::read_to_string(path).map_err(|_| Error::new(libc::EINVAL))
}

fn get_cpu_capacity(cpu_id: u32) -> Result<u32, Error> {
    get_cpu_info(cpu_id, "cpu_capacity")
}

fn get_cpu_maxfreq_khz(cpu_id: u32) -> Result<u32, Error> {
    get_cpu_info(cpu_id, "cpufreq/cpuinfo_max_freq")
}

fn get_cpu_minfreq_khz(cpu_id: u32) -> Result<u32, Error> {
    get_cpu_info(cpu_id, "cpufreq/cpuinfo_min_freq")
}

fn get_cpu_curfreq_khz(cpu_id: u32) -> Result<u32, Error> {
    get_cpu_info(cpu_id, "cpufreq/scaling_cur_freq")
}

fn get_cpu_util_factor(cpu_id: u32) -> Result<u32, Error> {
    let gov = get_cpu_info_str(cpu_id, "cpufreq/scaling_governor")?;
    match gov.trim() {
        "schedutil" => Ok(CPUFREQ_GOV_SCALE_FACTOR_SCHEDUTIL),
        _ => Ok(CPUFREQ_GOV_SCALE_FACTOR_DEFAULT),
    }
}

impl VirtCpufreqV2 {
    pub fn new(
        pcpu: u32,
        cpu_frequencies: BTreeMap<usize, Vec<u32>>,
        vcpu_domain_path: Option<PathBuf>,
        vcpu_domain: u32,
        vcpu_capacity: u32,
        largest_pcpu_idx: usize,
        vm_ctrl: Arc<Mutex<Tube>>,
        shared_domain_vcpus: Vec<usize>,
        shared_domain_perf: Arc<AtomicU32>,
    ) -> Self {
        let pcpu_capacity = get_cpu_capacity(pcpu).expect("Error reading capacity");
        let pcpu_fmax = get_cpu_maxfreq_khz(pcpu).expect("Error reading max freq");
        let util_factor = get_cpu_util_factor(pcpu).expect("Error getting util factor");
        let vcpu_freq_table = cpu_frequencies.get(&(pcpu as usize)).unwrap().clone();
        let freqtbl_sel = 0;
        let mut domain_uclamp_min = None;
        let mut domain_uclamp_max = None;
        // The vcpu_capacity passed in is normalized for frequency, reverse the normalization to
        // get the performance per clock ratio between the vCPU and the pCPU its running on. This
        // "relative capacity" is an approximation of the delta in IPC (Instructions per Cycle)
        // between the pCPU vs vCPU running a usecase containing a mix of instruction types.
        let vcpu_fmax = vcpu_freq_table.clone().into_iter().max().unwrap();
        let vcpu_relative_capacity =
            u32::try_from(u64::from(vcpu_capacity) * u64::from(pcpu_fmax) / u64::from(vcpu_fmax))
                .unwrap();
        let pcpu_min_cap =
            get_cpu_minfreq_khz(pcpu).expect("Error reading min freq") * pcpu_capacity / pcpu_fmax;

        if let Some(cgroup_path) = &vcpu_domain_path {
            domain_uclamp_min = Some(
                File::create(cgroup_path.join("cpu.uclamp.min")).unwrap_or_else(|err| {
                    panic!(
                        "Err: {}, Unable to open: {}",
                        err,
                        cgroup_path.join("cpu.uclamp.min").display()
                    )
                }),
            );
            domain_uclamp_max = Some(
                File::create(cgroup_path.join("cpu.uclamp.max")).unwrap_or_else(|err| {
                    panic!(
                        "Err: {}, Unable to open: {}",
                        err,
                        cgroup_path.join("cpu.uclamp.max").display()
                    )
                }),
            );
        }

        VirtCpufreqV2 {
            vcpu_freq_table,
            pcpu_fmax,
            pcpu_capacity,
            pcpu,
            util_factor,
            freqtbl_sel,
            vcpu_domain,
            domain_uclamp_min,
            domain_uclamp_max,
            vcpu_fmax,
            vcpu_capacity,
            vcpu_relative_capacity,
            worker: None,
            timer: Arc::new(Mutex::new(Timer::new().expect("failed to create Timer"))),
            vm_ctrl,
            pcpu_min_cap,
            largest_pcpu_idx,
            shared_domain_vcpus,
            shared_domain_perf,
        }
    }
}

impl BusDevice for VirtCpufreqV2 {
    fn device_id(&self) -> DeviceId {
        CrosvmDeviceId::VirtCpufreq.into()
    }

    fn debug_label(&self) -> String {
        "VirtCpufreq Device".to_owned()
    }

    fn read(&mut self, info: BusAccessInfo, data: &mut [u8]) {
        if data.len() != std::mem::size_of::<u32>() {
            warn!(
                "{}: unsupported read length {}, only support 4bytes read",
                self.debug_label(),
                data.len()
            );
            return;
        }

        let val = match info.offset as u32 {
            VCPUFREQ_CUR_PERF => {
                let shared_util = self.shared_domain_perf.load(Ordering::SeqCst);
                if shared_util != 0 && shared_util < self.pcpu_min_cap {
                    shared_util * self.vcpu_fmax / self.vcpu_capacity
                } else {
                    match get_cpu_curfreq_khz(self.pcpu) {
                        Ok(freq) => u32::try_from(
                            u64::from(freq) * u64::from(self.pcpu_capacity)
                                / u64::from(self.vcpu_relative_capacity),
                        )
                        .unwrap(),
                        Err(_) => 0,
                    }
                }
            }
            VCPUFREQ_FREQTBL_LEN => self.vcpu_freq_table.len() as u32,
            VCPUFREQ_PERF_DOMAIN => self.vcpu_domain,
            VCPUFREQ_FREQTBL_RD => *self
                .vcpu_freq_table
                .get(self.freqtbl_sel as usize)
                .unwrap_or(&0),
            _ => {
                warn!("{}: unsupported read address {}", self.debug_label(), info);
                return;
            }
        };

        let val_arr = val.to_ne_bytes();
        data.copy_from_slice(&val_arr);
    }

    fn write(&mut self, info: BusAccessInfo, data: &[u8]) {
        let val: u32 = match data.try_into().map(u32::from_ne_bytes) {
            Ok(v) => v,
            Err(e) => {
                warn!(
                    "{}: unsupported write length {:#}, only support 4bytes write",
                    self.debug_label(),
                    e
                );
                return;
            }
        };

        match info.offset as u32 {
            VCPUFREQ_SET_PERF => {
                // Util margin depends on the cpufreq governor on the host
                let util_raw = match u32::try_from(
                    u64::from(self.vcpu_capacity) * u64::from(val) / u64::from(self.vcpu_fmax),
                ) {
                    Ok(util) => util,
                    Err(e) => {
                        warn!("Potential overflow {:#}", e);
                        SCHED_CAPACITY_SCALE
                    }
                };

                let util = util_raw * self.util_factor / CPUFREQ_GOV_SCALE_FACTOR_DEFAULT;

                if let (Some(domain_uclamp_min), Some(domain_uclamp_max)) =
                    (&mut self.domain_uclamp_min, &mut self.domain_uclamp_max)
                {
                    use std::io::Write;
                    let val = util as f32 * 100.0 / SCHED_CAPACITY_SCALE as f32;
                    let val_formatted = format!("{:4}", val).into_bytes();

                    if self.vcpu_fmax != self.pcpu_fmax {
                        if let Err(e) = domain_uclamp_max.write(&val_formatted) {
                            warn!("Error setting uclamp_max: {:#}", e);
                        }
                    }
                    if let Err(e) = domain_uclamp_min.write(&val_formatted) {
                        warn!("Error setting uclamp_min: {:#}", e);
                    }
                } else {
                    let mut sched_attr = sched_attr::default();
                    sched_attr.sched_flags = SCHED_FLAG_KEEP_ALL
                        | SCHED_FLAG_UTIL_CLAMP_MIN
                        | SCHED_FLAG_UTIL_CLAMP_MAX
                        | SCHED_FLAG_RESET_ON_FORK;
                    sched_attr.sched_util_min = util;

                    if self.vcpu_fmax != self.pcpu_fmax {
                        sched_attr.sched_util_max = util;
                    } else {
                        sched_attr.sched_util_max = SCHED_CAPACITY_SCALE;
                    }

                    if let Err(e) = sched_setattr(0, &mut sched_attr, 0) {
                        panic!("{}: Error setting util value: {:#}", self.debug_label(), e);
                    }
                }

                self.shared_domain_perf.store(util_raw, Ordering::SeqCst);
                let timer = self.timer.clone();
                if self.worker.is_none() {
                    let vcpu_id = info.id;
                    let vm_ctrl = self.vm_ctrl.clone();
                    let worker_cpu_affinity = self.largest_pcpu_idx + self.vcpu_domain as usize + 1;
                    let shared_domain_vcpus = self.shared_domain_vcpus.clone();

                    self.worker = Some(WorkerThread::start(
                        format!("vcpu_throttle{vcpu_id}"),
                        move |kill_evt| {
                            vcpufreq_worker_thread(
                                shared_domain_vcpus,
                                kill_evt,
                                timer,
                                vm_ctrl,
                                worker_cpu_affinity,
                            )
                            .expect("error running vpucfreq_worker")
                        },
                    ));
                } else if util_raw < self.pcpu_min_cap {
                    // The period is porportional to the performance requested by the vCPU, we
                    // reduce the timeout period to increase the amount of throttling applied to
                    // the vCPU as the performance decreases. Ex. If vCPU requests half of the
                    // performance relatively to its pCPU@FMin, the vCPU will spend 50% of its
                    // cycles being throttled to increase time for the same workload that otherwise
                    // would've taken 1/2 of the time if ran at pCPU@FMin. We could've
                    // alternatively adjusted the workload and used some fixed period (such as
                    // 250us), but there's a floor for the minimum delay we add (cost of handling
                    // the userspace exit) and limits the range of performance we can emulate.
                    let timeout_period = (MIN_TIMER_US + TIMER_OVERHEAD_US) as f32
                        / (1.0 - (util_raw as f32 / self.pcpu_min_cap as f32));
                    let _ = timer
                        .lock()
                        .reset_repeating(Duration::from_micros(timeout_period as u64));
                } else {
                    let _ = timer.lock().clear();
                }
            }
            VCPUFREQ_FREQTBL_SEL => self.freqtbl_sel = val,
            _ => {
                warn!("{}: unsupported read address {}", self.debug_label(), info);
            }
        }
    }
}

pub fn vcpufreq_worker_thread(
    shared_domain_vcpus: Vec<usize>,
    kill_evt: Event,
    timer: Arc<Mutex<Timer>>,
    vm_ctrl: Arc<Mutex<Tube>>,
    cpu_affinity: usize,
) -> anyhow::Result<()> {
    #[derive(EventToken)]
    enum Token {
        // The timer expired.
        TimerExpire,
        // The parent thread requested an exit.
        Kill,
    }

    let wait_ctx = WaitContext::build_with(&[
        (&*timer.lock(), Token::TimerExpire),
        (&kill_evt, Token::Kill),
    ])
    .context("Failed to create wait_ctx")?;

    // The vcpufreq thread has strict scheduling requirements, let's affine it away from the vCPU
    // threads and clamp its util to high value.
    let cpu_set: Vec<usize> = vec![cpu_affinity];
    set_cpu_affinity(cpu_set)?;

    let mut sched_attr = sched_attr::default();
    sched_attr.sched_flags = SCHED_FLAG_KEEP_ALL
        | SCHED_FLAG_UTIL_CLAMP_MIN
        | SCHED_FLAG_UTIL_CLAMP_MAX
        | SCHED_FLAG_RESET_ON_FORK;
    sched_attr.sched_util_min = SCHED_CAPACITY_SCALE;
    sched_attr.sched_util_max = SCHED_CAPACITY_SCALE;
    if let Err(e) = sched_setattr(0, &mut sched_attr, 0) {
        warn!("Error setting util value: {}", e);
    }

    loop {
        let events = wait_ctx.wait().context("Failed to wait for events")?;
        for event in events.iter().filter(|e| e.is_readable) {
            match event.token {
                Token::TimerExpire => {
                    timer
                        .lock()
                        .mark_waited()
                        .context("failed to reset timer")?;
                    let vm_ctrl_unlocked = vm_ctrl.lock();
                    for vcpu_id in &shared_domain_vcpus {
                        let msg = vm_control::VmRequest::Throttle(*vcpu_id, MIN_TIMER_US);
                        vm_ctrl_unlocked
                            .send(&msg)
                            .context("failed to stall vCPUs")?;
                    }
                }
                Token::Kill => {
                    return Ok(());
                }
            }
        }
    }
}

impl Suspendable for VirtCpufreqV2 {}
