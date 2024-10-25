// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::collections::BTreeMap;

use base::sched_attr;
use base::sched_setattr;
use base::warn;
use base::Error;

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

const VCPUFREQ_CUR_PERF: u32 = 0x0;
const VCPUFREQ_SET_PERF: u32 = 0x4;
const VCPUFREQ_FREQTBL_LEN: u32 = 0x8;
const VCPUFREQ_FREQTBL_SEL: u32 = 0xc;
const VCPUFREQ_FREQTBL_RD: u32 = 0x10;
const VCPUFREQ_PERF_DOMAIN: u32 = 0x14;

const SCHED_FLAG_KEEP_ALL: u64 = SCHED_FLAG_KEEP_POLICY | SCHED_FLAG_KEEP_PARAMS;

/// Upstream linux compatible version of the virtual cpufreq interface
pub struct VirtCpufreqV2 {
    cpu_freq_table: Vec<u32>,
    cpu_fmax: u32,
    cpu_capacity: u32,
    pcpu: u32,
    util_factor: u32,
    freqtbl_sel: u32,
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
    pub fn new(pcpu: u32, cpu_frequencies: BTreeMap<usize, Vec<u32>>) -> Self {
        let cpu_capacity = get_cpu_capacity(pcpu).expect("Error reading capacity");
        let cpu_fmax = get_cpu_maxfreq_khz(pcpu).expect("Error reading max freq");
        let util_factor = get_cpu_util_factor(pcpu).expect("Error getting util factor");
        let cpu_freq_table = cpu_frequencies.get(&(pcpu as usize)).unwrap().clone();
        let freqtbl_sel = 0;

        VirtCpufreqV2 {
            cpu_freq_table,
            cpu_fmax,
            cpu_capacity,
            pcpu,
            util_factor,
            freqtbl_sel,
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
            VCPUFREQ_CUR_PERF => get_cpu_curfreq_khz(self.pcpu).unwrap_or(0),
            VCPUFREQ_FREQTBL_LEN => self.cpu_freq_table.len() as u32,
            VCPUFREQ_PERF_DOMAIN => self.pcpu,
            VCPUFREQ_FREQTBL_RD => *self
                .cpu_freq_table
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
                let cpu_cap_scaled =
                    self.cpu_capacity * self.util_factor / CPUFREQ_GOV_SCALE_FACTOR_DEFAULT;
                let util = cpu_cap_scaled.checked_mul(val).unwrap_or_else(|| {
                    warn!("{}: Requested freq causes overflow", self.debug_label());
                    0
                }) / self.cpu_fmax;

                let mut sched_attr = sched_attr::default();
                sched_attr.sched_flags =
                    SCHED_FLAG_KEEP_ALL | SCHED_FLAG_UTIL_CLAMP_MIN | SCHED_FLAG_RESET_ON_FORK;
                sched_attr.sched_util_min = util;

                if let Err(e) = sched_setattr(0, &mut sched_attr, 0) {
                    panic!("{}: Error setting util value: {:#}", self.debug_label(), e);
                }
            }
            VCPUFREQ_FREQTBL_SEL => self.freqtbl_sel = val,
            _ => {
                warn!("{}: unsupported read address {}", self.debug_label(), info);
            }
        }
    }
}

impl Suspendable for VirtCpufreqV2 {}
