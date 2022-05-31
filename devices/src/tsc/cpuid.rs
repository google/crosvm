// Copyright 2022 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// TODO(b/213149158): Remove after uses are added.
#![allow(dead_code)]

#[cfg(test)]
use lazy_static::lazy_static;
#[cfg(test)]
use std::arch::x86_64::CpuidResult;
#[cfg(not(test))]
use std::arch::x86_64::__cpuid_count;
#[cfg(test)]
use std::sync::Arc;
#[cfg(test)]
use sync::Mutex;

/// Gets the TSC frequency for cpuid leaf 0x15 from the existing leaves 0x15 and 0x16
pub fn tsc_frequency_cpuid() -> Option<hypervisor::CpuIdEntry> {
    // Safe because we pass 0 and 0 for this call and the host supports the `cpuid` instruction.
    let result = unsafe { __cpuid_count(0, 0) };
    if result.eax < 0x15 {
        return None;
    }

    let mut tsc_freq = hypervisor::CpuIdEntry {
        // 0x15 is the TSC frequency leaf.
        function: 0x15,
        index: 0,
        flags: 0,
        eax: 0,
        ebx: 0,
        ecx: 0,
        edx: 0,
    };
    // Safe because we pass 0 and 0 for this call and the host supports the `cpuid` instruction.
    unsafe {
        let result = __cpuid_count(tsc_freq.function, tsc_freq.index);
        tsc_freq.eax = result.eax;
        tsc_freq.ebx = result.ebx;
        tsc_freq.ecx = result.ecx;
        tsc_freq.edx = result.edx;
    }

    if tsc_freq.ecx != 0 {
        Some(tsc_freq)
    } else {
        // The core crystal frequency is missing. Old kernels (<5.3) don't try to derive it from the
        // CPU base clock speed. Here, we essentially implement
        // https://lore.kernel.org/patchwork/patch/1064690/ so that old kernels can calibrate TSC.
        // Safe because the host supports `cpuid` instruction.
        let cpu_clock = unsafe {
            // 0x16 is the base clock frequency leaf.
            __cpuid_count(0x16, 0)
        };
        if cpu_clock.eax > 0 {
            // Here, we assume the CPU base clock is the core crystal clock, as is done in the patch
            // that exists in 5.3+ kernels. We further assume that the core crystal clock is exactly
            // the TSC frequency. As such, we expose the base clock scaled by the _inverse_ of the
            // "tsc freq" / "core crystal clock freq" ratio. That way when the kernel extracts
            // the frequency & multiplies by the ratio, it obtains the TSC frequency.
            //
            // base_mhz = cpu_clock.eax
            // tsc_to_base_ratio = tsc_freq.eax / tsc_freq.ebx
            // crystal_hz = base_mhz * tsc_base_to_clock_ratio * 10^6
            tsc_freq.ecx = (cpu_clock.eax as f64 * tsc_freq.eax as f64 * 1_000_000_f64
                / tsc_freq.ebx as f64)
                .round() as u32;
            Some(tsc_freq)
        } else {
            None
        }
    }
}

/// Given the tsc frequency in Hz and the bus frequency in Hz, return a fake version of
/// cpuid leaf 0x15.
pub fn fake_tsc_frequency_cpuid(tsc_hz: u64, bus_hz: u32) -> hypervisor::CpuIdEntry {
    // We use 1000 for the crystal clock ratio denominator so we can preserve precision in case
    // tsc_hz is not neatly divisible by bus_hz
    let crystal_clock_ratio_denominator: u32 = 1000;
    let crystal_clock_ratio_numerator: u32 =
        (tsc_hz * crystal_clock_ratio_denominator as u64 / bus_hz as u64) as u32;

    hypervisor::CpuIdEntry {
        function: 0x15,
        index: 0,
        flags: 0,
        eax: crystal_clock_ratio_denominator,
        ebx: crystal_clock_ratio_numerator,
        ecx: bus_hz,
        edx: 0,
    }
}

/// Returns the Bus frequency in Hz, based on reading Intel-specific cpuids, or None
/// if the frequency can't be determined from cpuids.
pub fn bus_freq_hz() -> Option<u32> {
    tsc_frequency_cpuid().map(|cpuid| cpuid.ecx)
}

/// Returns the TSC frequency in Hz, based on reading Intel-specific cpuids, or None
/// if the frequency can't be determined from cpuids.
pub fn tsc_freq_hz() -> Option<u32> {
    tsc_frequency_cpuid()
        .map(|cpuid| (cpuid.ecx as u64 * cpuid.ebx as u64 / cpuid.eax as u64) as u32)
}

// This function is safe, but we mark it as unsafe so the signature matches the external
// __cpuid_count function so we don't get warnings.
#[cfg(test)]
unsafe fn __cpuid_count(function: u32, index: u32) -> CpuidResult {
    let cpuids = CPUIDS.lock();
    let entry = cpuids
        .iter()
        .find(|c| c.function == function && c.index == index)
        .map_or(hypervisor::CpuIdEntry::default(), |c| *c);

    CpuidResult {
        eax: entry.eax,
        ebx: entry.ebx,
        ecx: entry.ecx,
        edx: entry.edx,
    }
}

// Note: to use this mock without cross test pollution, tests must be run serially. Since there
// is exactly one test using it at the moment, serial running is not required.
#[cfg(test)]
lazy_static! {
    static ref CPUIDS: Arc<Mutex<Vec<hypervisor::CpuIdEntry>>> = Arc::new(Mutex::new(Vec::new()));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    // It seems that most Intel CPUs don't have any TSC frequency information in CPUID.15H.ECX. The
    // linux kernel only treats the TSC frequency as a "known" frequency if it comes from
    // CPUID.15H.ECX, and we want our TSC frequency to be "known" to prevent clock watchdogs from
    // invalidating the TSC clocksource. So we derive CPUID.15H.ECX from the values in CPUID.16H.
    // This test verifies that that derivation is working correctly.
    fn test_leaf15_derivation() {
        let crystal_clock_ratio = 88;
        let tsc_frequency_hz = 2100000000u32;

        {
            let mut cpuids = CPUIDS.lock();

            cpuids.push(hypervisor::CpuIdEntry {
                function: 0,
                index: 0,
                eax: 0x16, // highest available leaf is 0x16
                ..Default::default()
            });

            cpuids.push(hypervisor::CpuIdEntry {
                function: 0x15,
                index: 0,
                eax: 2, // eax usually contains 2, and ebx/eax is the crystal clock ratio
                ebx: crystal_clock_ratio * 2,
                ..Default::default()
            });

            cpuids.push(hypervisor::CpuIdEntry {
                function: 0x16,
                index: 0,
                eax: tsc_frequency_hz / 1_000_000_u32, // MHz frequency
                ..Default::default()
            });
        }

        // We compare the frequencies divided by the crystal_clock_ratio because that's the
        // resolution that the tsc frequency is stored at in CPUID.15H.ECX.
        assert_eq!(
            tsc_freq_hz().unwrap() / crystal_clock_ratio,
            tsc_frequency_hz / crystal_clock_ratio
        );

        CPUIDS.lock().clear();
    }
}
