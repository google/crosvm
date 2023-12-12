// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// TODO(b/213149158): Remove after uses are added.
#![allow(dead_code)]

use std::arch::x86_64::CpuidResult;

/// Function to retrieve the given CPUID leaf and sub-leaf.
pub type CpuidCountFn = unsafe fn(u32, u32) -> CpuidResult;

/// Gets the TSC frequency for cpuid leaf 0x15 from the existing leaves 0x15 and 0x16.
///
/// # Arguments
/// * `cpuid_count`: function that returns the CPUID information for the given leaf/subleaf
///   combination. `std::arch::x86_64::__cpuid_count` may be used to provide the CPUID information
///   from the host.
pub fn tsc_frequency_cpuid(cpuid_count: CpuidCountFn) -> Option<hypervisor::CpuIdEntry> {
    // SAFETY:
    // Safe because we pass 0 and 0 for this call and the host supports the `cpuid` instruction.
    let result = unsafe { cpuid_count(0, 0) };
    if result.eax < 0x15 {
        return None;
    }

    let mut tsc_freq = hypervisor::CpuIdEntry {
        // 0x15 is the TSC frequency leaf.
        function: 0x15,
        index: 0,
        flags: 0,
        cpuid: CpuidResult {
            eax: 0,
            ebx: 0,
            ecx: 0,
            edx: 0,
        },
    };
    // SAFETY:
    // Safe because we pass 0 and 0 for this call and the host supports the `cpuid` instruction.
    tsc_freq.cpuid = unsafe { cpuid_count(tsc_freq.function, tsc_freq.index) };

    if tsc_freq.cpuid.ecx != 0 {
        Some(tsc_freq)
    } else {
        // The core crystal frequency is missing. Old kernels (<5.3) don't try to derive it from the
        // CPU base clock speed. Here, we essentially implement
        // https://lore.kernel.org/patchwork/patch/1064690/ so that old kernels can calibrate TSC.
        // SAFETY:
        // Safe because the host supports `cpuid` instruction.
        let cpu_clock = unsafe {
            // 0x16 is the base clock frequency leaf.
            cpuid_count(0x16, 0)
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
            tsc_freq.cpuid.ecx = (cpu_clock.eax as f64 * tsc_freq.cpuid.eax as f64 * 1_000_000_f64
                / tsc_freq.cpuid.ebx as f64)
                .round() as u32;
            Some(tsc_freq)
        } else {
            None
        }
    }
}

/// Given the tsc frequency in Hz and the bus frequency in Hz, return a fake version of
/// cpuid leaf 0x15.
pub fn fake_tsc_frequency_cpuid(tsc_hz: u64, bus_hz: u32) -> CpuidResult {
    // We use 1000 for the crystal clock ratio denominator so we can preserve precision in case
    // tsc_hz is not neatly divisible by bus_hz
    let crystal_clock_ratio_denominator: u32 = 1000;
    let crystal_clock_ratio_numerator: u32 =
        (tsc_hz * crystal_clock_ratio_denominator as u64 / bus_hz as u64) as u32;

    CpuidResult {
        eax: crystal_clock_ratio_denominator,
        ebx: crystal_clock_ratio_numerator,
        ecx: bus_hz,
        edx: 0,
    }
}

/// Returns the Bus frequency in Hz, based on reading Intel-specific cpuids, or None
/// if the frequency can't be determined from cpuids.
pub fn bus_freq_hz(cpuid_count: CpuidCountFn) -> Option<u32> {
    tsc_frequency_cpuid(cpuid_count).map(|cpuid| cpuid.cpuid.ecx)
}

/// Returns the TSC frequency in Hz, based on reading Intel-specific cpuids, or None
/// if the frequency can't be determined from cpuids.
pub fn tsc_freq_hz(cpuid_count: CpuidCountFn) -> Option<u32> {
    tsc_frequency_cpuid(cpuid_count).map(|cpuid| {
        (cpuid.cpuid.ecx as u64 * cpuid.cpuid.ebx as u64 / cpuid.cpuid.eax as u64) as u32
    })
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
        const CRYSTAL_CLOCK_RATIO: u32 = 88;
        const TSC_FREQUENCY_HZ: u32 = 2100000000u32;

        let fake_cpuid = |function: u32, index: u32| {
            match (function, index) {
                (0, 0) => {
                    CpuidResult {
                        eax: 0x16, // highest available leaf is 0x16
                        ebx: 0,
                        ecx: 0,
                        edx: 0,
                    }
                }
                (0x15, 0) => {
                    CpuidResult {
                        eax: 2, // eax usually contains 2, and ebx/eax is the crystal clock ratio
                        ebx: CRYSTAL_CLOCK_RATIO * 2,
                        ecx: 0,
                        edx: 0,
                    }
                }
                (0x16, 0) => {
                    CpuidResult {
                        eax: TSC_FREQUENCY_HZ / 1_000_000_u32, // MHz frequency
                        ebx: 0,
                        ecx: 0,
                        edx: 0,
                    }
                }
                _ => CpuidResult {
                    eax: 0,
                    ebx: 0,
                    ecx: 0,
                    edx: 0,
                },
            }
        };

        // We compare the frequencies divided by the CRYSTAL_CLOCK_RATIO because that's the
        // resolution that the tsc frequency is stored at in CPUID.15H.ECX.
        assert_eq!(
            tsc_freq_hz(fake_cpuid).unwrap() / CRYSTAL_CLOCK_RATIO,
            TSC_FREQUENCY_HZ / CRYSTAL_CLOCK_RATIO
        );
    }
}
