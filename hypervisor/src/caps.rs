// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

/// An enumeration of different hypervisor capabilities.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HypervisorCap {
    ImmediateExit,
    UserMemory,
    #[cfg(target_arch = "x86_64")]
    Xcrs,
    #[cfg(target_arch = "x86_64")]
    /// CPUID leaf 0x15 is available on some Intel chips and contains the TSC
    /// frequency, which can be used to calibrate the guest's TSC clocksource;
    /// however, it is not typically accurate enough (being off by 1-2% is a
    /// big problem for a clocksource), and inside the guest, calibration by
    /// other means is not always reliable.
    ///
    /// Hypervisors which do not provide the TSC frequency (e.g. via the kvm
    /// pvclock) or have another suitable calibration source can declare this
    /// capability, which causes crosvm to substitute a calibrated value in leaf
    /// 0x15 that will be accurate enough for use in a clocksource.
    CalibratedTscLeafRequired,
    // By default, when swiotlb is enabled, crosvm will only specify its size in the device tree
    // and allow the guest to decide where to allocate the buffer in guest phsyical memory.
    //
    // If this capability is declared, then instead crosvm will carve out space at the end of
    // physical memory and register it as a distinct memory region. Then, both the address and
    // size will be specified in the device tree. This region will still be reported as part
    // of the main memory region in the device tree.
    StaticSwiotlbAllocationRequired,
    /// Some hypervisors (presently: Gunyah) will configure initial boot-time registers
    /// for vCPUs without need for CrosVM to specify.
    ///
    /// If this capability is declared, then crosvm will not try to initialize vcpu
    /// registers when creating the VM.
    HypervisorInitializedBootContext,
}

/// A capability the `Vm` can possibly expose.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VmCap {
    #[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
    ArmPmuV3,
    /// Track dirty pages
    DirtyLog,
    /// Paravirtualized clock device
    PvClock,
    /// VM can be run in protected mode, where the host does not have access to its memory.
    Protected,
    /// VM completes initialization of CPUID at creation time, not required after.
    EarlyInitCpuid,
    /// VM can detect the bus lock
    #[cfg(target_arch = "x86_64")]
    BusLockDetect,
    /// Supports read-only memory regions.
    ReadOnlyMemoryRegion,
    /// VM can set guest memory cache noncoherent DMA flag
    MemNoncoherentDma,
    /// If supported, this VM supports enabling ARM SVE (Scalable Vector Extension)
    /// by requesting `VcpuFeature::Sve` when calling `VcpuAarch64::init()`.
    #[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
    Sve,
}
