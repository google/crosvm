// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

/// Constants from Hyper-V Top Level Functional Specification.
/// This comes from the document published here:
/// <https://github.com/MicrosoftDocs/Virtualization-Documentation/raw/live/tlfs/Hypervisor%20Top%20Level%20Functional%20Specification%20v6.0b.pdf>

/// CPUID Leaf Range Register.
pub const HYPERV_CPUID_VENDOR_AND_MAX_FUNCTIONS: u32 = 0x40000000;
/// Start of CPUID information for Hyper-V.
pub const HYPERV_CPUID_MIN: u32 = 0x40000005;
/// Hypervisor Feature Identification Register.
pub const HYPERV_CPUID_FEATURES: u32 = 0x40000003;

/// Feature for Frequency MSR availability.
pub const HV_FEATURE_FREQUENCY_MSRS_AVAILABLE: u32 = 1 << 8;

/// Group A features.

/// Privilege bit for partition reference TSC register.
pub const HV_MSR_REFERENCE_TSC_AVAILABLE: u32 = 1 << 9;
/// Privilege bit showing Partition Local APIC and TSC frequency registers availability.
pub const HV_ACCESS_FREQUENCY_MSRS: u32 = 1 << 11;
/// Privilege bit for AccessTscInvariantControls.
pub const HV_ACCESS_TSC_INVARIANT: u32 = 1 << 15;

/// MSR definitions.
pub const HV_X64_MSR_TSC_INVARIANT_CONTROL: u32 = 0x40000118;
pub const HV_X64_MSR_APIC_FREQUENCY: u32 = 0x40000023;
pub const HV_X64_MSR_TSC_FREQUENCY: u32 = 0x40000022;
