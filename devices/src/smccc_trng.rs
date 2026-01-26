// Copyright 2025 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::ops::Range;

use anyhow::bail;
use base::fold_into_i32;
use base::warn;
use base::NegativeI32;
use base::U31;
use hypervisor::HypercallAbi;
use static_assertions::const_assert_ne;
use uuid::uuid;
use uuid::Uuid;
use vm_control::DeviceId;
use vm_control::PlatformDeviceId;

use crate::BusAccessInfo;
use crate::BusDevice;
use crate::BusDeviceSync;
use crate::Suspendable;

/// Error codes, as defined by the SMCCC TRNG (DEN0098).
///
/// Note that values are strictly positive but API return values are strictly negative.
#[repr(i32)]
#[derive(Clone, Copy, Debug)]
enum SmcccTrngError {
    NotSupported = -1,
    InvalidParameters = -2,
    #[allow(unused)]
    NoEntropy = -3,
}

impl SmcccTrngError {
    const fn as_i32(&self) -> i32 {
        *self as _
    }
}

impl From<SmcccTrngError> for i32 {
    fn from(e: SmcccTrngError) -> Self {
        e.as_i32()
    }
}

impl From<SmcccTrngError> for NegativeI32 {
    fn from(e: SmcccTrngError) -> Self {
        Self::new(e.as_i32()).unwrap()
    }
}

/// A backend implementation of the SMCCC TRNG (DEN0098).
///
/// Might not be fully spec-compliant regarding the conditioned entropy.
pub struct SmcccTrng {}

impl Default for SmcccTrng {
    fn default() -> Self {
        Self::new()
    }
}

impl SmcccTrng {
    /// Standard function ID ranges for TRNG 32-bit calls, defined in SMCCC (DEN0028).
    pub const HVC32_FID_RANGE: Range<u32> = 0x8400_0050..0x8400_0060;
    /// Standard function ID ranges for TRNG 64-bit calls, defined in SMCCC (DEN0028).
    pub const HVC64_FID_RANGE: Range<u32> = 0xC400_0050..0xC400_0060;

    const FID_TRNG_VERSION: u32 = 0x8400_0050;
    const FID_TRNG_FEATURES: u32 = 0x8400_0051;
    const FID_TRNG_GET_UUID: u32 = 0x8400_0052;
    const FID_TRNG_RND32: u32 = 0x8400_0053;
    const FID_TRNG_RND64: u32 = 0xC400_0053;

    const VERSION: (u16, u16) = (1, 0);
    /// CrosVM SMCCC TRNG back-end UUID.
    ///
    /// Equivalent to `Uuid::new_v8(*b"SMCCCTRNG-CrosVM")`.
    const UUID: Uuid = uuid!("534d4343-4354-824e-872d-43726f73564d");

    /// Creates a new instance of `SmcccTrng`.
    pub fn new() -> Self {
        Self {}
    }

    fn version(&self) -> Result<U31, SmcccTrngError> {
        Ok(U31::new(((Self::VERSION.0 as u32) << 16) | (Self::VERSION.1 as u32)).unwrap())
    }

    fn features(&self, func_id: u32) -> Result<U31, SmcccTrngError> {
        const AVAILABLE: U31 = U31::new(0).unwrap();
        match func_id {
            Self::FID_TRNG_VERSION => Ok(AVAILABLE),
            Self::FID_TRNG_FEATURES => Ok(AVAILABLE),
            Self::FID_TRNG_GET_UUID => Ok(AVAILABLE),
            Self::FID_TRNG_RND32 => Ok(AVAILABLE),
            Self::FID_TRNG_RND64 => Ok(AVAILABLE),
            _ => Err(SmcccTrngError::NotSupported),
        }
    }

    fn get_uuid(&self) -> Result<[u32; 4], SmcccTrngError> {
        const UUID: u128 = SmcccTrng::UUID.to_u128_le();
        const R3: u32 = (UUID >> (3 * u32::BITS)) as _;
        const R2: u32 = (UUID >> (2 * u32::BITS)) as _;
        const R1: u32 = (UUID >> u32::BITS) as _;
        const R0: u32 = UUID as _;
        // Otherwise return would be indistinguishable from SMCCC's NOT_SUPPORTED
        const_assert_ne!(R0, u32::MAX);

        Ok([R0, R1, R2, R3])
    }

    fn rnd32(&self, n_bits: u32) -> Result<[u32; 3], SmcccTrngError> {
        match n_bits.div_ceil(u32::BITS) {
            1 => Ok([rand::random(), 0, 0]),
            2 => Ok([rand::random(), rand::random(), 0]),
            3 => Ok([rand::random(), rand::random(), rand::random()]),
            n => {
                warn!("SMCCC TRNG: Invalid request for {n} u32 words");
                Err(SmcccTrngError::InvalidParameters)
            }
        }
    }

    fn rnd64(&self, n_bits: u64) -> Result<[u64; 3], SmcccTrngError> {
        match n_bits.div_ceil(u64::BITS.into()) {
            1 => Ok([rand::random(), 0, 0]),
            2 => Ok([rand::random(), rand::random(), 0]),
            3 => Ok([rand::random(), rand::random(), rand::random()]),
            n => {
                warn!("SMCCC TRNG: Invalid request for {n} u64 words");
                Err(SmcccTrngError::InvalidParameters)
            }
        }
    }
}

fn as_signed_usize(i: i32) -> usize {
    let sign_extended = i64::from(i);
    (sign_extended as u64).try_into().unwrap()
}

impl BusDevice for SmcccTrng {
    fn device_id(&self) -> DeviceId {
        PlatformDeviceId::SmcccTrng.into()
    }

    fn debug_label(&self) -> String {
        "SmcccTrng".to_owned()
    }

    fn handle_hypercall(&self, abi: &mut HypercallAbi) -> anyhow::Result<()> {
        let regs = match abi.hypercall_id() as u32 {
            Self::FID_TRNG_VERSION => {
                let r0 = as_signed_usize(fold_into_i32(self.version()));
                [r0, 0, 0, 0]
            }
            Self::FID_TRNG_FEATURES => {
                let feat = (*abi.get_argument(0).unwrap()) as u32;
                let r0 = as_signed_usize(fold_into_i32(self.features(feat)));
                [r0, 0, 0, 0]
            }
            Self::FID_TRNG_GET_UUID => match self.get_uuid() {
                Ok(uuid) => [
                    uuid[0].try_into().unwrap(),
                    uuid[1].try_into().unwrap(),
                    uuid[2].try_into().unwrap(),
                    uuid[3].try_into().unwrap(),
                ],
                Err(e) => [as_signed_usize(e.into()), 0, 0, 0],
            },
            Self::FID_TRNG_RND32 => {
                let n_bits = (*abi.get_argument(0).unwrap()) as u32;
                match self.rnd32(n_bits) {
                    Ok(entropy) => [
                        0,
                        entropy[0].try_into().unwrap(),
                        entropy[1].try_into().unwrap(),
                        entropy[2].try_into().unwrap(),
                    ],
                    Err(e) => [as_signed_usize(e.into()), 0, 0, 0],
                }
            }
            Self::FID_TRNG_RND64 => {
                let n_bits = (*abi.get_argument(0).unwrap()).try_into().unwrap();
                match self.rnd64(n_bits) {
                    Ok(entropy) => [
                        0,
                        entropy[0].try_into().unwrap(),
                        entropy[1].try_into().unwrap(),
                        entropy[2].try_into().unwrap(),
                    ],
                    Err(e) => [as_signed_usize(e.into()), 0, 0, 0],
                }
            }
            fid => bail!("SmcccTrng: Call {fid:#x} is not implemented"),
        };
        abi.set_results(&regs);
        Ok(())
    }

    fn read(&mut self, _info: BusAccessInfo, _data: &mut [u8]) {
        unimplemented!("SmcccTrng: read not supported");
    }

    fn write(&mut self, _info: BusAccessInfo, _data: &[u8]) {
        unimplemented!("SmcccTrng: write not supported");
    }
}

impl BusDeviceSync for SmcccTrng {
    fn read(&self, _info: BusAccessInfo, _data: &mut [u8]) {
        unimplemented!("SmcccTrng: read not supported");
    }

    fn write(&self, _info: BusAccessInfo, _data: &[u8]) {
        unimplemented!("SmcccTrng: write not supported");
    }
}

impl Suspendable for SmcccTrng {}
