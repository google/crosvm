// Copyright 2025 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! AArch64 system register names and encoding.

mod consts;
mod funcs;
mod gen;

#[cfg(test)]
mod tests;

pub use consts::*;
pub use funcs::*;
pub use gen::*;
use serde::Deserialize;
use serde::Serialize;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("invalid CRm {0}")]
    InvalidCrm(u8),
    #[error("invalid CRn {0}")]
    InvalidCrn(u8),
    #[error("invalid Op0 {0}")]
    InvalidOp0(u8),
    #[error("invalid Op1 {0}")]
    InvalidOp1(u8),
    #[error("invalid Op2 {0}")]
    InvalidOp2(u8),
}

pub type Result<T> = std::result::Result<T, Error>;

/// AArch64 system register as used in MSR/MRS instructions.
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Deserialize, Serialize)]
#[serde(transparent)]
pub struct AArch64SysRegId(u16);

impl AArch64SysRegId {
    /// Construct a system register ID from Op0, Op1, CRn, CRm, Op2.
    ///
    /// The meanings of the arguments are described in the ARMv8 Architecture Reference Manual
    /// "System instruction class encoding overview" section.
    pub fn new(op0: u8, op1: u8, crn: u8, crm: u8, op2: u8) -> Result<Self> {
        if op0 > 0b11 {
            return Err(Error::InvalidOp0(op0));
        }
        if op1 > 0b111 {
            return Err(Error::InvalidOp1(op1));
        }
        if crn > 0b1111 {
            return Err(Error::InvalidCrn(crn));
        }
        if crm > 0b1111 {
            return Err(Error::InvalidCrm(crm));
        }
        if op2 > 0b111 {
            return Err(Error::InvalidOp2(op2));
        }

        Ok(Self::new_unchecked(op0, op1, crn, crm, op2))
    }

    /// Construct a system register ID from Op0, Op1, CRn, CRm, Op2.
    ///
    /// Out-of-range values will be silently truncated.
    pub const fn new_unchecked(op0: u8, op1: u8, crn: u8, crm: u8, op2: u8) -> Self {
        let op0 = (op0 as u16 & 0b11) << 14;
        let op1 = (op1 as u16 & 0b111) << 11;
        let crn = (crn as u16 & 0b1111) << 7;
        let crm = (crm as u16 & 0b1111) << 3;
        let op2 = op2 as u16 & 0b111;
        Self(op0 | op1 | crn | crm | op2)
    }

    #[inline]
    pub fn from_encoded(v: u16) -> Self {
        Self(v)
    }

    #[inline]
    pub const fn op0(&self) -> u8 {
        ((self.0 >> 14) & 0b11) as u8
    }

    #[inline]
    pub const fn op1(&self) -> u8 {
        ((self.0 >> 11) & 0b111) as u8
    }

    #[inline]
    pub const fn crn(&self) -> u8 {
        ((self.0 >> 7) & 0b1111) as u8
    }

    #[inline]
    pub const fn crm(&self) -> u8 {
        ((self.0 >> 3) & 0b1111) as u8
    }

    #[inline]
    pub const fn op2(&self) -> u8 {
        (self.0 & 0b111) as u8
    }

    /// Returns the system register as encoded in bits 5-20 of MRS and MSR instructions.
    #[inline]
    pub const fn encoded(&self) -> u16 {
        self.0
    }
}

impl std::fmt::Debug for AArch64SysRegId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AArch64SysRegId")
            .field("Op0", &self.op0())
            .field("Op1", &self.op1())
            .field("CRn", &self.crn())
            .field("CRm", &self.crm())
            .field("Op2", &self.op2())
            .finish()
    }
}
