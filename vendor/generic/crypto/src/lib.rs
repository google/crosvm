// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Provides simple Read/Write wrappers that transparently encrypt/decrypt data
//! that passes through them.

use std::fmt::Debug;
use std::fmt::Display;
use std::fmt::Formatter;

use serde::Deserialize;
use serde::Serialize;
use zeroize::Zeroize;

mod always_panic_impl;
use always_panic_impl as crypto_impl;
pub use crypto_impl::*;

/// Stores a cryptographic key, but permits no access to the underlying data outside of this crate.
///
/// Note: there may be multiple copies of this trait because we want to restrict the internals
/// to access only within this crate.
#[derive(Clone, Default, Serialize, Deserialize)]
#[repr(transparent)]
pub struct CryptKey {
    pub(crate) key_bytes: SecureByteVec,
}

/// A vec wrapper suitable for storing cryptographic key material. On drop, the memory used will be
/// zeroed.
#[derive(Clone, Default, Serialize, Deserialize)]
#[repr(transparent)]
pub struct SecureByteVec {
    data: Vec<u8>,
}

impl Display for SecureByteVec {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str("SecureByteVec")
    }
}
impl Debug for SecureByteVec {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str("debug: SecureByteVec")
    }
}

impl From<Vec<u8>> for SecureByteVec {
    fn from(value: Vec<u8>) -> Self {
        Self { data: value }
    }
}

impl From<&[u8]> for SecureByteVec {
    fn from(value: &[u8]) -> Self {
        value.to_vec().into()
    }
}

impl SecureByteVec {
    pub fn as_slice(&self) -> &[u8] {
        self.data.as_slice()
    }
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        self.data.as_mut_slice()
    }
}

impl Drop for SecureByteVec {
    fn drop(&mut self) {
        self.data.zeroize();
    }
}
