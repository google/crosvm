// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#![deny(unsafe_op_in_unsafe_fn)]

//! Safe, Rusty wrappers around DPAPI.

use std::ffi::c_void;
use std::ptr;
use std::slice;

use anyhow::Context;
use anyhow::Result;
use winapi::um::dpapi::CryptProtectData;
use winapi::um::dpapi::CryptUnprotectData;
use winapi::um::winbase::LocalFree;
use winapi::um::wincrypt::DATA_BLOB;
use zeroize::Zeroize;

use crate::syscall_bail;

/// Wrapper around buffers allocated by DPAPI that can be freed with LocalFree.
pub struct LocalAllocBuffer {
    ptr: *mut u8,
    len: usize,
}

impl LocalAllocBuffer {
    /// # Safety
    /// 0. ptr is a valid buffer of length len and is safe to free with LocalFree.
    /// 1. The caller transfers ownership of the buffer to this object on construction.
    unsafe fn new(ptr: *mut u8, len: usize) -> Self {
        Self { ptr, len }
    }

    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        // SAFETY: ptr is a pointer to a buffer of length len.
        unsafe { slice::from_raw_parts_mut(self.ptr, self.len) }
    }

    pub fn as_slice(&self) -> &[u8] {
        // SAFETY: ptr is a pointer to a buffer of length len.
        unsafe { slice::from_raw_parts(self.ptr, self.len) }
    }
}

impl Drop for LocalAllocBuffer {
    fn drop(&mut self) {
        // This buffer likely contains cryptographic key material. Zero it.
        self.as_mut_slice().zeroize();

        // SAFETY: when this struct is created, the caller guarantees
        // ptr is a valid pointer to a buffer that can be freed with LocalFree.
        unsafe {
            LocalFree(self.ptr as *mut c_void);
        }
    }
}

/// # Summary
/// Wrapper around CryptProtectData that displays no UI.
pub fn crypt_protect_data(plaintext: &mut [u8]) -> Result<LocalAllocBuffer> {
    let mut plaintext_blob = DATA_BLOB {
        cbData: plaintext
            .len()
            .try_into()
            .context("plaintext size won't fit in DWORD")?,
        pbData: plaintext.as_mut_ptr(),
    };
    let mut ciphertext_blob = DATA_BLOB {
        cbData: 0,
        pbData: ptr::null_mut(),
    };

    // SAFETY: the FFI call is safe because
    // 1. plaintext_blob lives longer than the call.
    // 2. ciphertext_blob lives longer than the call, and we later give ownership of the memory the
    //    kernel allocates to LocalAllocBuffer which guarantees it is freed.
    let res = unsafe {
        CryptProtectData(
            &mut plaintext_blob as *mut _,
            /* szDataDescr= */ ptr::null_mut(),
            /* pOptionalEntropy= */ ptr::null_mut(),
            /* pvReserved= */ ptr::null_mut(),
            /* pPromptStruct */ ptr::null_mut(),
            /* dwFlags */ 0,
            &mut ciphertext_blob as *mut _,
        )
    };
    if res == 0 {
        syscall_bail!("CryptProtectData failed");
    }

    let ciphertext_len: usize = ciphertext_blob
        .cbData
        .try_into()
        .context("resulting ciphertext had an invalid size")?;

    // SAFETY: safe because ciphertext_blob refers to a valid buffer of the specified length. This
    // is guaranteed because CryptProtectData returned success.
    Ok(unsafe { LocalAllocBuffer::new(ciphertext_blob.pbData, ciphertext_len) })
}

/// # Summary
/// Wrapper around CryptProtectData that displays no UI.
pub fn crypt_unprotect_data(ciphertext: &mut [u8]) -> Result<LocalAllocBuffer> {
    let mut ciphertext_blob = DATA_BLOB {
        cbData: ciphertext
            .len()
            .try_into()
            .context("plaintext size won't fit in DWORD")?,
        pbData: ciphertext.as_mut_ptr(),
    };
    let mut plaintext_blob = DATA_BLOB {
        cbData: 0,
        pbData: ptr::null_mut(),
    };

    // SAFETY: the FFI call is safe because
    // 1. ciphertext_blob lives longer than the call.
    // 2. plaintext_blob lives longer than the call, and we later give ownership of the memory the
    //    kernel allocates to LocalAllocBuffer which guarantees it is freed.
    let res = unsafe {
        CryptUnprotectData(
            &mut ciphertext_blob as *mut _,
            /* szDataDescr= */ ptr::null_mut(),
            /* pOptionalEntropy= */ ptr::null_mut(),
            /* pvReserved= */ ptr::null_mut(),
            /* pPromptStruct */ ptr::null_mut(),
            /* dwFlags */ 0,
            &mut plaintext_blob as *mut _,
        )
    };
    if res == 0 {
        syscall_bail!("CryptUnprotectData failed");
    }

    let plaintext_len: usize = plaintext_blob
        .cbData
        .try_into()
        .context("resulting plaintext had an invalid size")?;

    // SAFETY: safe because plaintext_blob refers to a valid buffer of the specified length. This
    // is guaranteed because CryptUnprotectData returned success.
    Ok(unsafe { LocalAllocBuffer::new(plaintext_blob.pbData, plaintext_len) })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_empty_string_is_valid() {
        let plaintext_str = "";
        let mut plaintext_buffer = Vec::from(plaintext_str.as_bytes());

        let mut ciphertext_buffer = crypt_protect_data(plaintext_buffer.as_mut_slice()).unwrap();
        let decrypted_plaintext_buffer =
            crypt_unprotect_data(ciphertext_buffer.as_mut_slice()).unwrap();
        let decrypted_plaintext_str =
            std::str::from_utf8(decrypted_plaintext_buffer.as_slice()).unwrap();
        assert_eq!(plaintext_str, decrypted_plaintext_str);
    }

    #[test]
    fn encrypt_decrypt_plaintext_matches() {
        let plaintext_str = "test plaintext";
        let mut plaintext_buffer = Vec::from(plaintext_str.as_bytes());

        let mut ciphertext_buffer = crypt_protect_data(plaintext_buffer.as_mut_slice()).unwrap();

        // If our plaintext & ciphertext are the same, something is very wrong.
        assert_ne!(plaintext_str.as_bytes(), ciphertext_buffer.as_slice());

        // Decrypt the ciphertext and make sure it's our original plaintext.
        let decrypted_plaintext_buffer =
            crypt_unprotect_data(ciphertext_buffer.as_mut_slice()).unwrap();
        let decrypted_plaintext_str =
            std::str::from_utf8(decrypted_plaintext_buffer.as_slice()).unwrap();
        assert_eq!(plaintext_str, decrypted_plaintext_str);
    }
}
