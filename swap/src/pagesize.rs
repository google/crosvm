// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Helpers to calculate values derived from page size.
//!
//! This has performance benefits from:
//!
//! * Avoiding calling `sysconf(_SC_PAGESIZE)` multiple times by caching the shift bit.
//! * Using the (faster) shift instruction instead of (slower) multiply/divide instruction.

use std::fs;
use std::str;

use anyhow::Context;
use base::pagesize;
use base::warn;
use once_cell::sync::Lazy;

const TRANSPARENT_HUGEPAGE_SIZE_PATH: &str = "/sys/kernel/mm/transparent_hugepage/hpage_pmd_size";

static PAGESIZE_SHIFT: Lazy<u8> = Lazy::new(|| {
    let pagesize_shift = pagesize().trailing_zeros();
    // pagesize() should be power of 2 in almost all cases. vmm-swap feature does not support
    // systems in which page size is not power of 2.
    if 1 << pagesize_shift != pagesize() {
        panic!("page size is not power of 2");
    }
    // pagesize_shift must be less than 64 since usize has at most 64 bits.
    pagesize_shift as u8
});

/// The transparent hugepage size loaded from /sys/kernel/mm/transparent_hugepage/hpage_pmd_size.
///
/// If it fails to load the hugepage size, it fallbacks to use 2MB.
pub static THP_SIZE: Lazy<usize> = Lazy::new(|| {
    match load_transparent_hugepage_size() {
        Ok(transparent_hugepage_size) => transparent_hugepage_size,
        Err(e) => {
            warn!(
                "failed to load huge page size: {:?}. fallback to 2MB as hugepage size.",
                e
            );
            2 * 1024 * 1024 // = 2MB
        }
    }
});

fn load_transparent_hugepage_size() -> anyhow::Result<usize> {
    let buf = fs::read(TRANSPARENT_HUGEPAGE_SIZE_PATH).context("read thp size file")?;
    let text = str::from_utf8(&buf).context("utf8")?;
    let hugepage_size = text.trim().parse::<usize>().context("parse usize")?;
    Ok(hugepage_size)
}

/// Helper methods to calculate values derived from page size.
///
/// This has performance benefits from:
///
/// * Avoiding calling `sysconf(_SC_PAGESIZE)` multiple times by caching the shift bit.
/// * Using the (faster) shift instruction instead of (slower) multiply/divide instruction.
#[derive(Clone, Copy, Debug)]
pub struct PagesizeShift(u8);

/// The page index of the page which contains the "addr".
#[inline]
pub fn addr_to_page_idx(addr: usize) -> usize {
    addr >> *PAGESIZE_SHIFT
}

/// The head address of the page.
#[inline]
pub fn page_idx_to_addr(page_idx: usize) -> usize {
    page_idx << *PAGESIZE_SHIFT
}

/// The head address of the page which contains the "addr".
#[inline]
pub fn page_base_addr(addr: usize) -> usize {
    let pagesize_shift = *PAGESIZE_SHIFT;
    (addr >> pagesize_shift) << pagesize_shift
}

/// Returns whether the address/size is aligned with page.
#[inline]
pub fn is_page_aligned(v: usize) -> bool {
    let mask = (1 << *PAGESIZE_SHIFT) - 1;
    v & mask == 0
}

/// Converts the bytes to number of pages.
///
/// This rounds down if the `size_in_bytes` is not multiple of page size.
#[inline]
pub fn bytes_to_pages(size_in_bytes: usize) -> usize {
    size_in_bytes >> *PAGESIZE_SHIFT
}

/// Converts number of pages to byte size.
#[inline]
pub fn pages_to_bytes(num_of_pages: usize) -> usize {
    num_of_pages << *PAGESIZE_SHIFT
}

/// Returns whether the address/size is aligned with hugepage.
#[inline]
pub fn is_hugepage_aligned(v: usize) -> bool {
    v & (*THP_SIZE - 1) == 0
}

/// Rounds up the address/size with the hugepage size.
#[inline]
pub fn round_up_hugepage_size(v: usize) -> usize {
    let hugepage_size = *THP_SIZE;
    (v + hugepage_size - 1) & !(hugepage_size - 1)
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_addr_to_page_idx() {
        let addr = 10 * pagesize();
        assert_eq!(addr_to_page_idx(addr - 1), 9);
        assert_eq!(addr_to_page_idx(addr), 10);
        assert_eq!(addr_to_page_idx(addr + 1), 10);
    }

    #[test]
    fn test_page_idx_to_addr() {
        assert_eq!(page_idx_to_addr(10), 10 * pagesize());
    }

    #[test]
    fn test_page_base_addr() {
        let addr = 10 * pagesize();
        assert_eq!(page_base_addr(addr - 1), addr - pagesize());
        assert_eq!(page_base_addr(addr), addr);
        assert_eq!(page_base_addr(addr + 1), addr);
    }

    #[test]
    fn test_is_page_aligned() {
        let addr = 10 * pagesize();
        assert!(!is_page_aligned(addr - 1));
        assert!(is_page_aligned(addr));
        assert!(!is_page_aligned(addr + 1));
    }

    #[test]
    fn test_bytes_to_pages() {
        assert_eq!(bytes_to_pages(10 * pagesize()), 10);
        assert_eq!(bytes_to_pages(10 * pagesize() + 1), 10);
    }

    #[test]
    fn test_pages_to_bytes() {
        assert_eq!(pages_to_bytes(1), pagesize());
        assert_eq!(pages_to_bytes(10), 10 * pagesize());
    }

    #[test]
    fn test_is_hugepage_aligned() {
        let addr = 10 * *THP_SIZE;
        assert!(!is_hugepage_aligned(addr - 1));
        assert!(is_hugepage_aligned(addr));
        assert!(!is_hugepage_aligned(addr - 1));
        assert!(!is_hugepage_aligned(pagesize()));
    }

    #[test]
    fn test_round_up_hugepage_size() {
        let addr = 10 * *THP_SIZE;

        assert_eq!(round_up_hugepage_size(0), 0);
        assert_eq!(round_up_hugepage_size(addr - 1), addr);
        assert_eq!(round_up_hugepage_size(addr), addr);
        assert_eq!(round_up_hugepage_size(addr + 1), addr + *THP_SIZE);
        assert_eq!(round_up_hugepage_size(pagesize()), *THP_SIZE);
    }
}
