// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Helpers to calculate values derived from page size.
//!
//! This has performance benefits from:
//!
//! * Avoiding calling `sysconf(_SC_PAGESIZE)` multiple times by caching the shift bit.
//! * Using the (faster) shift instruction instead of (slower) multiply/divide instruction.

use base::pagesize;
use once_cell::sync::Lazy;

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

/// Whether the address is aligned with page.
#[inline]
pub fn is_page_aligned(addr: usize) -> bool {
    let mask = (1 << *PAGESIZE_SHIFT) - 1;
    addr & mask == 0
}

/// Convert the bytes to number of pages.
///
/// This rounds down if the `size_in_bytes` is not multiple of page size.
#[inline]
pub fn bytes_to_pages(size_in_bytes: usize) -> usize {
    size_in_bytes >> *PAGESIZE_SHIFT
}

/// Convert number of pages to byte size.
#[inline]
pub fn pages_to_bytes(num_of_pages: usize) -> usize {
    num_of_pages << *PAGESIZE_SHIFT
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
}
