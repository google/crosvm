// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#![deny(missing_docs)]

use std::ops::Range;

/// [PresentList] is a utility for tracking whether or not pages in an address space are present.
///
/// TODO(b/262379173): Use bit vector to represent the list instead of boolean vector.
#[derive(Debug)]
pub struct PresentList {
    list: Vec<bool>,
    /// Cursor used when iterating over pages present. All pages with indices less than the cursor
    /// are known to be empty.
    min_possible_idx: usize,
}

impl PresentList {
    /// Allocates the list of state.
    ///
    /// # Arguments
    ///
    /// * `num_of_pages` - the number of pages in the region.
    pub fn new(num_of_pages: usize) -> Self {
        Self {
            list: vec![false; num_of_pages],
            min_possible_idx: num_of_pages,
        }
    }

    /// Returns the length of the list.
    pub fn len(&self) -> usize {
        self.list.len()
    }

    /// Returns whether the page is present or not
    ///
    /// # Arguments
    ///
    /// * `idx` - the index in the list.
    pub fn get(&self, idx: usize) -> Option<&bool> {
        self.list.get(idx)
    }

    /// Marks the range of indices as present.
    ///
    /// # Arguments
    ///
    /// * `idx_range` - the indices of consecutive pages to be marked as present.
    pub fn mark_as_present(&mut self, idx_range: Range<usize>) -> bool {
        let result = self.update(idx_range, true);
        // Setting 0 is faster than setting exact index by comparing the idx_range.start and current
        // min_possible_idx because it does not have conditional branch. This may cause useless
        // traversing on first_data_range(). But it should be acceptable because first_data_range()
        // is called on swap in and swap out while mark_as_present() is called on moving the guest
        // memory to the staging which is more latency-aware.
        // TODO(kawasin): Use a branchless conditional move.
        self.min_possible_idx = 0;
        result
    }

    /// Clears the states of the pages.
    ///
    /// # Arguments
    ///
    /// * `idx_range` - the indices of consecutive pages to be cleared.
    pub fn clear_range(&mut self, idx_range: Range<usize>) -> bool {
        let result = self.update(idx_range.clone(), false);
        // TODO(b/265758094): skip updating min_possible_idx on page fault handling.
        if result
            && idx_range.start <= self.min_possible_idx
            && self.min_possible_idx < idx_range.end
        {
            self.min_possible_idx = idx_range.end;
        }
        result
    }

    fn update(&mut self, idx_range: Range<usize>, value: bool) -> bool {
        if let Some(list) = self.list.get_mut(idx_range) {
            for v in list {
                *v = value;
            }
            true
        } else {
            false
        }
    }

    /// Returns the first range of indices of consecutive pages present in the list.
    ///
    /// # Arguments
    ///
    /// * `max_pages` - the max size of the returned chunk even if the chunk of consecutive present
    ///   pages is longer than this.
    pub fn first_data_range(&mut self, max_pages: usize) -> Option<Range<usize>> {
        let head_idx =
            if let Some(offset) = self.list[self.min_possible_idx..].iter().position(|v| *v) {
                // Update min_possible_idx otherwise min_possible_idx will not be updated on next
                // clear_range().
                self.min_possible_idx += offset;
                self.min_possible_idx
            } else {
                // Update min_possible_idx to skip traversing on next calls.
                self.min_possible_idx = self.list.len();
                return None;
            };
        let tail_idx = std::cmp::min(self.list.len() - head_idx, max_pages) + head_idx;
        let tail_idx = self.list[head_idx + 1..tail_idx]
            .iter()
            .position(|v| !*v)
            .map_or(tail_idx, |offset| offset + head_idx + 1);
        Some(head_idx..tail_idx)
    }

    /// Returns the count of present pages in the list.
    pub fn present_pages(&self) -> usize {
        self.list[self.min_possible_idx..]
            .iter()
            .fold(0, |acc, v| if *v { acc + 1 } else { acc })
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn len() {
        assert_eq!(PresentList::new(1).len(), 1);
        assert_eq!(PresentList::new(100).len(), 100);
    }

    #[test]
    fn get_default() {
        let list = PresentList::new(200);

        assert_eq!(*list.get(0).unwrap(), false);
        assert_eq!(*list.get(10).unwrap(), false);
    }

    #[test]
    fn get_out_of_range() {
        let list = PresentList::new(200);

        assert!(list.get(200).is_none());
    }

    #[test]
    fn mark_as_present() {
        let mut list = PresentList::new(200);

        assert!(list.mark_as_present(10..12));
        assert_eq!(*list.get(9).unwrap(), false);
        assert_eq!(*list.get(10).unwrap(), true);
        assert_eq!(*list.get(11).unwrap(), true);
        assert_eq!(*list.get(12).unwrap(), false);
    }

    #[test]
    fn mark_as_present_duplicated() {
        let mut list = PresentList::new(200);

        assert!(list.mark_as_present(10..12));
        assert!(list.mark_as_present(11..13));
        assert_eq!(*list.get(9).unwrap(), false);
        assert_eq!(*list.get(10).unwrap(), true);
        assert_eq!(*list.get(11).unwrap(), true);
        assert_eq!(*list.get(12).unwrap(), true);
        assert_eq!(*list.get(13).unwrap(), false);
    }

    #[test]
    fn mark_as_present_out_of_range() {
        let mut list = PresentList::new(200);

        assert!(!list.mark_as_present(10..201));
        assert_eq!(*list.get(10).unwrap(), false);
    }

    #[test]
    fn clear_range() {
        let mut list = PresentList::new(200);

        assert!(list.mark_as_present(10..14));
        assert!(list.clear_range(11..13));
        assert_eq!(*list.get(9).unwrap(), false);
        assert_eq!(*list.get(10).unwrap(), true);
        assert_eq!(*list.get(11).unwrap(), false);
        assert_eq!(*list.get(12).unwrap(), false);
        assert_eq!(*list.get(13).unwrap(), true);
        assert_eq!(*list.get(14).unwrap(), false);
    }

    #[test]
    fn clear_range_duplicated() {
        let mut list = PresentList::new(200);

        assert!(list.mark_as_present(10..14));
        assert!(list.clear_range(11..13));
        assert!(list.clear_range(12..15));
        assert_eq!(*list.get(9).unwrap(), false);
        assert_eq!(*list.get(10).unwrap(), true);
        assert_eq!(*list.get(11).unwrap(), false);
        assert_eq!(*list.get(12).unwrap(), false);
        assert_eq!(*list.get(13).unwrap(), false);
        assert_eq!(*list.get(14).unwrap(), false);
        assert_eq!(*list.get(15).unwrap(), false);
    }

    #[test]
    fn clear_range_out_of_range() {
        let mut list = PresentList::new(200);

        assert!(list.mark_as_present(10..11));
        assert!(!list.clear_range(10..201));
        assert_eq!(*list.get(10).unwrap(), true);
    }

    #[test]
    fn first_data_range() {
        let mut list = PresentList::new(200);

        list.mark_as_present(1..3);
        list.mark_as_present(12..13);
        list.mark_as_present(20..22);
        list.mark_as_present(22..23);
        list.mark_as_present(23..30);

        assert_eq!(list.first_data_range(200).unwrap(), 1..3);
        list.clear_range(1..3);
        assert_eq!(list.first_data_range(200).unwrap(), 12..13);
        list.clear_range(12..13);
        assert_eq!(list.first_data_range(200).unwrap(), 20..30);
        list.clear_range(20..30);
        assert!(list.first_data_range(200).is_none());
    }

    #[test]
    fn first_data_range_clear_partially() {
        let mut list = PresentList::new(200);

        list.mark_as_present(10..20);

        list.clear_range(5..10);
        assert_eq!(list.first_data_range(200).unwrap(), 10..20);
        list.clear_range(5..12);
        assert_eq!(list.first_data_range(200).unwrap(), 12..20);
        list.clear_range(19..21);
        assert_eq!(list.first_data_range(200).unwrap(), 12..19);
        list.clear_range(16..17);
        assert_eq!(list.first_data_range(200).unwrap(), 12..16);
    }

    #[test]
    fn first_data_range_mark_after_clear() {
        let mut list = PresentList::new(200);

        list.mark_as_present(10..20);

        list.clear_range(10..15);
        assert_eq!(list.first_data_range(200).unwrap(), 15..20);
        list.mark_as_present(5..15);
        assert_eq!(list.first_data_range(200).unwrap(), 5..20);
    }

    #[test]
    fn first_data_range_end_is_full() {
        let mut list = PresentList::new(20);

        list.mark_as_present(10..20);

        assert_eq!(list.first_data_range(20).unwrap(), 10..20);
    }

    #[test]
    fn first_data_range_max_pages() {
        let mut list = PresentList::new(20);

        list.mark_as_present(10..13);

        assert_eq!(list.first_data_range(1).unwrap(), 10..11);
        assert_eq!(list.first_data_range(2).unwrap(), 10..12);
        assert_eq!(list.first_data_range(3).unwrap(), 10..13);
        assert_eq!(list.first_data_range(4).unwrap(), 10..13);
    }

    #[test]
    fn present_pages() {
        let mut list = PresentList::new(20);

        list.mark_as_present(1..5);
        list.mark_as_present(12..13);

        assert_eq!(list.present_pages(), 5);
    }
}
