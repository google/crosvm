// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::alloc::alloc;
use std::alloc::alloc_zeroed;
use std::alloc::dealloc;
use std::alloc::Layout;
use std::cmp::min;

/// A contiguous memory allocation with a specified size and alignment, with a
/// Drop impl to perform the deallocation.
///
/// Conceptually this is like a Box<[u8]> but for which we can select a minimum
/// required alignment at the time of allocation.
///
/// # Example
///
/// ```
/// use std::alloc::Layout;
/// use std::mem;
/// use base::LayoutAllocation;
///
/// #[repr(C)]
/// struct Header {
///     q: usize,
///     entries: [Entry; 0], // flexible array member
/// }
///
/// #[repr(C)]
/// struct Entry {
///     e: usize,
/// }
///
/// fn demo(num_entries: usize) {
///     let size = mem::size_of::<Header>() + num_entries * mem::size_of::<Entry>();
///     let layout = Layout::from_size_align(size, mem::align_of::<Header>()).unwrap();
///     let mut allocation = LayoutAllocation::zeroed(layout);
///
///     // SAFETY:
///     // Safe to obtain an exclusive reference because there are no other
///     // references to the allocation yet and all-zero is a valid bit pattern for
///     // our header.
///     let header = unsafe { allocation.as_mut::<Header>() };
/// }
/// ```
pub struct LayoutAllocation {
    ptr: *mut u8,
    layout: Layout,
}

impl LayoutAllocation {
    /// Allocates memory with the specified size and alignment. The content is
    /// not initialized.
    ///
    /// Uninitialized data is not safe to read. Further, it is not safe to
    /// obtain a reference to data potentially holding a bit pattern
    /// incompatible with its type, for example an uninitialized bool or enum.
    pub fn uninitialized(layout: Layout) -> Self {
        let ptr = if layout.size() > 0 {
            // SAFETY:
            // Safe as long as we guarantee layout.size() > 0.
            unsafe { alloc(layout) }
        } else {
            layout.align() as *mut u8
        };
        LayoutAllocation { ptr, layout }
    }

    /// Allocates memory with the specified size and alignment and initializes
    /// the content to all zero-bytes.
    ///
    /// Note that zeroing the memory does not necessarily make it safe to obtain
    /// a reference to the allocation. Depending on the intended type T,
    /// all-zero may or may not be a legal bit pattern for that type. For
    /// example obtaining a reference would immediately be undefined behavior if
    /// one of the fields has type NonZeroUsize.
    pub fn zeroed(layout: Layout) -> Self {
        let ptr = if layout.size() > 0 {
            // SAFETY:
            // Safe as long as we guarantee layout.size() > 0.
            unsafe { alloc_zeroed(layout) }
        } else {
            layout.align() as *mut u8
        };
        LayoutAllocation { ptr, layout }
    }

    /// Returns a raw pointer to the allocated data.
    pub fn as_ptr<T>(&self) -> *mut T {
        self.ptr as *mut T
    }

    /// Returns a reference to the `Layout` used to create this allocation.
    pub fn layout(&self) -> &Layout {
        &self.layout
    }

    /// Returns a shared reference to the allocated data.
    ///
    /// # Safety
    ///
    /// Caller is responsible for ensuring that the data behind this pointer has
    /// been initialized as much as necessary and that there are no already
    /// existing mutable references to any part of the data.
    pub unsafe fn as_ref<T>(&self) -> &T {
        &*self.as_ptr()
    }

    /// Returns an exclusive reference to the allocated data.
    ///
    /// # Safety
    ///
    /// Caller is responsible for ensuring that the data behind this pointer has
    /// been initialized as much as necessary and that there are no already
    /// existing references to any part of the data.
    pub unsafe fn as_mut<T>(&mut self) -> &mut T {
        &mut *self.as_ptr()
    }

    /// Returns a shared slice reference to the allocated data.
    ///
    /// # Arguments
    ///
    /// `num_elements` - Number of `T` elements to include in the slice.
    ///                  The length of the slice will be capped to the allocation's size.
    ///                  Caller must ensure that any sliced elements are initialized.
    ///
    /// # Safety
    ///
    /// Caller is responsible for ensuring that the data behind this pointer has
    /// been initialized as much as necessary and that there are no already
    /// existing mutable references to any part of the data.
    pub unsafe fn as_slice<T>(&self, num_elements: usize) -> &[T] {
        let len = min(num_elements, self.layout.size() / std::mem::size_of::<T>());
        std::slice::from_raw_parts(self.as_ptr(), len)
    }

    /// Returns an exclusive slice reference to the allocated data.
    ///
    /// # Arguments
    ///
    /// `num_elements` - Number of `T` elements to include in the slice.
    ///                  The length of the slice will be capped to the allocation's size.
    ///                  Caller must ensure that any sliced elements are initialized.
    ///
    /// # Safety
    ///
    /// Caller is responsible for ensuring that the data behind this pointer has
    /// been initialized as much as necessary and that there are no already
    /// existing references to any part of the data.
    pub unsafe fn as_mut_slice<T>(&mut self, num_elements: usize) -> &mut [T] {
        let len = min(num_elements, self.layout.size() / std::mem::size_of::<T>());
        std::slice::from_raw_parts_mut(self.as_ptr(), len)
    }
}

impl Drop for LayoutAllocation {
    fn drop(&mut self) {
        if self.layout.size() > 0 {
            // SAFETY:
            // Safe as long as we guarantee layout.size() > 0.
            unsafe {
                dealloc(self.ptr, self.layout);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::mem::align_of;
    use std::mem::size_of;

    use super::*;

    #[test]
    fn test_as_slice_u32() {
        let layout = Layout::from_size_align(size_of::<u32>() * 15, align_of::<u32>()).unwrap();
        let allocation = LayoutAllocation::zeroed(layout);
        // SAFETY:
        // Slice less than the allocation size, which will return a slice of only the requested
        // length.
        let slice: &[u32] = unsafe { allocation.as_slice(15) };
        assert_eq!(slice.len(), 15);
        assert_eq!(slice[0], 0);
        assert_eq!(slice[14], 0);
    }

    #[test]
    fn test_as_slice_u32_smaller_len() {
        let layout = Layout::from_size_align(size_of::<u32>() * 15, align_of::<u32>()).unwrap();
        let allocation = LayoutAllocation::zeroed(layout);

        // SAFETY:
        // Slice less than the allocation size, which will return a slice of only the requested
        // length.
        let slice: &[u32] = unsafe { allocation.as_slice(5) };
        assert_eq!(slice.len(), 5);
    }

    #[test]
    fn test_as_slice_u32_larger_len() {
        let layout = Layout::from_size_align(size_of::<u32>() * 15, align_of::<u32>()).unwrap();
        let allocation = LayoutAllocation::zeroed(layout);

        // SAFETY:
        // Slice more than the allocation size, which will clamp the returned slice len to the
        // limit.
        let slice: &[u32] = unsafe { allocation.as_slice(100) };
        assert_eq!(slice.len(), 15);
    }

    #[test]
    fn test_as_slice_u32_remainder() {
        // Allocate a buffer that is not a multiple of u32 in size.
        let layout = Layout::from_size_align(size_of::<u32>() * 15 + 2, align_of::<u32>()).unwrap();
        let allocation = LayoutAllocation::zeroed(layout);

        // SAFETY:
        // Slice as many u32s as possible, which should return a slice that only includes the full
        // u32s, not the trailing 2 bytes.
        let slice: &[u32] = unsafe { allocation.as_slice(100) };
        assert_eq!(slice.len(), 15);
    }
}
