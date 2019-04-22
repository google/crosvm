// Copyright 2019 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::alloc::{alloc, alloc_zeroed, dealloc, Layout};

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
/// use sys_util::LayoutAllocation;
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
            unsafe {
                // Safe as long as we guarantee layout.size() > 0.
                alloc(layout)
            }
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
            unsafe {
                // Safe as long as we guarantee layout.size() > 0.
                alloc_zeroed(layout)
            }
        } else {
            layout.align() as *mut u8
        };
        LayoutAllocation { ptr, layout }
    }

    /// Returns a raw pointer to the allocated data.
    pub fn as_ptr<T>(&self) -> *mut T {
        self.ptr as *mut T
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
}

impl Drop for LayoutAllocation {
    fn drop(&mut self) {
        if self.layout.size() > 0 {
            unsafe {
                // Safe as long as we guarantee layout.size() > 0.
                dealloc(self.ptr, self.layout);
            }
        }
    }
}
