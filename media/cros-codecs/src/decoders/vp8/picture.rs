// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::cell::RefCell;
use std::rc::Rc;

use crate::decoders::vp8::parser::Header;
use crate::decoders::DynPicture;
use crate::decoders::MappableHandle;

/// A VP8 picture.
pub struct Picture<T> {
    /// The header that was parsed when decoding this picture.
    pub header: Header,
    /// The backend handle with any data the backend needs in order to back this
    /// picture.
    pub backend_handle: Option<T>,
    /// A number that identifies the picture.
    timestamp: u64,
}

impl<T> Picture<T> {
    pub fn new(header: Header, backend_handle: Option<T>, timestamp: u64) -> Self {
        Self {
            header,
            backend_handle,
            timestamp,
        }
    }

    /// Gets a shared reference to the backend handle of this picture. Assumes
    /// that this picture is backed by a handle, which may not be the case if
    /// the picture has "show_previous_frame" set, for example.
    pub fn backend_handle_unchecked(&self) -> &T {
        self.backend_handle.as_ref().unwrap()
    }

    /// Gets an exclusive reference to the backend handle of this picture.
    /// Assumes that this picture is backed by a handle, which may not be the
    /// case if the picture has "show_previous_frame" set, for example.
    pub fn backend_handle_unchecked_mut(&mut self) -> &mut T {
        self.backend_handle.as_mut().unwrap()
    }

    /// Whether two pictures are the same.
    pub fn same(lhs: &Rc<RefCell<Self>>, rhs: &Rc<RefCell<Self>>) -> bool {
        Rc::ptr_eq(lhs, rhs)
    }

    /// Get a reference to the picture's timestamp.
    pub fn timestamp(&self) -> u64 {
        self.timestamp
    }
}

impl<T: MappableHandle> DynPicture for Picture<T> {
    fn dyn_mappable_handle(&self) -> &dyn MappableHandle {
        self.backend_handle.as_ref().unwrap()
    }

    fn dyn_mappable_handle_mut(&mut self) -> &mut dyn MappableHandle {
        self.backend_handle.as_mut().unwrap()
    }
}
