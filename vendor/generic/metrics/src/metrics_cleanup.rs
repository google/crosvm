// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Provides an tool for metrics client cleanup which may hold global state.

/// Ensures any cleanup necessary is performed on drop. Can be used to ensure cleanup is done
/// regardless of how the caller exits. Should be idempotent.
pub struct MetricsClientDestructor(Box<dyn FnMut()>);
impl MetricsClientDestructor {
    pub fn new<T: 'static + FnMut()>(cleanup: T) -> Self {
        MetricsClientDestructor(Box::new(cleanup))
    }
    /// A convenience method for immediately dropping self and invoking drop logic on the contained
    /// object.
    pub fn cleanup(self) {}
}
impl Drop for MetricsClientDestructor {
    fn drop(&mut self) {
        self.0();
    }
}
