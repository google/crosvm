// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#![cfg(unix)]

use std::path::Path;

use base::safe_descriptor_from_path;
use base::Error;
use base::FromRawDescriptor;
use base::SafeDescriptor;
use libc::EBADF;
use libc::EINVAL;

/// Runs all unix specific integration tests in a single binary.
mod net;
mod process;
mod scoped_signal_handler;
mod syslog;
mod tube;

#[test]
fn safe_descriptor_from_path_valid() {
    assert!(safe_descriptor_from_path(Path::new("/proc/self/fd/2"))
        .unwrap()
        .is_some());
}

#[test]
fn safe_descriptor_from_path_invalid_integer() {
    assert_eq!(
        safe_descriptor_from_path(Path::new("/proc/self/fd/blah")),
        Err(Error::new(EINVAL))
    );
}

#[test]
fn safe_descriptor_from_path_invalid_fd() {
    assert_eq!(
        safe_descriptor_from_path(Path::new("/proc/self/fd/42")),
        Err(Error::new(EBADF))
    );
}

#[test]
fn safe_descriptor_from_path_none() {
    assert_eq!(
        safe_descriptor_from_path(Path::new("/something/else")).unwrap(),
        None
    );
}

#[test]
#[allow(clippy::eq_op)]
fn clone_equality() {
    let ret = unsafe { libc::eventfd(0, 0) };
    if ret < 0 {
        panic!("failed to create eventfd");
    }
    let descriptor = unsafe { SafeDescriptor::from_raw_descriptor(ret) };

    assert_eq!(descriptor, descriptor);

    assert_eq!(
        descriptor,
        descriptor.try_clone().expect("failed to clone eventfd")
    );

    let ret = unsafe { libc::eventfd(0, 0) };
    if ret < 0 {
        panic!("failed to create eventfd");
    }
    let another = unsafe { SafeDescriptor::from_raw_descriptor(ret) };

    assert_ne!(descriptor, another);
}
