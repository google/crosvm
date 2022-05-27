// Copyright 2022 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::io::{Error, Read, Result};

use winapi::{
    shared::{minwindef::LPVOID, ntdef::NULL},
    um::{fileapi::ReadFile, minwinbase::LPOVERLAPPED},
};

use crate::{AsRawDescriptor, ReadNotifier};

pub struct Console(std::io::Stdin);

impl Console {
    pub fn new() -> Self {
        Self(std::io::stdin())
    }
}

impl Read for Console {
    fn read(&mut self, out: &mut [u8]) -> Result<usize> {
        let mut num_of_bytes_read: u32 = 0;
        // Safe because `out` is guarenteed to be a valid mutable array
        // and `num_of_bytes_read` is a valid u32.
        let res = unsafe {
            ReadFile(
                self.0.as_raw_descriptor(),
                out.as_mut_ptr() as LPVOID,
                out.len() as u32,
                &mut num_of_bytes_read,
                NULL as LPOVERLAPPED,
            )
        };
        let error = Error::last_os_error();
        if res == 0 {
            Err(error)
        } else {
            Ok(num_of_bytes_read as usize)
        }
    }
}

impl ReadNotifier for Console {
    fn get_read_notifier(&self) -> &dyn AsRawDescriptor {
        &self.0
    }
}
