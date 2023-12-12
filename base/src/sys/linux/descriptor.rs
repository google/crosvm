// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use crate::descriptor::SafeDescriptor;

const KCMP_FILE: u32 = 0;

impl PartialEq for SafeDescriptor {
    fn eq(&self, other: &Self) -> bool {
        // If RawFd numbers match then we can return early without calling kcmp
        if self.descriptor == other.descriptor {
            return true;
        }

        // SAFETY:
        // safe because we only use the return value and libc says it's always successful
        let pid = unsafe { libc::getpid() };
        // SAFETY:
        // safe because we are passing everything by value and checking the return value
        let ret = unsafe {
            libc::syscall(
                libc::SYS_kcmp,
                pid,
                pid,
                KCMP_FILE,
                self.descriptor,
                other.descriptor,
            )
        };

        ret == 0
    }
}
