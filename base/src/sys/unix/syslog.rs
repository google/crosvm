// Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

pub use super::{target_os::syslog::PlatformSyslog, RawDescriptor};

#[cfg(test)]
mod tests {
    use crate::syslog::*;

    use libc::{shm_open, shm_unlink, O_CREAT, O_EXCL, O_RDWR};

    use std::{
        ffi::CStr,
        fs::File,
        io::{Read, Seek, SeekFrom},
        os::unix::io::FromRawFd,
    };

    #[test]
    fn fds() {
        init().unwrap();
        let mut fds = Vec::new();
        push_descriptors(&mut fds);
        assert!(!fds.is_empty());
        for fd in fds {
            assert!(fd >= 0);
        }
    }

    #[test]
    fn syslog_file() {
        init().unwrap();
        let shm_name = CStr::from_bytes_with_nul(b"/crosvm_shm\0").unwrap();
        let mut file = unsafe {
            shm_unlink(shm_name.as_ptr());
            let fd = shm_open(shm_name.as_ptr(), O_RDWR | O_CREAT | O_EXCL, 0o666);
            assert!(fd >= 0, "error creating shared memory;");
            shm_unlink(shm_name.as_ptr());
            File::from_raw_fd(fd)
        };

        let syslog_file = file.try_clone().expect("error cloning shared memory file");
        echo_file(Some(syslog_file));

        const TEST_STR: &str = "hello shared memory file";
        log(
            Priority::Error,
            Facility::User,
            Some((file!(), line!())),
            &format_args!("{}", TEST_STR),
        );

        file.seek(SeekFrom::Start(0))
            .expect("error seeking shared memory file");
        let mut buf = String::new();
        file.read_to_string(&mut buf)
            .expect("error reading shared memory file");
        assert!(buf.contains(TEST_STR));
    }
}
