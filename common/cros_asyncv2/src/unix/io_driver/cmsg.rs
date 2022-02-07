// Copyright 2021 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::{
    alloc::Layout,
    cmp::min,
    convert::TryFrom,
    io,
    mem::{align_of, size_of},
    os::unix::io::RawFd,
};

use anyhow::anyhow;
use sys_util::LayoutAllocation;

// Allocates a buffer to hold a `libc::cmsghdr` with `cap` bytes of data.
//
// Returns the `LayoutAllocation` for the buffer as well as the size of the allocation, which is
// guaranteed to be at least `size_of::<libc::cmsghdr>() + cap` bytes.
pub fn allocate_cmsg_buffer(cap: u32) -> anyhow::Result<(LayoutAllocation, usize)> {
    // Not sure why this is unsafe.
    let cmsg_cap = usize::try_from(unsafe { libc::CMSG_SPACE(cap) })
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    let alloc = Layout::from_size_align(cmsg_cap, align_of::<libc::cmsghdr>())
        .map(LayoutAllocation::zeroed)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;

    Ok((alloc, cmsg_cap))
}

// Adds a control message with the file descriptors from `fds` to `msg`.
// Note: this doesn't append but expects no cmsg already set and puts `fds` as a
// single `cmsg` inside passed `msg`
//
// Returns the `LayoutAllocation` backing the control message.
pub fn add_fds_to_message(
    msg: &mut libc::msghdr,
    fds: &[RawFd],
) -> anyhow::Result<LayoutAllocation> {
    let fd_len = fds
        .len()
        .checked_mul(size_of::<RawFd>())
        .and_then(|l| u32::try_from(l).ok())
        .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidInput))?;

    let (cmsg_buffer, cmsg_cap) = allocate_cmsg_buffer(fd_len)?;

    if !msg.msg_control.is_null() {
        anyhow::bail!("msg already contains cmsg");
    }

    msg.msg_control = cmsg_buffer.as_ptr();
    msg.msg_controllen = cmsg_cap;

    unsafe {
        // Safety:
        // * CMSG_FIRSTHDR will either return a null pointer or a pointer to `msg.msg_control`.
        // * `msg.msg_control` is properly aligned because `cmsg_buffer` is properly aligned.
        // * The buffer is zeroed, which is a valid bit-pattern for `libc::cmsghdr`.
        // * The reference does not escape this function.
        let cmsg = libc::CMSG_FIRSTHDR(msg).as_mut().unwrap();
        cmsg.cmsg_len = libc::CMSG_LEN(fd_len) as libc::size_t;
        cmsg.cmsg_level = libc::SOL_SOCKET;
        cmsg.cmsg_type = libc::SCM_RIGHTS;

        // Safety: `libc::CMSG_DATA(cmsg)` and `fds` are valid for `fd_len` bytes of memory.
        libc::memcpy(
            libc::CMSG_DATA(cmsg).cast(),
            fds.as_ptr().cast(),
            fd_len as usize,
        );
    }

    Ok(cmsg_buffer)
}

// Copies file descriptors from the control message in `msg` into `fds`.
//
// Returns the number of file descriptors that were copied from `msg`.
pub fn take_fds_from_message(msg: &libc::msghdr, fds: &mut [RawFd]) -> anyhow::Result<usize> {
    let cap = fds
        .len()
        .checked_mul(size_of::<RawFd>())
        .ok_or_else(|| anyhow!(io::Error::from(io::ErrorKind::InvalidInput)))?;

    let mut rem = cap;
    let mut fd_pos = 0;
    unsafe {
        let mut cmsg = libc::CMSG_FIRSTHDR(msg);

        // Safety:
        // * CMSG_FIRSTHDR will either return a null pointer or a pointer to `msg.msg_control`.
        // * `msg.msg_control` is properly aligned because it was allocated by `allocate_cmsg_buffer`.
        // * The buffer was zero-initialized, which is a valid bit-pattern for `libc::cmsghdr`.
        // * The reference does not escape this function.
        while let Some(current) = cmsg.as_ref() {
            if current.cmsg_level != libc::SOL_SOCKET || current.cmsg_type != libc::SCM_RIGHTS {
                cmsg = libc::CMSG_NXTHDR(msg, cmsg);
                continue;
            }

            let data_len = min(current.cmsg_len - libc::CMSG_LEN(0) as usize, rem);

            // Safety: `fds` and `libc::CMSG_DATA(cmsg)` are valid for `data_len` bytes of memory.
            libc::memcpy(
                fds[fd_pos..].as_mut_ptr().cast(),
                libc::CMSG_DATA(cmsg).cast(),
                data_len,
            );
            rem -= data_len;
            fd_pos += data_len / size_of::<RawFd>();
            if rem == 0 {
                break;
            }

            cmsg = libc::CMSG_NXTHDR(msg, cmsg);
        }
    }

    Ok((cap - rem) / size_of::<RawFd>())
}

#[cfg(test)]
mod tests {
    use std::ptr;

    use super::*;

    #[test]
    #[cfg(not(target_arch = "arm"))]
    fn test_add_fds_to_message() {
        let buf = [0xEAu8, 0xDD, 0xAA, 0xCC];
        let mut iov = libc::iovec {
            iov_base: buf.as_ptr() as *const libc::c_void as *mut libc::c_void,
            iov_len: buf.len() as libc::size_t,
        };

        let fds = [0xDE, 0xAD, 0xBE, 0xEF];
        let mut msg = libc::msghdr {
            msg_name: ptr::null_mut(),
            msg_namelen: 0,
            msg_iov: &mut iov,
            msg_iovlen: 1,
            msg_flags: 0,
            msg_control: ptr::null_mut(),
            msg_controllen: 0,
        };

        let cmsg_buffer = add_fds_to_message(&mut msg, &fds[..]).unwrap();
        let expected_cmsg = [
            32u8, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0xDE, 0, 0, 0, 0xAD, 0, 0, 0, 0xBE,
            0, 0, 0, 0xEF, 0, 0, 0,
        ];
        assert_eq!(unsafe { cmsg_buffer.as_slice::<u8>(9999) }, &expected_cmsg);
        assert_eq!(msg.msg_controllen, unsafe {
            cmsg_buffer.as_slice::<u8>(9999).len()
        });
        assert_eq!(msg.msg_control, cmsg_buffer.as_ptr());

        let mut extracted_fds = [0x0i32; 4];

        assert_eq!(
            4,
            take_fds_from_message(&msg, &mut extracted_fds[..]).unwrap()
        );

        assert_eq!(extracted_fds, fds);
    }

    #[test]
    #[cfg(not(target_arch = "arm"))]
    fn test_take_fds_from_message() {
        let buf = [0xEAu8, 0xDD, 0xAA, 0xCC];
        let mut iov = libc::iovec {
            iov_base: buf.as_ptr() as *const libc::c_void as *mut libc::c_void,
            iov_len: buf.len() as libc::size_t,
        };

        let mut cmsg = [
            32u8, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0xDE, 0, 0, 0, 0xAD, 0, 0, 0, 0xBE,
            0, 0, 0, 0xEF, 0, 0, 0, 32u8, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0xDE, 0, 0,
            0, 0xAD, 0, 0, 0, 0xBE, 0, 0, 0, 0xEF, 0, 0, 0,
        ];

        let msg = libc::msghdr {
            msg_name: ptr::null_mut(),
            msg_namelen: 0,
            msg_iov: &mut iov,
            msg_iovlen: 1,
            msg_flags: 0,
            msg_control: cmsg.as_mut_ptr() as *mut libc::c_void,
            msg_controllen: cmsg.len(),
        };

        let mut extracted_fds = [0x0i32; 9];
        assert_eq!(take_fds_from_message(&msg, &mut extracted_fds).unwrap(), 8);
        assert_eq!(
            extracted_fds,
            [0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF, 0x00]
        );
    }
}
