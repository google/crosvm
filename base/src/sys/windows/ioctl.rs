// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Macros and wrapper functions for dealing with ioctls.

use std::mem::size_of;
use std::os::raw::c_int;
use std::os::raw::c_ulong;
use std::os::raw::*;
use std::ptr::null_mut;

use winapi::um::errhandlingapi::GetLastError;
use winapi::um::ioapiset::DeviceIoControl;
pub use winapi::um::winioctl::CTL_CODE;
pub use winapi::um::winioctl::FILE_ANY_ACCESS;
pub use winapi::um::winioctl::METHOD_BUFFERED;

use crate::descriptor::AsRawDescriptor;
use crate::errno_result;
use crate::Result;

/// Raw macro to declare the expression that calculates an ioctl number
#[macro_export]
macro_rules! device_io_control_expr {
    // TODO (colindr) b/144440409: right now GVM is our only DeviceIOControl
    //  target on windows, and it only uses METHOD_BUFFERED for the transfer
    //  type and FILE_ANY_ACCESS for the required access, so we're going to
    //  just use that for now. However, we may need to support more
    //  options later.
    ($dtype:expr, $code:expr) => {
        $crate::windows::CTL_CODE(
            $dtype,
            $code,
            $crate::windows::METHOD_BUFFERED,
            $crate::windows::FILE_ANY_ACCESS,
        ) as ::std::os::raw::c_ulong
    };
}

/// Raw macro to declare a function that returns an DeviceIOControl code.
#[macro_export]
macro_rules! ioctl_ioc_nr {
    ($name:ident, $dtype:expr, $code:expr) => {
        #[allow(non_snake_case)]
        pub fn $name() -> ::std::os::raw::c_ulong {
            $crate::device_io_control_expr!($dtype, $code)
        }
    };
    ($name:ident, $dtype:expr, $code:expr, $($v:ident),+) => {
        #[allow(non_snake_case)]
        pub fn $name($($v: ::std::os::raw::c_uint),+) -> ::std::os::raw::c_ulong {
            $crate::device_io_control_expr!($dtype, $code)
        }
    };
}

/// Declare an ioctl that transfers no data.
#[macro_export]
macro_rules! ioctl_io_nr {
    ($name:ident, $ty:expr, $nr:expr) => {
        $crate::ioctl_ioc_nr!($name, $ty, $nr);
    };
    ($name:ident, $ty:expr, $nr:expr, $($v:ident),+) => {
        $crate::ioctl_ioc_nr!($name, $ty, $nr, $($v),+);
    };
}

/// Declare an ioctl that reads data.
#[macro_export]
macro_rules! ioctl_ior_nr {
    ($name:ident, $ty:expr, $nr:expr, $size:ty) => {
        $crate::ioctl_ioc_nr!(
            $name,
            $ty,
            $nr
        );
    };
    ($name:ident, $ty:expr, $nr:expr, $size:ty, $($v:ident),+) => {
        $crate::ioctl_ioc_nr!(
            $name,
            $ty,
            $nr,
            $($v),+
        );
    };
}

/// Declare an ioctl that writes data.
#[macro_export]
macro_rules! ioctl_iow_nr {
    ($name:ident, $ty:expr, $nr:expr, $size:ty) => {
        $crate::ioctl_ioc_nr!(
            $name,
            $ty,
            $nr
        );
    };
    ($name:ident, $ty:expr, $nr:expr, $size:ty, $($v:ident),+) => {
        $crate::ioctl_ioc_nr!(
            $name,
            $ty,
            $nr,
            $($v),+
        );
    };
}

/// Declare an ioctl that reads and writes data.
#[macro_export]
macro_rules! ioctl_iowr_nr {
    ($name:ident, $ty:expr, $nr:expr, $size:ty) => {
        $crate::ioctl_ioc_nr!(
            $name,
            $ty,
            $nr
        );
    };
    ($name:ident, $ty:expr, $nr:expr, $size:ty, $($v:ident),+) => {
        $crate::ioctl_ioc_nr!(
            $name,
            $ty,
            $nr,
            $($v),+
        );
    };
}

pub type IoctlNr = c_ulong;

/// Run an ioctl with no arguments.
// (colindr) b/144457461 : This will probably not be used on windows.
// It's only used on linux for the ioctls that override the exit code to
// be the  return value of the ioctl. As far as I can tell, no DeviceIoControl
// will do this, they will always instead return values in the output
// buffer. So, as a result, we have no tests for this function, and
// we may want to remove it if we never use it on windows, but we can't
// remove it right now until we re-implement all the code that calls
// this funciton for windows.
/// # Safety
/// The caller is responsible for determining the safety of the particular ioctl.
/// This method should be safe as `DeviceIoControl` will handle error cases
/// and it does size checking.
pub unsafe fn ioctl<F: AsRawDescriptor>(descriptor: &F, nr: IoctlNr) -> c_int {
    let mut byte_ret: c_ulong = 0;
    let ret = DeviceIoControl(
        descriptor.as_raw_descriptor(),
        nr,
        null_mut(),
        0,
        null_mut(),
        0,
        &mut byte_ret,
        null_mut(),
    );

    if ret == 1 {
        return 0;
    }

    GetLastError() as i32
}

/// Run an ioctl with a single value argument.
/// # Safety
/// The caller is responsible for determining the safety of the particular ioctl.
/// This method should be safe as `DeviceIoControl` will handle error cases
/// and it does size checking.
pub unsafe fn ioctl_with_val(
    descriptor: &dyn AsRawDescriptor,
    nr: IoctlNr,
    mut arg: c_ulong,
) -> c_int {
    let mut byte_ret: c_ulong = 0;

    let ret = DeviceIoControl(
        descriptor.as_raw_descriptor(),
        nr,
        &mut arg as *mut c_ulong as *mut c_void,
        size_of::<c_ulong>() as u32,
        null_mut(),
        0,
        &mut byte_ret,
        null_mut(),
    );

    if ret == 1 {
        return 0;
    }

    GetLastError() as i32
}

/// Run an ioctl with an immutable reference.
/// # Safety
/// The caller is responsible for determining the safety of the particular ioctl.
/// Look at `ioctl_with_ptr` comments.
pub unsafe fn ioctl_with_ref<T>(descriptor: &dyn AsRawDescriptor, nr: IoctlNr, arg: &T) -> c_int {
    ioctl_with_ptr(descriptor, nr, arg)
}

/// Run an ioctl with a mutable reference.
/// # Safety
/// The caller is responsible for determining the safety of the particular ioctl.
/// Look at `ioctl_with_ptr` comments.
pub unsafe fn ioctl_with_mut_ref<T>(
    descriptor: &dyn AsRawDescriptor,
    nr: IoctlNr,
    arg: &mut T,
) -> c_int {
    ioctl_with_mut_ptr(descriptor, nr, arg)
}

/// Run an ioctl with a raw pointer, specifying the size of the buffer.
/// # Safety
/// This method should be safe as `DeviceIoControl` will handle error cases
/// and it does size checking. Also The caller should make sure `T` is valid.
pub unsafe fn ioctl_with_ptr_sized<T>(
    descriptor: &dyn AsRawDescriptor,
    nr: IoctlNr,
    arg: *const T,
    size: usize,
) -> c_int {
    let mut byte_ret: c_ulong = 0;

    // We are trusting the DeviceIoControl function to not write anything
    // to the input buffer. Just because it's a *const does not prevent
    // the unsafe call from writing to it.
    let ret = DeviceIoControl(
        descriptor.as_raw_descriptor(),
        nr,
        arg as *mut c_void,
        size as u32,
        // We pass a null_mut as the output buffer.  If you expect
        // an output, you should be calling the mut variant of this
        // function.
        null_mut(),
        0,
        &mut byte_ret,
        null_mut(),
    );

    if ret == 1 {
        return 0;
    }

    GetLastError() as i32
}

/// Run an ioctl with a raw pointer.
/// # Safety
/// The caller is responsible for determining the safety of the particular ioctl.
/// This method should be safe as `DeviceIoControl` will handle error cases
/// and it does size checking. Also The caller should make sure `T` is valid.
pub unsafe fn ioctl_with_ptr<T>(
    descriptor: &dyn AsRawDescriptor,
    nr: IoctlNr,
    arg: *const T,
) -> c_int {
    ioctl_with_ptr_sized(descriptor, nr, arg, size_of::<T>())
}

/// Run an ioctl with a mutable raw pointer.
/// # Safety
/// The caller is responsible for determining the safety of the particular ioctl.
/// This method should be safe as `DeviceIoControl` will handle error cases
/// and it does size checking. Also The caller should make sure `T` is valid.
pub unsafe fn ioctl_with_mut_ptr<T>(
    descriptor: &dyn AsRawDescriptor,
    nr: IoctlNr,
    arg: *mut T,
) -> c_int {
    let mut byte_ret: c_ulong = 0;

    let ret = DeviceIoControl(
        descriptor.as_raw_descriptor(),
        nr,
        arg as *mut c_void,
        size_of::<T>() as u32,
        arg as *mut c_void,
        size_of::<T>() as u32,
        &mut byte_ret,
        null_mut(),
    );

    if ret == 1 {
        return 0;
    }

    GetLastError() as i32
}

/// Run a DeviceIoControl, specifying all options, only available on windows
/// # Safety
/// This method should be safe as `DeviceIoControl` will handle error cases
/// for invalid paramters and takes input buffer and output buffer size
/// arguments. Also The caller should make sure `T` is valid.
pub unsafe fn device_io_control<F: AsRawDescriptor, T, T2>(
    descriptor: &F,
    nr: IoctlNr,
    input: *const T,
    inputsize: u32,
    output: *mut T2,
    outputsize: u32,
    byte_ret: &mut c_ulong,
) -> Result<()> {
    let ret = DeviceIoControl(
        descriptor.as_raw_descriptor(),
        nr,
        input as *mut c_void,
        inputsize,
        output as *mut c_void,
        outputsize,
        byte_ret,
        null_mut(),
    );

    if ret == 1 {
        return Ok(());
    }

    errno_result()
}

#[cfg(test)]
mod tests {

    use std::ffi::OsStr;
    use std::fs::File;
    use std::fs::OpenOptions;
    use std::io::prelude::*;
    use std::os::raw::*;
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::prelude::*;
    use std::ptr::null_mut;

    use tempfile::tempdir;
    use winapi::um::fileapi::CreateFileW;
    use winapi::um::fileapi::OPEN_EXISTING;
    use winapi::um::winbase::SECURITY_SQOS_PRESENT;
    use winapi::um::winioctl::FSCTL_GET_COMPRESSION;
    use winapi::um::winioctl::FSCTL_SET_COMPRESSION;
    use winapi::um::winnt::COMPRESSION_FORMAT_LZNT1;
    use winapi::um::winnt::COMPRESSION_FORMAT_NONE;
    use winapi::um::winnt::FILE_SHARE_READ;
    use winapi::um::winnt::FILE_SHARE_WRITE;
    use winapi::um::winnt::GENERIC_READ;
    use winapi::um::winnt::GENERIC_WRITE;

    // helper func, returns str as Vec<u16>
    fn to_u16s<S: AsRef<OsStr>>(s: S) -> std::io::Result<Vec<u16>> {
        Ok(s.as_ref().encode_wide().chain(Some(0)).collect())
    }

    #[cfg_attr(all(target_os = "windows", target_env = "gnu"), ignore)]
    #[test]
    fn ioct_get_and_set_compression() {
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("test.dat");
        let file_path = file_path.as_path();

        // compressed = empty short for compressed status to be read into
        let mut compressed: c_ushort = 0x0000;

        // open our random file and write "foo" in it
        let mut f = OpenOptions::new()
            .write(true)
            .create(true)
            .open(file_path)
            .unwrap();
        f.write_all(b"foo").expect("Failed to write bytes.");
        f.sync_all().expect("Failed to sync all.");

        // read the compression status
        // SAFETY: safe because return value is checked.
        let ecode = unsafe {
            super::super::ioctl::ioctl_with_mut_ref(&f, FSCTL_GET_COMPRESSION, &mut compressed)
        };

        // shouldn't error
        assert_eq!(ecode, 0);
        // should not be compressed by default (not sure if this will be the case on
        // all machines...)
        assert_eq!(compressed, COMPRESSION_FORMAT_NONE);

        // Now do a FSCTL_SET_COMPRESSED to set it to COMPRESSION_FORMAT_LZNT1.
        compressed = COMPRESSION_FORMAT_LZNT1;

        // NOTE: Theoretically I should be able to open this file like so:
        // let mut f = OpenOptions::new()
        //     .access_mode(GENERIC_WRITE|GENERIC_WRITE)
        //     .share_mode(FILE_SHARE_READ|FILE_SHARE_WRITE)
        //     .open("test.dat").unwrap();
        //
        //   However, that does not work, and I'm not sure why.  Here's where
        //   the underlying std code is doing a CreateFileW:
        //   https://github.com/rust-lang/rust/blob/master/src/libstd/sys/windows/fs.rs#L260
        //   For now I'm just going to leave this test as-is.
        //
        // SAFETY: safe because return value is checked.
        let f = unsafe {
            File::from_raw_handle(CreateFileW(
                to_u16s(file_path).unwrap().as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                null_mut(),
                OPEN_EXISTING,
                // I read there's some security concerns if you don't use this
                SECURITY_SQOS_PRESENT,
                null_mut(),
            ))
        };

        let ecode =
            // SAFETY: safe because return value is checked.
            unsafe { super::super::ioctl::ioctl_with_ref(&f, FSCTL_SET_COMPRESSION, &compressed) };

        assert_eq!(ecode, 0);
        // set compressed short back to 0 for reading purposes,
        // otherwise we can't be sure we're the FSCTL_GET_COMPRESSION
        // is writing anything to the compressed pointer.
        compressed = 0;

        // SAFETY: safe because return value is checked.
        let ecode = unsafe {
            super::super::ioctl::ioctl_with_mut_ref(&f, FSCTL_GET_COMPRESSION, &mut compressed)
        };

        // now should be compressed
        assert_eq!(ecode, 0);
        assert_eq!(compressed, COMPRESSION_FORMAT_LZNT1);

        drop(f);
        // clean up
        dir.close().expect("Failed to close the temp directory.");
    }

    #[cfg_attr(all(target_os = "windows", target_env = "gnu"), ignore)]
    #[test]
    fn ioctl_with_val() {
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("test.dat");
        let file_path = file_path.as_path();

        // compressed = empty short for compressed status to be read into
        // Now do a FSCTL_SET_COMPRESSED to set it to COMPRESSION_FORMAT_LZNT1.
        let mut compressed: c_ushort = COMPRESSION_FORMAT_LZNT1;

        // open our random file and write "foo" in it
        let mut f = OpenOptions::new()
            .write(true)
            .create(true)
            .open(file_path)
            .unwrap();
        f.write_all(b"foo").expect("Failed to write bytes.");
        f.sync_all().expect("Failed to sync all.");

        // NOTE: Theoretically I should be able to open this file like so:
        // let mut f = OpenOptions::new()
        //     .access_mode(GENERIC_WRITE|GENERIC_WRITE)
        //     .share_mode(FILE_SHARE_READ|FILE_SHARE_WRITE)
        //     .open("test.dat").unwrap();
        //
        //   However, that does not work, and I'm not sure why.  Here's where
        //   the underlying std code is doing a CreateFileW:
        //   https://github.com/rust-lang/rust/blob/master/src/libstd/sys/windows/fs.rs#L260
        //   For now I'm just going to leave this test as-is.
        //
        // SAFETY: safe because return value is checked.
        let f = unsafe {
            File::from_raw_handle(CreateFileW(
                to_u16s(file_path).unwrap().as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                null_mut(),
                OPEN_EXISTING,
                // I read there's some security concerns if you don't use this
                SECURITY_SQOS_PRESENT,
                null_mut(),
            ))
        };

        // now we call ioctl_with_val, which isn't particularly any more helpful than
        // ioctl_with_ref except for the cases where the input is only a word long
        // SAFETY: safe because return value is checked.
        let ecode = unsafe {
            super::super::ioctl::ioctl_with_val(&f, FSCTL_SET_COMPRESSION, compressed.into())
        };

        assert_eq!(ecode, 0);
        // set compressed short back to 0 for reading purposes,
        // otherwise we can't be sure we're the FSCTL_GET_COMPRESSION
        // is writing anything to the compressed pointer.
        compressed = 0;

        // SAFETY: safe because return value is checked.
        let ecode = unsafe {
            super::super::ioctl::ioctl_with_mut_ref(&f, FSCTL_GET_COMPRESSION, &mut compressed)
        };

        // now should be compressed
        assert_eq!(ecode, 0);
        assert_eq!(compressed, COMPRESSION_FORMAT_LZNT1);

        drop(f);
        // clean up
        dir.close().expect("Failed to close the temp directory.");
    }
}
