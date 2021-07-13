// Copyright 2021 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::ops::{Deref, DerefMut};

use data_model::IoBufMut;

/// A trait for describing regions of memory to be used for IO.
///
/// # Safety
///
/// Types that implement this trait _must_ guarantee that the memory regions described by
/// `as_iobufs()` are valid for the lifetime of the borrow.
pub unsafe trait AsIoBufs {
    /// Returns a slice describing regions of memory on which to perform some IO. The returned
    /// memory region descriptions may be passed on to the OS kernel so implmentations must
    /// guarantee that the memory regions are valid for the lifetime of the borrow.
    fn as_iobufs(&mut self) -> &[IoBufMut];
}

/// An owned buffer for IO.
///
/// This type will be most commonly used to wrap a `Vec<u8>`.
///
/// # Examples
///
/// ```
/// # async fn do_it() -> anyhow::Result<()> {
///     use cros_async::{Executor, File, OwnedIoBuf};
///     use std::{convert::TryFrom, fs::OpenOptions};
///
///     let urandom = File::open("/dev/urandom")?;
///     let buf = OwnedIoBuf::new(vec![0; 256]);
///
///     let (res, mut buf) = urandom.read_iobuf(buf, None).await;
///     let count = res?;
///     buf.truncate(count);
///
///     let null = OpenOptions::new()
///         .write(true)
///         .open("/dev/null")
///         .map_err(From::from)
///         .and_then(File::try_from)?;
///     while buf.len() > 0 {
///         let (res, data) = null.write_iobuf(buf, None).await;
///         let bytes_written = res?;
///         buf = data;
///         buf.advance(bytes_written);
///     }
/// #     Ok(())
/// # }
/// # cros_async::Executor::new().run_until(do_it()).unwrap().unwrap();
/// ```
pub struct OwnedIoBuf {
    buf: Box<[u8]>,
    // This IoBufMut has a static lifetime because it points to the data owned by `buf` so the
    // pointer is always valid for the lifetime of this struct.
    iobuf: [IoBufMut<'static>; 1],
}

impl OwnedIoBuf {
    /// Create a new owned IO buffer.
    pub fn new<B: Into<Box<[u8]>>>(buf: B) -> OwnedIoBuf {
        let mut buf = buf.into();
        let iobuf = unsafe { IoBufMut::from_raw_parts(buf.as_mut_ptr(), buf.len()) };
        OwnedIoBuf {
            buf,
            iobuf: [iobuf],
        }
    }

    /// Returns the length of the IO buffer.
    pub fn len(&self) -> usize {
        self.iobuf[0].len()
    }

    /// Returns true if the length of the buffer is 0.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Advances the beginning of the buffer by `count` bytes.
    ///
    /// Panics if `count > self.len()`.
    pub fn advance(&mut self, count: usize) {
        self.iobuf[0].advance(count)
    }

    /// Change the size of the buffer used for IO.
    ///
    /// Has no effect if `len > self.len()`.
    pub fn truncate(&mut self, len: usize) {
        self.iobuf[0].truncate(len)
    }

    /// Reset the buffer to its full length.
    pub fn reset(&mut self) {
        self.iobuf[0] = unsafe { IoBufMut::from_raw_parts(self.buf.as_mut_ptr(), self.buf.len()) };
    }

    /// Convert this `OwnedIoBuf` back into the inner type.
    pub fn into_inner<C: From<Box<[u8]>>>(self) -> C {
        self.buf.into()
    }
}

impl Deref for OwnedIoBuf {
    type Target = [u8];
    fn deref(&self) -> &Self::Target {
        &self.buf
    }
}

impl DerefMut for OwnedIoBuf {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.buf
    }
}

// Safe because the pointer and length in the returned `&[IoBufMut]` are valid for the lifetime of
// the OwnedIoBuf.
unsafe impl AsIoBufs for OwnedIoBuf {
    fn as_iobufs(&mut self) -> &[IoBufMut] {
        &self.iobuf
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn len() {
        let buf = OwnedIoBuf::new(vec![0xcc; 64]);

        assert_eq!(buf.len(), 64);
    }

    #[test]
    fn advance() {
        let mut buf = OwnedIoBuf::new(vec![0xcc; 64]);

        buf.advance(17);
        assert_eq!(buf.len(), 47);
        assert_eq!(buf.iobuf[0].as_ptr(), unsafe { buf.buf.as_ptr().add(17) });

        buf.advance(9);
        assert_eq!(buf.len(), 38);
        assert_eq!(buf.iobuf[0].as_ptr(), unsafe { buf.buf.as_ptr().add(26) });

        buf.advance(38);
        assert_eq!(buf.len(), 0);
        assert_eq!(buf.iobuf[0].as_ptr(), unsafe { buf.buf.as_ptr().add(64) });
    }

    #[test]
    fn truncate() {
        let mut buf = OwnedIoBuf::new(vec![0xcc; 64]);

        buf.truncate(99);
        assert_eq!(buf.len(), 64);

        buf.truncate(64);
        assert_eq!(buf.len(), 64);

        buf.truncate(22);
        assert_eq!(buf.len(), 22);

        buf.truncate(0);
        assert_eq!(buf.len(), 0);
    }

    #[test]
    fn reset() {
        let mut buf = OwnedIoBuf::new(vec![0xcc; 64]);

        buf.truncate(22);
        assert_eq!(buf.len(), 22);
        assert_eq!(buf.iobuf[0].as_ptr(), buf.buf.as_ptr());

        buf.advance(17);
        assert_eq!(buf.len(), 5);
        assert_eq!(buf.iobuf[0].as_ptr(), unsafe { buf.buf.as_ptr().add(17) });

        buf.reset();
        assert_eq!(buf.len(), 64);
        assert_eq!(buf.iobuf[0].as_ptr(), buf.buf.as_ptr());
    }
}
