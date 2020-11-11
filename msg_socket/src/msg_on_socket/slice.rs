// Copyright 2020 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use base::RawDescriptor;
use std::mem::{size_of, ManuallyDrop, MaybeUninit};
use std::ptr::drop_in_place;

use crate::{MsgOnSocket, MsgResult};

use super::{simple_read, simple_write};

/// Helper used by the types that read a slice of homegenously typed data.
///
/// # Safety
/// This function has the same safety requirements as `T::read_from_buffer`, with the additional
/// requirements that the `msgs` are only used on success of this function
pub unsafe fn slice_read_helper<T: MsgOnSocket>(
    buffer: &[u8],
    fds: &[RawDescriptor],
    msgs: &mut [MaybeUninit<T>],
) -> MsgResult<usize> {
    let mut offset = 0usize;
    let mut fd_offset = 0usize;

    // In case of an error, we need to keep track of how many elements got initialized.
    // In order to perform the necessary drops, the below loop is executed in a closure
    // to capture errors without returning.
    let mut last_index = 0;
    let res = (|| {
        for msg in &mut msgs[..] {
            let element_size = match T::fixed_size() {
                Some(s) => s,
                None => simple_read::<u64>(buffer, &mut offset)? as usize,
            };
            // Assuming the unsafe caller gave valid FDs, this call should be safe.
            let (m, fd_size) = T::read_from_buffer(&buffer[offset..], &fds[fd_offset..])?;
            *msg = MaybeUninit::new(m);
            offset += element_size;
            fd_offset += fd_size;
            last_index += 1;
        }
        Ok(())
    })();

    // Because `MaybeUninit` will not automatically call drops, we have to drop the
    // partially initialized array manually in the case of an error.
    if let Err(e) = res {
        for msg in &mut msgs[..last_index] {
            // The call to `as_mut_ptr()` turns the `MaybeUninit` element of the array
            // into a pointer, which can be used with `drop_in_place` to call the
            // destructor without moving the element, which is impossible. This is safe
            // because `last_index` prevents this loop from traversing into the
            // uninitialized parts of the array.
            drop_in_place(msg.as_mut_ptr());
        }
        return Err(e);
    }

    Ok(fd_offset)
}

/// Helper used by the types that write a slice of homegenously typed data.
pub fn slice_write_helper<T: MsgOnSocket>(
    msgs: &[T],
    buffer: &mut [u8],
    fds: &mut [RawDescriptor],
) -> MsgResult<usize> {
    let mut offset = 0usize;
    let mut fd_offset = 0usize;
    for msg in msgs {
        let element_size = match T::fixed_size() {
            Some(s) => s,
            None => {
                let element_size = msg.msg_size();
                simple_write(element_size as u64, buffer, &mut offset)?;
                element_size as usize
            }
        };
        let fd_size = msg.write_to_buffer(&mut buffer[offset..], &mut fds[fd_offset..])?;
        offset += element_size;
        fd_offset += fd_size;
    }

    Ok(fd_offset)
}

impl<T: MsgOnSocket> MsgOnSocket for Vec<T> {
    fn uses_descriptor() -> bool {
        T::uses_descriptor()
    }

    fn fixed_size() -> Option<usize> {
        None
    }

    fn msg_size(&self) -> usize {
        let vec_size = match T::fixed_size() {
            Some(s) => s * self.len(),
            None => self.iter().map(|i| i.msg_size() + size_of::<u64>()).sum(),
        };
        size_of::<u64>() + vec_size
    }

    fn descriptor_count(&self) -> usize {
        if T::uses_descriptor() {
            self.iter().map(|i| i.descriptor_count()).sum()
        } else {
            0
        }
    }

    unsafe fn read_from_buffer(buffer: &[u8], fds: &[RawDescriptor]) -> MsgResult<(Self, usize)> {
        let mut offset = 0;
        let len = simple_read::<u64>(buffer, &mut offset)? as usize;
        let mut msgs: Vec<MaybeUninit<T>> = Vec::with_capacity(len);
        msgs.set_len(len);
        let fd_count = slice_read_helper(&buffer[offset..], fds, &mut msgs)?;
        let mut msgs = ManuallyDrop::new(msgs);
        Ok((
            Vec::from_raw_parts(msgs.as_mut_ptr() as *mut T, msgs.len(), msgs.capacity()),
            fd_count,
        ))
    }

    fn write_to_buffer(&self, buffer: &mut [u8], fds: &mut [RawDescriptor]) -> MsgResult<usize> {
        let mut offset = 0;
        simple_write(self.len() as u64, buffer, &mut offset)?;
        slice_write_helper(self, &mut buffer[offset..], fds)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_write_1_fixed() {
        let vec = vec![1u32];
        let mut buffer = vec![0; vec.msg_size()];
        vec.write_to_buffer(&mut buffer, &mut []).unwrap();
        let read_vec = unsafe { <Vec<u32>>::read_from_buffer(&buffer, &[]) }
            .unwrap()
            .0;

        assert_eq!(vec, read_vec);
    }

    #[test]
    fn read_write_8_fixed() {
        let vec = vec![1u16, 1, 3, 5, 8, 13, 21, 34];
        let mut buffer = vec![0; vec.msg_size()];
        vec.write_to_buffer(&mut buffer, &mut []).unwrap();
        let read_vec = unsafe { <Vec<u16>>::read_from_buffer(&buffer, &[]) }
            .unwrap()
            .0;
        assert_eq!(vec, read_vec);
    }

    #[test]
    fn read_write_1() {
        let vec = vec![Some(1u64)];
        let mut buffer = vec![0; vec.msg_size()];
        println!("{:?}", vec.msg_size());
        vec.write_to_buffer(&mut buffer, &mut []).unwrap();
        let read_vec = unsafe { <Vec<_>>::read_from_buffer(&buffer, &[]) }
            .unwrap()
            .0;

        assert_eq!(vec, read_vec);
    }

    #[test]
    fn read_write_4() {
        let vec = vec![Some(12u16), Some(0), None, None];
        let mut buffer = vec![0; vec.msg_size()];
        vec.write_to_buffer(&mut buffer, &mut []).unwrap();
        let read_vec = unsafe { <Vec<_>>::read_from_buffer(&buffer, &[]) }
            .unwrap()
            .0;

        assert_eq!(vec, read_vec);
    }
}
