// Copyright 2020 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use base::RawDescriptor;
use std::mem::size_of;

use crate::{MsgOnSocket, MsgResult};

use super::{simple_read, simple_write};

// Returns the size of one part of a tuple.
fn tuple_size_helper<T: MsgOnSocket>(v: &T) -> usize {
    T::fixed_size().unwrap_or_else(|| v.msg_size() + size_of::<u64>())
}

unsafe fn tuple_read_helper<T: MsgOnSocket>(
    buffer: &[u8],
    fds: &[RawDescriptor],
    buffer_index: &mut usize,
    fd_index: &mut usize,
) -> MsgResult<T> {
    let end = match T::fixed_size() {
        Some(_) => buffer.len(),
        None => {
            let len = simple_read::<u64>(buffer, buffer_index)? as usize;
            *buffer_index + len
        }
    };
    let (v, fd_read) = T::read_from_buffer(&buffer[*buffer_index..end], &fds[*fd_index..])?;
    *buffer_index += v.msg_size();
    *fd_index += fd_read;
    Ok(v)
}

fn tuple_write_helper<T: MsgOnSocket>(
    v: &T,
    buffer: &mut [u8],
    fds: &mut [RawDescriptor],
    buffer_index: &mut usize,
    fd_index: &mut usize,
) -> MsgResult<()> {
    let end = match T::fixed_size() {
        Some(_) => buffer.len(),
        None => {
            let len = v.msg_size();
            simple_write(len as u64, buffer, buffer_index)?;
            *buffer_index + len
        }
    };
    let fd_written = v.write_to_buffer(&mut buffer[*buffer_index..end], &mut fds[*fd_index..])?;
    *buffer_index += v.msg_size();
    *fd_index += fd_written;
    Ok(())
}

macro_rules! tuple_impls {
    () => {};
    ($t: ident) => {
        #[allow(unused_variables, non_snake_case)]
        impl<$t: MsgOnSocket> MsgOnSocket for ($t,) {
            fn uses_descriptor() -> bool {
                $t::uses_descriptor()
            }

            fn descriptor_count(&self) -> usize {
                self.0.descriptor_count()
            }

            fn fixed_size() -> Option<usize> {
                $t::fixed_size()
            }

            fn msg_size(&self) -> usize {
                self.0.msg_size()
            }

            unsafe fn read_from_buffer(buffer: &[u8], fds: &[RawDescriptor]) -> MsgResult<(Self, usize)> {
                let (t, s) = $t::read_from_buffer(buffer, fds)?;
                Ok(((t,), s))
            }

            fn write_to_buffer(
                &self,
                buffer: &mut [u8],
                fds: &mut [RawDescriptor],
            ) -> MsgResult<usize> {
                self.0.write_to_buffer(buffer, fds)
            }
        }
    };
    ($t: ident, $($ts:ident),*) => {
        #[allow(unused_variables, non_snake_case)]
        impl<$t: MsgOnSocket $(, $ts: MsgOnSocket)*> MsgOnSocket for ($t$(, $ts)*) {
            fn uses_descriptor() -> bool {
                $t::uses_descriptor() $(|| $ts::uses_descriptor())*
            }

            fn descriptor_count(&self) -> usize {
                if Self::uses_descriptor() {
                    return 0;
                }
                let ($t $(,$ts)*) = self;
                $t.descriptor_count() $(+ $ts.descriptor_count())*
            }

            fn fixed_size() -> Option<usize> {
                // Returns None if any element is not fixed size.
                Some($t::fixed_size()? $(+ $ts::fixed_size()?)*)
            }

            fn msg_size(&self) -> usize {
                if let Some(size) = Self::fixed_size() {
                    return size
                }

                let ($t $(,$ts)*) = self;
                tuple_size_helper($t) $(+ tuple_size_helper($ts))*
            }

            unsafe fn read_from_buffer(buffer: &[u8], fds: &[RawDescriptor]) -> MsgResult<(Self, usize)> {
                let mut buffer_index = 0;
                let mut fd_index = 0;
                Ok((
                        (
                            tuple_read_helper(buffer, fds, &mut buffer_index, &mut fd_index)?,
                            $({
                                // Dummy let used to trigger the correct number of iterations.
                                let $ts = ();
                                tuple_read_helper(buffer, fds, &mut buffer_index, &mut fd_index)?
                            },)*
                        ),
                        fd_index
                ))
            }

            fn write_to_buffer(
                &self,
                buffer: &mut [u8],
                fds: &mut [RawDescriptor],
            ) -> MsgResult<usize> {
                let mut buffer_index = 0;
                let mut fd_index = 0;
                let ($t $(,$ts)*) = self;
                tuple_write_helper($t, buffer, fds, &mut buffer_index, &mut fd_index)?;
                $(
                    tuple_write_helper($ts, buffer, fds, &mut buffer_index, &mut fd_index)?;
                )*
                Ok(fd_index)
            }
        }
        tuple_impls!{ $($ts),* }
    }
}

// Imlpement tuple for up to 8 elements.
tuple_impls! { A, B, C, D, E, F, G, H }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_write_1_fixed() {
        let tuple = (1,);
        let mut buffer = vec![0; tuple.msg_size()];
        tuple.write_to_buffer(&mut buffer, &mut []).unwrap();
        let read_tuple = unsafe { <(u32,)>::read_from_buffer(&buffer, &[]) }
            .unwrap()
            .0;

        assert_eq!(tuple, read_tuple);
    }

    #[test]
    fn read_write_8_fixed() {
        let tuple = (1u32, 2u8, 3u16, 4u64, 5u32, 6u16, 7u8, 8u8);
        let mut buffer = vec![0; tuple.msg_size()];
        tuple.write_to_buffer(&mut buffer, &mut []).unwrap();
        let read_tuple = unsafe { <_>::read_from_buffer(&buffer, &[]) }.unwrap().0;

        assert_eq!(tuple, read_tuple);
    }

    #[test]
    fn read_write_1() {
        let tuple = (Some(1u64),);
        let mut buffer = vec![0; tuple.msg_size()];
        tuple.write_to_buffer(&mut buffer, &mut []).unwrap();
        let read_tuple = unsafe { <_>::read_from_buffer(&buffer, &[]) }.unwrap().0;

        assert_eq!(tuple, read_tuple);
    }

    #[test]
    fn read_write_4() {
        let tuple = (Some(12u16), Some(false), None::<u8>, None::<u64>);
        let mut buffer = vec![0; tuple.msg_size()];
        println!("{:?}", tuple.msg_size());
        tuple.write_to_buffer(&mut buffer, &mut []).unwrap();
        let read_tuple = unsafe { <_>::read_from_buffer(&buffer, &[]) }.unwrap().0;

        assert_eq!(tuple, read_tuple);
    }
}
