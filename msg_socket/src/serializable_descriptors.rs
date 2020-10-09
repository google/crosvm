// Copyright 2020 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use crate::msg_on_socket::{MsgError, MsgOnSocket, MsgResult};
use base::{AsRawDescriptor, Event, FromRawDescriptor, RawDescriptor};
use std::fs::File;
use std::net::{TcpListener, TcpStream, UdpSocket};
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::net::{UnixDatagram, UnixListener, UnixStream};

macro_rules! rawdescriptor_impl {
    ($type:ident) => {
        impl MsgOnSocket for $type {
            fn uses_descriptor() -> bool {
                true
            }
            fn msg_size(&self) -> usize {
                0
            }
            fn descriptor_count(&self) -> usize {
                1
            }
            unsafe fn read_from_buffer(
                _buffer: &[u8],
                descriptors: &[RawDescriptor],
            ) -> MsgResult<(Self, usize)> {
                if descriptors.len() < 1 {
                    return Err(MsgError::ExpectDescriptor);
                }
                Ok(($type::from_raw_descriptor(descriptors[0]), 1))
            }
            fn write_to_buffer(
                &self,
                _buffer: &mut [u8],
                descriptors: &mut [RawDescriptor],
            ) -> MsgResult<usize> {
                if descriptors.is_empty() {
                    return Err(MsgError::WrongDescriptorBufferSize);
                }
                descriptors[0] = self.as_raw_descriptor();
                Ok(1)
            }
        }
    };
}

rawdescriptor_impl!(Event);
rawdescriptor_impl!(File);

macro_rules! rawfd_impl {
    ($type:ident) => {
        impl MsgOnSocket for $type {
            fn uses_descriptor() -> bool {
                true
            }
            fn msg_size(&self) -> usize {
                0
            }
            fn descriptor_count(&self) -> usize {
                1
            }
            unsafe fn read_from_buffer(_buffer: &[u8], fds: &[RawFd]) -> MsgResult<(Self, usize)> {
                if fds.len() < 1 {
                    return Err(MsgError::ExpectDescriptor);
                }
                Ok(($type::from_raw_fd(fds[0]), 1))
            }
            fn write_to_buffer(&self, _buffer: &mut [u8], fds: &mut [RawFd]) -> MsgResult<usize> {
                if fds.is_empty() {
                    return Err(MsgError::WrongDescriptorBufferSize);
                }
                fds[0] = self.as_raw_fd();
                Ok(1)
            }
        }
    };
}

rawfd_impl!(UnixStream);
rawfd_impl!(TcpStream);
rawfd_impl!(TcpListener);
rawfd_impl!(UdpSocket);
rawfd_impl!(UnixListener);
rawfd_impl!(UnixDatagram);
