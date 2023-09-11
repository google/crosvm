// Copyright 2022 The Chromium OS Authors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Structs for Tube based endpoint. Listeners are not used with Tubes, since they are essentially
//! fancy socket pairs.

use std::cmp::min;
use std::fs::File;
use std::io::IoSlice;
use std::io::IoSliceMut;
use std::marker::PhantomData;
use std::path::Path;
use std::ptr::copy_nonoverlapping;

use base::AsRawDescriptor;
use base::FromRawDescriptor;
use base::RawDescriptor;
use base::Tube;
use serde::Deserialize;
use serde::Serialize;
use tube_transporter::packed_tube;

use crate::connection::Endpoint;
use crate::connection::Req;
use crate::message::SlaveReq;
use crate::take_single_file;
use crate::Error;
use crate::Result;

#[derive(Serialize, Deserialize)]
struct RawDescriptorContainer {
    #[serde(with = "base::with_raw_descriptor")]
    rd: RawDescriptor,
}

#[derive(Serialize, Deserialize)]
struct EndpointMessage {
    rds: Vec<RawDescriptorContainer>,
    data: Vec<u8>,
}

/// Tube endpoint for vhost-user connection.
pub struct TubeEndpoint<R: Req> {
    tube: Tube,
    _r: PhantomData<R>,
}

impl<R: Req> TubeEndpoint<R> {
    pub(crate) fn get_tube(&self) -> &Tube {
        &self.tube
    }
}

impl<R: Req> From<Tube> for TubeEndpoint<R> {
    fn from(tube: Tube) -> Self {
        Self {
            tube,
            _r: PhantomData,
        }
    }
}

impl<R: Req> Endpoint<R> for TubeEndpoint<R> {
    fn connect<P: AsRef<Path>>(_path: P) -> Result<Self> {
        unimplemented!("connections not supported on Tubes")
    }

    /// Sends bytes from scatter-gather vectors with optional attached file descriptors.
    ///
    /// # Return:
    /// * - number of bytes sent on success
    /// * - TubeError: tube related errors.
    fn send_iovec(&mut self, iovs: &[IoSlice], rds: Option<&[RawDescriptor]>) -> Result<usize> {
        // Gather the iovecs
        let total_bytes = iovs.iter().map(|iov| iov.len()).sum();
        let mut data = Vec::with_capacity(total_bytes);
        for iov in iovs {
            data.extend(iov.iter());
        }

        let mut msg = EndpointMessage {
            data,
            rds: Vec::with_capacity(rds.map_or(0, |rds| rds.len())),
        };
        if let Some(rds) = rds {
            for rd in rds {
                msg.rds.push(RawDescriptorContainer { rd: *rd });
            }
        }
        self.tube.send(&msg)?;
        Ok(total_bytes)
    }

    /// Reads bytes from the tube into the given scatter/gather vectors with optional attached
    /// file.
    ///
    /// The underlying communication channel is a Tube. Providing too little recv buffer space will
    /// cause data to get dropped (with an error). This is tricky to fix with Tube backing our
    /// transport layer, and as far as we can tell, is not exercised in practice.
    ///
    /// # Return:
    /// * - (number of bytes received, [received files]) on success
    /// * - RecvBufferTooSmall: Input bufs is too small for the received buffer.
    /// * - TubeError: tube related errors.
    fn recv_into_bufs(
        &mut self,
        bufs: &mut [IoSliceMut],
        _allow_rds: bool,
    ) -> Result<(usize, Option<Vec<File>>)> {
        // TODO(b/221882601): implement "allow_rds"

        let msg: EndpointMessage = self.tube.recv()?;

        let files = match msg.rds.len() {
            0 => None,
            // Safe because we own r.rd and it is guaranteed valid.
            _ => Some(
                msg.rds
                    .iter()
                    .map(|r| unsafe { File::from_raw_descriptor(r.rd) })
                    .collect::<Vec<File>>(),
            ),
        };

        let mut bytes_read = 0;
        for dest_iov in bufs.iter_mut() {
            if bytes_read >= msg.data.len() {
                // We've read all the available data into the iovecs.
                break;
            }

            let copy_count = min(dest_iov.len(), msg.data.len() - bytes_read);

            // Safe because:
            //      1) msg.data and dest_iov do not overlap.
            //      2) copy_count is bounded by dest_iov's length and msg.data.len() so we can't
            //         overrun.
            unsafe {
                copy_nonoverlapping(
                    msg.data.as_ptr().add(bytes_read),
                    dest_iov.as_mut_ptr(),
                    copy_count,
                )
            };
            bytes_read += copy_count;
        }

        if bytes_read != msg.data.len() {
            // User didn't supply enough iov space.
            return Err(Error::RecvBufferTooSmall {
                got: bytes_read,
                want: msg.data.len(),
            });
        }

        Ok((bytes_read, files))
    }

    fn create_slave_request_endpoint(
        &mut self,
        files: Option<Vec<File>>,
    ) -> Result<Box<dyn Endpoint<SlaveReq>>> {
        let file = take_single_file(files).ok_or(Error::InvalidMessage)?;
        // Safe because the file represents a packed tube.
        let tube = unsafe { packed_tube::unpack(file.into()).expect("unpacked Tube") };
        Ok(Box::new(TubeEndpoint::from(tube)))
    }
}

impl<R: Req> AsRawDescriptor for TubeEndpoint<R> {
    /// WARNING: this function does not return a waitable descriptor! Use base::ReadNotifier
    /// instead.
    fn as_raw_descriptor(&self) -> RawDescriptor {
        self.tube.as_raw_descriptor()
    }
}

#[cfg(test)]
mod tests {
    use std::io::IoSlice;
    use std::io::Read;
    use std::io::Seek;
    use std::io::SeekFrom;
    use std::io::Write;
    use std::mem;

    use base::AsRawDescriptor;
    use base::Tube;
    use tempfile::tempfile;

    use super::*;
    use crate::connection::EndpointExt;
    use crate::message::MasterReq;
    use crate::message::VhostUserMsgHeader;

    fn create_pair() -> (TubeEndpoint<MasterReq>, TubeEndpoint<MasterReq>) {
        let (master_tube, slave_tube) = Tube::pair().unwrap();
        (
            TubeEndpoint::<MasterReq>::from(master_tube),
            TubeEndpoint::<MasterReq>::from(slave_tube),
        )
    }

    #[test]
    fn send_data() {
        let (mut master, mut slave) = create_pair();

        let buf1 = vec![0x1, 0x2, 0x3, 0x4];
        let len = master.send_slice(IoSlice::new(&buf1[..]), None).unwrap();
        assert_eq!(len, 4);
        let (bytes, buf2, _) = slave.recv_into_buf(0x1000).unwrap();
        assert_eq!(bytes, 4);
        assert_eq!(&buf1[..], &buf2[..bytes]);
    }

    #[test]
    fn send_fd() {
        let (mut master, mut slave) = create_pair();

        let mut file = tempfile().unwrap();
        write!(file, "test").unwrap();

        // Normal case for sending/receiving file descriptors
        let buf1 = vec![0x1, 0x2, 0x3, 0x4];
        let len = master
            .send_slice(IoSlice::new(&buf1[..]), Some(&[file.as_raw_descriptor()]))
            .unwrap();
        assert_eq!(len, 4);

        let (bytes, buf2, files) = slave.recv_into_buf(4).unwrap();
        assert_eq!(bytes, 4);
        assert_eq!(&buf1[..], &buf2[..]);
        assert!(files.is_some());
        let files = files.unwrap();
        {
            assert_eq!(files.len(), 1);
            let mut file = &files[0];
            let mut content = String::new();
            file.seek(SeekFrom::Start(0)).unwrap();
            file.read_to_string(&mut content).unwrap();
            assert_eq!(content, "test");
        }

        // Following communication pattern should work:
        // Sending side: data, data with fds
        // Receiving side: data, data with fds
        let len = master.send_slice(IoSlice::new(&buf1[..]), None).unwrap();
        assert_eq!(len, 4);
        let len = master
            .send_slice(
                IoSlice::new(&buf1[..]),
                Some(&[
                    file.as_raw_descriptor(),
                    file.as_raw_descriptor(),
                    file.as_raw_descriptor(),
                ]),
            )
            .unwrap();
        assert_eq!(len, 4);

        let (bytes, buf2, files) = slave.recv_into_buf(0x4).unwrap();
        assert_eq!(bytes, 4);
        assert_eq!(&buf1[..], &buf2[..]);
        assert!(files.is_none());

        let (bytes, buf2, files) = slave.recv_into_buf(0x4).unwrap();
        assert_eq!(bytes, 4);
        assert_eq!(&buf1[..], &buf2[..]);
        assert!(files.is_some());
        let files = files.unwrap();
        {
            assert_eq!(files.len(), 3);
            let mut file = &files[1];
            let mut content = String::new();
            file.seek(SeekFrom::Start(0)).unwrap();
            file.read_to_string(&mut content).unwrap();
            assert_eq!(content, "test");
        }

        // If the target fd array is too small, extra file descriptors will get lost.
        //
        // Porting note: no, they won't. The FD array is sized to whatever the header says it
        // should be.
        let len = master
            .send_slice(
                IoSlice::new(&buf1[..]),
                Some(&[
                    file.as_raw_descriptor(),
                    file.as_raw_descriptor(),
                    file.as_raw_descriptor(),
                ]),
            )
            .unwrap();
        assert_eq!(len, 4);

        let (bytes, _, files) = slave.recv_into_buf(0x4).unwrap();
        assert_eq!(bytes, 4);
        assert!(files.is_some());
    }

    #[test]
    fn send_recv() {
        let (mut master, mut slave) = create_pair();

        let mut hdr1 =
            VhostUserMsgHeader::new(MasterReq::GET_FEATURES, 0, mem::size_of::<u64>() as u32);
        hdr1.set_need_reply(true);
        let features1 = 0x1u64;
        master.send_message(&hdr1, &features1, None).unwrap();

        let mut features2 = 0u64;
        let slice = unsafe {
            std::slice::from_raw_parts_mut(
                (&mut features2 as *mut u64) as *mut u8,
                mem::size_of::<u64>(),
            )
        };
        let (hdr2, bytes, files) = slave.recv_body_into_buf(slice).unwrap();
        assert_eq!(hdr1, hdr2);
        assert_eq!(bytes, 8);
        assert_eq!(features1, features2);
        assert!(files.is_none());

        master.send_header(&hdr1, None).unwrap();
        let (hdr2, files) = slave.recv_header().unwrap();
        assert_eq!(hdr1, hdr2);
        assert!(files.is_none());
    }
}
