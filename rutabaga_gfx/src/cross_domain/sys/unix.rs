// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::fs::File;
use std::io::IoSliceMut;
use std::io::Seek;
use std::io::SeekFrom;

use base::pipe;
use base::AsRawDescriptor;
use base::FileFlags;
use base::FromRawDescriptor;
use base::RawDescriptor;
use base::ScmSocket;
use data_model::VolatileSlice;

use super::super::cross_domain::add_item;
use super::super::cross_domain::CrossDomainContext;
use super::super::cross_domain::CrossDomainItem;
use super::super::cross_domain::CrossDomainJob;
use super::super::cross_domain::CrossDomainState;
use super::super::cross_domain_protocol::CrossDomainSendReceive;
use super::super::cross_domain_protocol::CROSS_DOMAIN_ID_TYPE_READ_PIPE;
use super::super::cross_domain_protocol::CROSS_DOMAIN_ID_TYPE_VIRTGPU_BLOB;
use super::super::cross_domain_protocol::CROSS_DOMAIN_ID_TYPE_WRITE_PIPE;
use super::super::cross_domain_protocol::CROSS_DOMAIN_MAX_IDENTIFIERS;
use crate::cross_domain::cross_domain_protocol::CrossDomainInit;
use crate::RutabagaError;
use crate::RutabagaResult;

// TODO(b:231309513): The alias can be moved to base crate for wider use.
pub(crate) type SystemStream = std::os::unix::net::UnixStream;

// Determine type of OS-specific descriptor.  See `from_file` in wl.rs  for explantation on the
// current, Linux-based method.
pub(crate) fn descriptor_analysis(
    descriptor: &mut File,
    descriptor_type: &mut u32,
    size: &mut u32,
) -> RutabagaResult<()> {
    match descriptor.seek(SeekFrom::End(0)) {
        Ok(seek_size) => {
            *descriptor_type = CROSS_DOMAIN_ID_TYPE_VIRTGPU_BLOB;
            *size = seek_size.try_into()?;
            Ok(())
        }
        _ => {
            *descriptor_type = match FileFlags::from_file(descriptor) {
                Ok(FileFlags::Write) => CROSS_DOMAIN_ID_TYPE_WRITE_PIPE,
                _ => return Err(RutabagaError::InvalidCrossDomainItemType),
            };
            Ok(())
        }
    }
}

impl CrossDomainState {
    fn send_msg(
        &self,
        opaque_data: &[VolatileSlice],
        descriptors: &[RawDescriptor],
    ) -> RutabagaResult<usize> {
        self.connection
            .as_ref()
            .ok_or(RutabagaError::InvalidCrossDomainChannel)
            .and_then(|conn| Ok(conn.send_with_fds(opaque_data, descriptors)?))
    }

    pub(crate) fn receive_msg(
        &self,
        opaque_data: &mut [u8],
        descriptors: &mut [RawDescriptor; CROSS_DOMAIN_MAX_IDENTIFIERS],
    ) -> RutabagaResult<(usize, Vec<File>)> {
        // If any errors happen, the socket will get dropped, preventing more reading.
        if let Some(connection) = &self.connection {
            let mut files: Vec<File> = Vec::new();
            let (len, file_count) =
                connection.recv_with_fds(IoSliceMut::new(opaque_data), descriptors)?;

            for descriptor in descriptors.iter_mut().take(file_count) {
                // Safe since the descriptors from recv_with_fds(..) are owned by us and valid.
                let file = unsafe { File::from_raw_descriptor(*descriptor) };
                files.push(file);
            }

            Ok((len, files))
        } else {
            Err(RutabagaError::InvalidCrossDomainChannel)
        }
    }
}

impl CrossDomainContext {
    pub(crate) fn get_connection(
        &mut self,
        cmd_init: &CrossDomainInit,
    ) -> RutabagaResult<Option<SystemStream>> {
        let channels = self
            .channels
            .take()
            .ok_or(RutabagaError::InvalidCrossDomainChannel)?;
        let base_channel = &channels
            .iter()
            .find(|channel| channel.channel_type == cmd_init.channel_type)
            .ok_or(RutabagaError::InvalidCrossDomainChannel)?
            .base_channel;
        Ok(Some(SystemStream::connect(base_channel)?))
    }

    pub(crate) fn send(
        &self,
        cmd_send: &CrossDomainSendReceive,
        opaque_data: &[VolatileSlice],
    ) -> RutabagaResult<()> {
        let mut descriptors = [0; CROSS_DOMAIN_MAX_IDENTIFIERS];

        let mut write_pipe_opt: Option<File> = None;
        let mut read_pipe_id_opt: Option<u32> = None;

        let num_identifiers = cmd_send.num_identifiers.try_into()?;

        if num_identifiers > CROSS_DOMAIN_MAX_IDENTIFIERS {
            return Err(RutabagaError::SpecViolation(
                "max cross domain identifiers exceeded",
            ));
        }

        let iter = cmd_send
            .identifiers
            .iter()
            .zip(cmd_send.identifier_types.iter())
            .zip(descriptors.iter_mut())
            .take(num_identifiers);

        for ((identifier, identifier_type), descriptor) in iter {
            if *identifier_type == CROSS_DOMAIN_ID_TYPE_VIRTGPU_BLOB {
                let context_resources = self.context_resources.lock().unwrap();

                let context_resource = context_resources
                    .get(identifier)
                    .ok_or(RutabagaError::InvalidResourceId)?;

                if let Some(ref handle) = context_resource.handle {
                    *descriptor = handle.os_handle.as_raw_descriptor();
                } else {
                    return Err(RutabagaError::InvalidRutabagaHandle);
                }
            } else if *identifier_type == CROSS_DOMAIN_ID_TYPE_READ_PIPE {
                // In practice, just 1 pipe pair per send is observed.  If we encounter
                // more, this can be changed later.
                if write_pipe_opt.is_some() {
                    return Err(RutabagaError::SpecViolation("expected just one pipe pair"));
                }

                let (read_pipe, write_pipe) = pipe(true)?;

                *descriptor = write_pipe.as_raw_descriptor();
                let read_pipe_id: u32 = add_item(
                    &self.item_state,
                    CrossDomainItem::WaylandReadPipe(read_pipe),
                );

                // For Wayland read pipes, the guest guesses which identifier the host will use to
                // avoid waiting for the host to generate one.  Validate guess here.  This works
                // because of the way Sommelier copy + paste works.  If the Sommelier sequence of events
                // changes, it's always possible to wait for the host response.
                if read_pipe_id != *identifier {
                    return Err(RutabagaError::InvalidCrossDomainItemId);
                }

                // The write pipe needs to be dropped after the send_msg(..) call is complete, so the read pipe
                // can receive subsequent hang-up events.
                write_pipe_opt = Some(write_pipe);
                read_pipe_id_opt = Some(read_pipe_id);
            } else {
                // Don't know how to handle anything else yet.
                return Err(RutabagaError::InvalidCrossDomainItemType);
            }
        }

        if let (Some(state), Some(resample_evt)) = (&self.state, &self.resample_evt) {
            state.send_msg(opaque_data, &descriptors[..num_identifiers])?;

            if let Some(read_pipe_id) = read_pipe_id_opt {
                state.add_job(CrossDomainJob::AddReadPipe(read_pipe_id));
                resample_evt.signal()?;
            }
        } else {
            return Err(RutabagaError::InvalidCrossDomainState);
        }

        Ok(())
    }
}
