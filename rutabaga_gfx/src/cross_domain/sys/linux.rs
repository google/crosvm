// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::fs::File;
use std::io::Seek;
use std::io::SeekFrom;
use std::os::fd::AsFd;
use std::os::unix::io::AsRawFd;

use libc::O_ACCMODE;
use libc::O_WRONLY;
use nix::fcntl::fcntl;
use nix::fcntl::FcntlArg;
use nix::sys::eventfd::EfdFlags;
use nix::sys::eventfd::EventFd;
use nix::unistd::pipe;
use nix::unistd::read;
use nix::unistd::write;

use super::super::add_item;
use super::super::cross_domain_protocol::CrossDomainSendReceive;
use super::super::cross_domain_protocol::CROSS_DOMAIN_ID_TYPE_READ_PIPE;
use super::super::cross_domain_protocol::CROSS_DOMAIN_ID_TYPE_VIRTGPU_BLOB;
use super::super::cross_domain_protocol::CROSS_DOMAIN_ID_TYPE_WRITE_PIPE;
use super::super::cross_domain_protocol::CROSS_DOMAIN_MAX_IDENTIFIERS;
use super::super::CrossDomainContext;
use super::super::CrossDomainItem;
use super::super::CrossDomainJob;
use crate::rutabaga_os::AsRawDescriptor;
use crate::RutabagaError;
use crate::RutabagaResult;

// Determine type of OS-specific descriptor.  See `from_file` in wl.rs  for explantation on the
// current, Linux-based method.
pub fn descriptor_analysis(
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
            let flags = fcntl(descriptor.as_raw_descriptor(), FcntlArg::F_GETFL)?;
            *descriptor_type = match flags & O_ACCMODE {
                O_WRONLY => CROSS_DOMAIN_ID_TYPE_WRITE_PIPE,
                _ => return Err(RutabagaError::InvalidCrossDomainItemType),
            };

            Ok(())
        }
    }
}

impl CrossDomainContext {
    pub(crate) fn send(
        &self,
        cmd_send: &CrossDomainSendReceive,
        opaque_data: &[u8],
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

                let (raw_read_pipe, raw_write_pipe) = pipe()?;
                let read_pipe = File::from(raw_read_pipe);
                let write_pipe = File::from(raw_write_pipe);

                *descriptor = write_pipe.as_raw_descriptor();
                let read_pipe_id: u32 = add_item(
                    &self.item_state,
                    CrossDomainItem::WaylandReadPipe(read_pipe),
                );

                // For Wayland read pipes, the guest guesses which identifier the host will use to
                // avoid waiting for the host to generate one.  Validate guess here.  This works
                // because of the way Sommelier copy + paste works.  If the Sommelier sequence of
                // events changes, it's always possible to wait for the host
                // response.
                if read_pipe_id != *identifier {
                    return Err(RutabagaError::InvalidCrossDomainItemId);
                }

                // The write pipe needs to be dropped after the send_msg(..) call is complete, so
                // the read pipe can receive subsequent hang-up events.
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
                channel_signal(resample_evt)?;
            }
        } else {
            return Err(RutabagaError::InvalidCrossDomainState);
        }

        Ok(())
    }
}

pub type Sender = EventFd;
// TODO: Receiver should be EventFd as well, but there is no way to clone a nix EventFd.
pub type Receiver = File;

pub fn channel_signal(sender: &Sender) -> RutabagaResult<()> {
    sender.write(1)?;
    Ok(())
}

pub fn channel_wait(receiver: &Receiver) -> RutabagaResult<()> {
    read(receiver.as_raw_fd(), &mut 1u64.to_ne_bytes())?;
    Ok(())
}

pub fn read_volatile(file: &File, opaque_data: &mut [u8]) -> RutabagaResult<usize> {
    let bytes_read = read(file.as_raw_fd(), opaque_data)?;
    Ok(bytes_read)
}

pub fn write_volatile(file: &File, opaque_data: &[u8]) -> RutabagaResult<()> {
    write(file.as_fd(), opaque_data)?;
    Ok(())
}

pub fn channel() -> RutabagaResult<(Sender, Receiver)> {
    let sender = EventFd::from_flags(EfdFlags::empty())?;
    let receiver = sender.as_fd().try_clone_to_owned()?.into();
    Ok((sender, receiver))
}
