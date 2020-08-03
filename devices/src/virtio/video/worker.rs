// Copyright 2020 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Worker that runs in a virtio-video thread.

use std::collections::{BTreeMap, VecDeque};

use base::{error, EventFd, PollContext};
use vm_memory::GuestMemory;

use crate::virtio::queue::{DescriptorChain, Queue};
use crate::virtio::resource_bridge::ResourceRequestSocket;
use crate::virtio::video::command::{QueueType, VideoCmd};
use crate::virtio::video::device::{
    AsyncCmdResponse, AsyncCmdTag, Device, Token, VideoCmdResponseType, VideoEvtResponseType,
};
use crate::virtio::video::error::VideoError;
use crate::virtio::video::event::{self, EvtType, VideoEvt};
use crate::virtio::video::protocol;
use crate::virtio::video::response::{self, CmdResponse, Response};
use crate::virtio::video::{Error, Result};
use crate::virtio::{Interrupt, Reader, Writer};

pub struct Worker {
    pub interrupt: Interrupt,
    pub mem: GuestMemory,
    pub cmd_evt: EventFd,
    pub event_evt: EventFd,
    pub kill_evt: EventFd,
    pub resource_bridge: ResourceRequestSocket,
}

/// BTreeMap which stores descriptor chains in which asynchronous responses will be written.
type DescPool = BTreeMap<AsyncCmdTag, DescriptorChain>;
/// Pair of a descriptor chain and a response to be written.
type WritableResp = (DescriptorChain, response::CmdResponse);

/// Invalidates and removes all pending asynchronous commands in a given `DescPool` value
/// and returns a list of `WritableResp` to be sent to the guest.
fn cancel_pending_requests(target_stream_id: u32, desc_pool: &mut DescPool) -> Vec<WritableResp> {
    let old_desc_pool = std::mem::take(desc_pool);
    let mut resps = vec![];
    for (key, value) in old_desc_pool.into_iter() {
        match key {
            AsyncCmdTag::Queue { stream_id, .. } if stream_id == target_stream_id => {
                resps.push((
                    value,
                    CmdResponse::ResourceQueue {
                        timestamp: 0,
                        flags: protocol::VIRTIO_VIDEO_BUFFER_FLAG_ERR,
                        size: 0,
                    },
                ));
            }
            AsyncCmdTag::Drain { stream_id } | AsyncCmdTag::Clear { stream_id, .. }
                if stream_id == target_stream_id =>
            {
                // TODO(b/1518105): Use more appropriate error code if a new protocol supports one.
                resps.push((value, VideoError::InvalidOperation.into()));
            }
            AsyncCmdTag::Queue { .. } | AsyncCmdTag::Drain { .. } | AsyncCmdTag::Clear { .. } => {
                // Keep commands for other streams.
                desc_pool.insert(key, value);
            }
        }
    }
    resps
}

impl Worker {
    /// Writes responses into the command queue.
    fn write_responses(
        &self,
        cmd_queue: &mut Queue,
        responses: &mut VecDeque<WritableResp>,
    ) -> Result<()> {
        let mut needs_interrupt_commandq = false;
        // Write responses into command virtqueue.
        while let Some((desc, resp)) = responses.pop_front() {
            let desc_index = desc.index;
            let mut writer = Writer::new(&self.mem, desc).map_err(Error::InvalidDescriptorChain)?;
            if let Err(e) = resp.write(&mut writer) {
                error!("failed to write a command response for {:?}: {}", resp, e);
            }
            cmd_queue.add_used(&self.mem, desc_index, writer.bytes_written() as u32);
            needs_interrupt_commandq = true;
        }
        if needs_interrupt_commandq {
            self.interrupt.signal_used_queue(cmd_queue.vector);
        }
        Ok(())
    }

    /// Writes a `VideoEvt` into the event queue.
    fn write_event(&self, event_queue: &mut Queue, event: &mut event::VideoEvt) -> Result<()> {
        let desc = event_queue
            .peek(&self.mem)
            .ok_or_else(|| Error::DescriptorNotAvailable)?;
        event_queue.pop_peeked(&self.mem);

        let desc_index = desc.index;
        let mut writer = Writer::new(&self.mem, desc).map_err(Error::InvalidDescriptorChain)?;
        event
            .write(&mut writer)
            .map_err(|error| Error::WriteEventFailure {
                event: event.clone(),
                error,
            })?;
        event_queue.add_used(&self.mem, desc_index, writer.bytes_written() as u32);
        self.interrupt.signal_used_queue(event_queue.vector);
        Ok(())
    }

    /// Handles a `DescriptorChain` value sent via the command queue and returns a `VecDeque`
    /// of `WritableResp` to be sent to the guest.
    fn handle_command_desc<'a, T: Device>(
        &'a self,
        device: &mut T,
        poll_ctx: &PollContext<Token>,
        desc_pool: &mut DescPool,
        desc: DescriptorChain,
    ) -> Result<VecDeque<WritableResp>> {
        let mut resps: VecDeque<WritableResp> = Default::default();
        let mut reader =
            Reader::new(&self.mem, desc.clone()).map_err(Error::InvalidDescriptorChain)?;

        let cmd = VideoCmd::from_reader(&mut reader).map_err(Error::ReadFailure)?;

        // If a destruction command comes, cancel pending requests.
        match cmd {
            VideoCmd::ResourceDestroyAll { stream_id } | VideoCmd::StreamDestroy { stream_id } => {
                let rs = cancel_pending_requests(stream_id, desc_pool);
                resps.append(&mut Into::<VecDeque<_>>::into(rs));
            }
            _ => (),
        };

        // Process the command by the device.
        let resp = device.process_cmd(cmd, &poll_ctx, &self.resource_bridge);

        match resp {
            Ok(VideoCmdResponseType::Sync(r)) => {
                resps.push_back((desc.clone(), r));
            }
            Ok(VideoCmdResponseType::Async(tag)) => {
                // If the command expects an asynchronous response,
                // store `desc` to use it after the back-end device notifies the
                // completion.
                desc_pool.insert(tag, desc);
            }
            Err(e) => {
                error!("returning error response: {}", &e);
                resps.push_back((desc.clone(), e.into()));
            }
        }

        Ok(resps)
    }

    /// Handles each command in the command queue.
    fn handle_command_queue<'a, T: Device>(
        &'a self,
        cmd_queue: &mut Queue,
        device: &mut T,
        poll_ctx: &PollContext<Token>,
        desc_pool: &mut DescPool,
    ) -> Result<()> {
        let _ = self.cmd_evt.read();

        while let Some(desc) = cmd_queue.pop(&self.mem) {
            let mut resps = self.handle_command_desc(device, poll_ctx, desc_pool, desc)?;
            self.write_responses(cmd_queue, &mut resps)?;
        }
        Ok(())
    }

    /// Handles a `VideoEvtResponseType` value and returns a `VecDeque` of `WritableResp`
    /// to be sent to the guest.
    fn handle_event_resp<'a, T: Device>(
        &'a self,
        event_queue: &mut Queue,
        device: &mut T,
        desc_pool: &mut DescPool,
        resp: VideoEvtResponseType,
    ) -> Result<VecDeque<WritableResp>> {
        let mut responses: VecDeque<WritableResp> = Default::default();
        match resp {
            VideoEvtResponseType::AsyncCmd(async_response) => {
                let AsyncCmdResponse {
                    tag,
                    response: cmd_result,
                } = async_response;
                let desc = desc_pool
                    .remove(&tag)
                    .ok_or_else(|| Error::UnexpectedResponse(tag))?;

                // TODO(b/161774071): handle_event_fd() can provide these responses
                // so that we don't have to do an additional stage of processing here.
                // TODO(b/161782360): Check that `response` is not an error before
                // sending EOS in Drain, and cancelling pending requests in Clear.
                match tag {
                    AsyncCmdTag::Drain { stream_id } => {
                        // When `Drain` request is completed, returns an empty output resource
                        // with EOS flag first.
                        let resource_id = device
                            .take_resource_id_to_notify_eos(stream_id)
                            .ok_or_else(|| Error::NoEOSBuffer { stream_id })?;

                        let queue_desc = desc_pool
                            .remove(&AsyncCmdTag::Queue {
                                stream_id,
                                queue_type: QueueType::Output,
                                resource_id,
                            })
                            .ok_or_else(|| Error::InvalidEOSResource {
                                stream_id,
                                resource_id,
                            })?;

                        responses.push_back((
                            queue_desc,
                            CmdResponse::ResourceQueue {
                                timestamp: 0,
                                flags: protocol::VIRTIO_VIDEO_BUFFER_FLAG_EOS,
                                size: 0,
                            },
                        ));
                    }

                    AsyncCmdTag::Clear { stream_id, .. } => {
                        // When `Clear` request is completed, invalidate all pending requests.
                        let resps = cancel_pending_requests(stream_id, desc_pool);
                        responses.append(&mut Into::<VecDeque<_>>::into(resps));
                    }

                    _ => {
                        // No extra responses necessary.
                    }
                }

                let cmd_response = match cmd_result {
                    Ok(r) => r,
                    Err(e) => {
                        error!("returning async error response: {}", &e);
                        e.into()
                    }
                };
                responses.push_back((desc, cmd_response));
            }
            VideoEvtResponseType::Event(mut evt) => {
                self.write_event(event_queue, &mut evt)?;
            }
        };
        Ok(responses)
    }

    /// Handles an event notified via an event FD.
    fn handle_event_fd<'a, T: Device>(
        &'a self,
        cmd_queue: &mut Queue,
        event_queue: &mut Queue,
        device: &mut T,
        desc_pool: &mut DescPool,
        stream_id: u32,
    ) -> Result<()> {
        if let Some(event_responses) = device.process_event_fd(stream_id) {
            for r in event_responses {
                match self.handle_event_resp(event_queue, device, desc_pool, r) {
                    Ok(mut resps) => {
                        self.write_responses(cmd_queue, &mut resps)?;
                    }
                    Err(e) => {
                        // Ignore result of write_event for a fatal error.
                        let _ = self.write_event(
                            event_queue,
                            &mut VideoEvt {
                                typ: EvtType::Error,
                                stream_id,
                            },
                        );
                        return Err(e);
                    }
                }
            }
        }
        Ok(())
    }

    pub fn run<T: Device>(
        &mut self,
        mut cmd_queue: Queue,
        mut event_queue: Queue,
        mut device: T,
    ) -> Result<()> {
        let poll_ctx: PollContext<Token> = PollContext::build_with(&[
            (&self.cmd_evt, Token::CmdQueue),
            (&self.event_evt, Token::EventQueue),
            (&self.kill_evt, Token::Kill),
            (self.interrupt.get_resample_evt(), Token::InterruptResample),
        ])
        .map_err(Error::PollContextCreationFailed)?;

        // Stores descriptors in which responses for asynchronous commands will be written.
        let mut desc_pool: DescPool = Default::default();

        loop {
            let poll_events = poll_ctx.wait().map_err(Error::PollError)?;

            for poll_event in poll_events.iter_readable() {
                match poll_event.token() {
                    Token::CmdQueue => {
                        self.handle_command_queue(
                            &mut cmd_queue,
                            &mut device,
                            &poll_ctx,
                            &mut desc_pool,
                        )?;
                    }
                    Token::EventQueue => {
                        let _ = self.event_evt.read();
                    }
                    Token::EventFd { id } => {
                        self.handle_event_fd(
                            &mut cmd_queue,
                            &mut event_queue,
                            &mut device,
                            &mut desc_pool,
                            id,
                        )?;
                    }
                    Token::InterruptResample => {
                        self.interrupt.interrupt_resample();
                    }
                    Token::Kill => return Ok(()),
                }
            }
        }
    }
}
