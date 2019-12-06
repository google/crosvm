// Copyright 2020 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Worker that runs in a virtio-video thread.

use std::collections::{BTreeMap, VecDeque};

use sys_util::{error, EventFd, GuestMemory, PollContext};

use crate::virtio::queue::{DescriptorChain, Queue};
use crate::virtio::resource_bridge::ResourceRequestSocket;
use crate::virtio::video::command::{QueueType, VideoCmd};
use crate::virtio::video::device::{
    AsyncCmdTag, Device, Token, VideoCmdResponseType, VideoEvtResponseType,
};
use crate::virtio::video::error::{VideoError, VideoResult};
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
type DescPool<'a> = BTreeMap<AsyncCmdTag, DescriptorChain<'a>>;
/// Pair of a descriptor chain and a response to be written.
type WritableResp<'a> = (DescriptorChain<'a>, VideoResult<response::CmdResponse>);

/// Invalidates all pending asynchronous commands in a given `DescPool` value and returns an updated
/// `DescPool` value and a list of `WritableResp` to be sent to the guest.
fn cancel_pending_requests<'a>(
    s_id: u32,
    desc_pool: DescPool<'a>,
) -> (DescPool<'a>, Vec<WritableResp<'a>>) {
    let mut new_desc_pool: DescPool<'a> = Default::default();
    let mut resps = vec![];

    for (key, value) in desc_pool.into_iter() {
        match key {
            AsyncCmdTag::Queue { stream_id, .. } if stream_id == s_id => {
                resps.push((
                    value,
                    Ok(CmdResponse::ResourceQueue {
                        timestamp: 0,
                        flags: protocol::VIRTIO_VIDEO_BUFFER_FLAG_ERR,
                        size: 0,
                    }),
                ));
            }
            AsyncCmdTag::Drain { stream_id } | AsyncCmdTag::Clear { stream_id, .. }
                if stream_id == s_id =>
            {
                // TODO(b/1518105): Use more appropriate error code if a new protocol supports one.
                resps.push((value, Err(VideoError::InvalidOperation)));
            }
            AsyncCmdTag::Queue { .. } | AsyncCmdTag::Drain { .. } | AsyncCmdTag::Clear { .. } => {
                // Keep commands for other streams.
                new_desc_pool.insert(key, value);
            }
        }
    }

    (new_desc_pool, resps)
}

impl Worker {
    /// Writes responses into the command queue.
    fn write_responses<'a>(
        &self,
        cmd_queue: &mut Queue,
        responses: &mut VecDeque<WritableResp>,
    ) -> Result<()> {
        let mut needs_interrupt_commandq = false;
        // Write responses into command virtqueue.
        while let Some((desc, resp)) = responses.pop_front() {
            let desc_index = desc.index;
            let mut writer = Writer::new(&self.mem, desc).map_err(Error::InvalidDescriptorChain)?;
            match resp {
                Ok(r) => {
                    if let Err(e) = r.write(&mut writer) {
                        error!("failed to write an OK response for {:?}: {}", r, e);
                    }
                }
                Err(err) => {
                    if let Err(e) = err.write(&mut writer) {
                        error!("failed to write an Error response for {:?}: {}", err, e);
                    }
                }
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

    /// Handles a `DescriptorChain` value sent via the command queue and returns an updated
    /// `DescPool` and `VecDeque` of `WritableResp` to be sent to the guest.
    fn handle_command_desc<'a, T: Device>(
        &'a self,
        device: &mut T,
        poll_ctx: &PollContext<Token>,
        mut desc_pool: DescPool<'a>,
        desc: DescriptorChain<'a>,
    ) -> Result<(DescPool<'a>, VecDeque<WritableResp<'a>>)> {
        let mut resps: VecDeque<WritableResp> = Default::default();
        let mut reader =
            Reader::new(&self.mem, desc.clone()).map_err(Error::InvalidDescriptorChain)?;

        let cmd = VideoCmd::from_reader(&mut reader).map_err(Error::ReadFailure)?;

        // If a destruction command comes, cancel pending requests.
        match cmd {
            VideoCmd::ResourceDestroyAll { stream_id } | VideoCmd::StreamDestroy { stream_id } => {
                let (next_desc_pool, rs) = cancel_pending_requests(stream_id, desc_pool);
                desc_pool = next_desc_pool;
                resps.append(&mut Into::<VecDeque<_>>::into(rs));
            }
            _ => (),
        };

        // Process the command by the device.
        let resp = device.process_cmd(cmd, &poll_ctx, &self.resource_bridge);

        match resp {
            Ok(VideoCmdResponseType::Sync(r)) => {
                resps.push_back((desc.clone(), Ok(r)));
            }
            Ok(VideoCmdResponseType::Async(tag)) => {
                // If the command expects an asynchronous response,
                // store `desc` to use it after the back-end device notifies the
                // completion.
                desc_pool.insert(tag, desc);
            }
            Err(e) => {
                resps.push_back((desc.clone(), Err(e)));
            }
        }

        Ok((desc_pool, resps))
    }

    /// Handles the command queue returns an updated `DescPool`.
    fn handle_command_queue<'a, T: Device>(
        &'a self,
        cmd_queue: &mut Queue,
        device: &mut T,
        poll_ctx: &PollContext<Token>,
        mut desc_pool: DescPool<'a>,
    ) -> Result<DescPool<'a>> {
        let _ = self.cmd_evt.read();

        while let Some(desc) = cmd_queue.pop(&self.mem) {
            let (next_desc_pool, mut resps) =
                self.handle_command_desc(device, poll_ctx, desc_pool, desc)?;
            desc_pool = next_desc_pool;
            self.write_responses(cmd_queue, &mut resps)?;
        }
        Ok(desc_pool)
    }

    /// Handles a `VideoEvtResponseType` value and returns an updated `DescPool` and `VecDeque` of
    /// `WritableResp` to be sent to the guest.
    fn handle_event_resp<'a, T: Device>(
        &'a self,
        event_queue: &mut Queue,
        device: &mut T,
        mut desc_pool: DescPool<'a>,
        resp: VideoEvtResponseType,
    ) -> Result<(DescPool<'a>, VecDeque<WritableResp>)> {
        let mut responses: VecDeque<WritableResp> = Default::default();
        match resp {
            VideoEvtResponseType::AsyncCmd {
                tag: AsyncCmdTag::Drain { stream_id },
                resp,
            } => {
                let tag = AsyncCmdTag::Drain { stream_id };
                let drain_desc = desc_pool
                    .remove(&tag)
                    .ok_or_else(|| Error::UnexpectedResponse(tag))?;

                // When `Drain` request is completed, returns an empty output resource
                // with EOS flag first.
                let resource_id = device
                    .take_resource_id_to_notify_eos(stream_id)
                    .ok_or_else(|| Error::NoEOSBuffer { stream_id })?;

                let q_desc = desc_pool
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
                    q_desc,
                    Ok(CmdResponse::ResourceQueue {
                        timestamp: 0,
                        flags: protocol::VIRTIO_VIDEO_BUFFER_FLAG_EOS,
                        size: 0,
                    }),
                ));

                // Then, responds the Drain request.
                responses.push_back((drain_desc, resp));
            }
            VideoEvtResponseType::AsyncCmd {
                tag:
                    AsyncCmdTag::Clear {
                        queue_type,
                        stream_id,
                    },
                resp,
            } => {
                let tag = AsyncCmdTag::Clear {
                    queue_type,
                    stream_id,
                };
                let desc = desc_pool
                    .remove(&tag)
                    .ok_or_else(|| Error::UnexpectedResponse(tag))?;

                // When `Clear` request is completed, invalidate all pending requests.
                let (next_desc_pool, resps) = cancel_pending_requests(stream_id, desc_pool);
                desc_pool = next_desc_pool;
                responses.append(&mut Into::<VecDeque<_>>::into(resps));

                // Then, responds the `Clear` request.
                responses.push_back((desc, resp));
            }
            VideoEvtResponseType::AsyncCmd { tag, resp } => {
                let desc = desc_pool
                    .remove(&tag)
                    .ok_or_else(|| Error::UnexpectedResponse(tag))?;
                responses.push_back((desc, resp));
            }
            VideoEvtResponseType::Event(mut evt) => {
                self.write_event(event_queue, &mut evt)?;
            }
        };
        Ok((desc_pool, responses))
    }

    /// Handles an event notified via an event FD and returns an updated `DescPool`.
    fn handle_event_fd<'a, T: Device>(
        &'a self,
        cmd_queue: &mut Queue,
        event_queue: &mut Queue,
        device: &mut T,
        desc_pool: DescPool<'a>,
        stream_id: u32,
    ) -> Result<DescPool<'a>> {
        let resp = device.process_event_fd(stream_id);
        match resp {
            Some(r) => match self.handle_event_resp(event_queue, device, desc_pool, r) {
                Ok((updated_desc_pool, mut resps)) => {
                    self.write_responses(cmd_queue, &mut resps)?;
                    Ok(updated_desc_pool)
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
                    Err(e)
                }
            },
            None => Ok(desc_pool),
        }
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
        let mut desc_pool: DescPool<'_> = Default::default();

        loop {
            let poll_events = poll_ctx.wait().map_err(Error::PollError)?;

            for poll_event in poll_events.iter_readable() {
                match poll_event.token() {
                    Token::CmdQueue => {
                        desc_pool = self.handle_command_queue(
                            &mut cmd_queue,
                            &mut device,
                            &poll_ctx,
                            desc_pool,
                        )?;
                    }
                    Token::EventQueue => {
                        let _ = self.event_evt.read();
                    }
                    Token::EventFd { id } => {
                        desc_pool = self.handle_event_fd(
                            &mut cmd_queue,
                            &mut event_queue,
                            &mut device,
                            desc_pool,
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
