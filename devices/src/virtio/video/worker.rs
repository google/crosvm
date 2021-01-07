// Copyright 2020 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Worker that runs in a virtio-video thread.

use std::collections::VecDeque;

use base::{error, info, Event, Tube, WaitContext};
use vm_memory::GuestMemory;

use crate::virtio::queue::{DescriptorChain, Queue};
use crate::virtio::video::async_cmd_desc_map::AsyncCmdDescMap;
use crate::virtio::video::command::{QueueType, VideoCmd};
use crate::virtio::video::device::{
    AsyncCmdResponse, AsyncCmdTag, Device, Token, VideoCmdResponseType, VideoEvtResponseType,
};
use crate::virtio::video::event::{self, EvtType, VideoEvt};
use crate::virtio::video::response::{self, Response};
use crate::virtio::video::{Error, Result};
use crate::virtio::{Interrupt, Reader, SignalableInterrupt, Writer};

pub struct Worker {
    pub interrupt: Interrupt,
    pub mem: GuestMemory,
    pub cmd_evt: Event,
    pub event_evt: Event,
    pub kill_evt: Event,
    pub resource_bridge: Tube,
}

/// Pair of a descriptor chain and a response to be written.
type WritableResp = (DescriptorChain, response::CmdResponse);

impl Worker {
    /// Writes responses into the command queue.
    fn write_responses(
        &self,
        cmd_queue: &mut Queue,
        responses: &mut VecDeque<WritableResp>,
    ) -> Result<()> {
        if responses.is_empty() {
            return Ok(());
        }
        while let Some((desc, response)) = responses.pop_front() {
            let desc_index = desc.index;
            let mut writer =
                Writer::new(self.mem.clone(), desc).map_err(Error::InvalidDescriptorChain)?;
            if let Err(e) = response.write(&mut writer) {
                error!(
                    "failed to write a command response for {:?}: {}",
                    response, e
                );
            }
            cmd_queue.add_used(&self.mem, desc_index, writer.bytes_written() as u32);
        }
        self.interrupt.signal_used_queue(cmd_queue.vector);
        Ok(())
    }

    /// Writes a `VideoEvt` into the event queue.
    fn write_event(&self, event_queue: &mut Queue, event: event::VideoEvt) -> Result<()> {
        let desc = event_queue
            .peek(&self.mem)
            .ok_or(Error::DescriptorNotAvailable)?;
        event_queue.pop_peeked(&self.mem);

        let desc_index = desc.index;
        let mut writer =
            Writer::new(self.mem.clone(), desc).map_err(Error::InvalidDescriptorChain)?;
        event
            .write(&mut writer)
            .map_err(|error| Error::WriteEventFailure { event, error })?;
        event_queue.add_used(&self.mem, desc_index, writer.bytes_written() as u32);
        self.interrupt.signal_used_queue(event_queue.vector);
        Ok(())
    }

    fn write_event_responses(
        &self,
        event_responses: Vec<VideoEvtResponseType>,
        cmd_queue: &mut Queue,
        event_queue: &mut Queue,
        desc_map: &mut AsyncCmdDescMap,
        stream_id: u32,
    ) -> Result<()> {
        let mut responses: VecDeque<WritableResp> = Default::default();
        for event_response in event_responses {
            match event_response {
                VideoEvtResponseType::AsyncCmd(async_response) => {
                    let AsyncCmdResponse {
                        tag,
                        response: cmd_result,
                    } = async_response;
                    match desc_map.remove(&tag) {
                        Some(desc) => {
                            let cmd_response = match cmd_result {
                                Ok(r) => r,
                                Err(e) => {
                                    error!("returning async error response: {}", &e);
                                    e.into()
                                }
                            };
                            responses.push_back((desc, cmd_response))
                        }
                        None => match tag {
                            // TODO(b/153406792): Drain is cancelled by clearing either of the
                            // stream's queues. To work around a limitation in the VDA api, the
                            // output queue is cleared synchronously without going through VDA.
                            // Because of this, the cancellation response from VDA for the
                            // input queue might fail to find the drain's AsyncCmdTag.
                            AsyncCmdTag::Drain { stream_id: _ } => {
                                info!("ignoring unknown drain response");
                            }
                            _ => {
                                error!("dropping response for an untracked command: {:?}", tag);
                            }
                        },
                    }
                }
                VideoEvtResponseType::Event(evt) => {
                    self.write_event(event_queue, evt)?;
                }
            }
        }

        if let Err(e) = self.write_responses(cmd_queue, &mut responses) {
            error!("Failed to write event responses: {:?}", e);
            // Ignore result of write_event for a fatal error.
            let _ = self.write_event(
                event_queue,
                VideoEvt {
                    typ: EvtType::Error,
                    stream_id,
                },
            );
            return Err(e);
        }

        Ok(())
    }

    /// Handles a `DescriptorChain` value sent via the command queue and returns a `VecDeque`
    /// of `WritableResp` to be sent to the guest.
    fn handle_command_desc<T: Device>(
        &self,
        cmd_queue: &mut Queue,
        event_queue: &mut Queue,
        device: &mut T,
        wait_ctx: &WaitContext<Token>,
        desc_map: &mut AsyncCmdDescMap,
        desc: DescriptorChain,
    ) -> Result<VecDeque<WritableResp>> {
        let mut responses: VecDeque<WritableResp> = Default::default();
        let mut reader =
            Reader::new(self.mem.clone(), desc.clone()).map_err(Error::InvalidDescriptorChain)?;

        let cmd = VideoCmd::from_reader(&mut reader).map_err(Error::ReadFailure)?;

        // If a destruction command comes, cancel pending requests.
        // TODO(b/161774071): Allow `process_cmd` to return multiple responses and move this
        // into encoder/decoder.
        let async_responses = match cmd {
            VideoCmd::ResourceDestroyAll {
                stream_id,
                queue_type,
            } => desc_map.create_cancellation_responses(&stream_id, Some(queue_type), None),
            VideoCmd::StreamDestroy { stream_id } => {
                desc_map.create_cancellation_responses(&stream_id, None, None)
            }
            VideoCmd::QueueClear {
                stream_id,
                queue_type: QueueType::Output,
            } => {
                // TODO(b/153406792): Due to a workaround for a limitation in the VDA api,
                // clearing the output queue doesn't go through the same Async path as clearing
                // the input queue. However, we still need to cancel the pending resources.
                desc_map.create_cancellation_responses(&stream_id, Some(QueueType::Output), None)
            }
            _ => Default::default(),
        };
        for async_response in async_responses {
            let AsyncCmdResponse {
                tag,
                response: cmd_result,
            } = async_response;
            let destroy_response = match cmd_result {
                Ok(r) => r,
                Err(e) => {
                    error!("returning async error response: {}", &e);
                    e.into()
                }
            };
            match desc_map.remove(&tag) {
                Some(destroy_desc) => {
                    responses.push_back((destroy_desc, destroy_response));
                }
                None => error!("dropping response for an untracked command: {:?}", tag),
            }
        }

        // Process the command by the device.
        let (cmd_response, event_responses_with_id) =
            device.process_cmd(cmd, &wait_ctx, &self.resource_bridge);
        match cmd_response {
            VideoCmdResponseType::Sync(r) => {
                responses.push_back((desc, r));
            }
            VideoCmdResponseType::Async(tag) => {
                // If the command expects an asynchronous response,
                // store `desc` to use it after the back-end device notifies the
                // completion.
                desc_map.insert(tag, desc);
            }
        }
        if let Some((stream_id, event_responses)) = event_responses_with_id {
            self.write_event_responses(
                event_responses,
                cmd_queue,
                event_queue,
                desc_map,
                stream_id,
            )?;
        }

        Ok(responses)
    }

    /// Handles each command in the command queue.
    fn handle_command_queue<T: Device>(
        &self,
        cmd_queue: &mut Queue,
        event_queue: &mut Queue,
        device: &mut T,
        wait_ctx: &WaitContext<Token>,
        desc_map: &mut AsyncCmdDescMap,
    ) -> Result<()> {
        let _ = self.cmd_evt.read();
        while let Some(desc) = cmd_queue.pop(&self.mem) {
            let mut resps =
                self.handle_command_desc(cmd_queue, event_queue, device, wait_ctx, desc_map, desc)?;
            self.write_responses(cmd_queue, &mut resps)?;
        }
        Ok(())
    }

    /// Handles an event notified via an event.
    fn handle_event<T: Device>(
        &self,
        cmd_queue: &mut Queue,
        event_queue: &mut Queue,
        device: &mut T,
        desc_map: &mut AsyncCmdDescMap,
        stream_id: u32,
    ) -> Result<()> {
        if let Some(event_responses) = device.process_event(desc_map, stream_id) {
            self.write_event_responses(
                event_responses,
                cmd_queue,
                event_queue,
                desc_map,
                stream_id,
            )?;
        }
        Ok(())
    }

    pub fn run<T: Device>(
        &mut self,
        mut cmd_queue: Queue,
        mut event_queue: Queue,
        mut device: T,
    ) -> Result<()> {
        let wait_ctx: WaitContext<Token> = WaitContext::build_with(&[
            (&self.cmd_evt, Token::CmdQueue),
            (&self.event_evt, Token::EventQueue),
            (&self.kill_evt, Token::Kill),
        ])
        .and_then(|wc| {
            if let Some(resample_evt) = self.interrupt.get_resample_evt() {
                wc.add(resample_evt, Token::InterruptResample)?;
            }
            Ok(wc)
        })
        .map_err(Error::WaitContextCreationFailed)?;

        // Stores descriptors in which responses for asynchronous commands will be written.
        let mut desc_map: AsyncCmdDescMap = Default::default();

        loop {
            let wait_events = wait_ctx.wait().map_err(Error::WaitError)?;

            for wait_event in wait_events.iter().filter(|e| e.is_readable) {
                match wait_event.token {
                    Token::CmdQueue => {
                        self.handle_command_queue(
                            &mut cmd_queue,
                            &mut event_queue,
                            &mut device,
                            &wait_ctx,
                            &mut desc_map,
                        )?;
                    }
                    Token::EventQueue => {
                        let _ = self.event_evt.read();
                    }
                    Token::Event { id } => {
                        self.handle_event(
                            &mut cmd_queue,
                            &mut event_queue,
                            &mut device,
                            &mut desc_map,
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
