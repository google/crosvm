// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Worker that runs in a virtio-video thread.

use std::collections::VecDeque;
use std::time::Duration;

use base::clone_descriptor;
use base::error;
use base::info;
use base::Event;
use base::WaitContext;
use cros_async::select3;
use cros_async::AsyncWrapper;
use cros_async::EventAsync;
use cros_async::Executor;
use cros_async::SelectResult;
use futures::FutureExt;

use crate::virtio::video::async_cmd_desc_map::AsyncCmdDescMap;
use crate::virtio::video::command::QueueType;
use crate::virtio::video::command::VideoCmd;
use crate::virtio::video::device::AsyncCmdResponse;
use crate::virtio::video::device::AsyncCmdTag;
use crate::virtio::video::device::Device;
use crate::virtio::video::device::Token;
use crate::virtio::video::device::VideoCmdResponseType;
use crate::virtio::video::device::VideoEvtResponseType;
use crate::virtio::video::event;
use crate::virtio::video::event::EvtType;
use crate::virtio::video::event::VideoEvt;
use crate::virtio::video::response;
use crate::virtio::video::response::Response;
use crate::virtio::video::Error;
use crate::virtio::video::Result;
use crate::virtio::DescriptorChain;
use crate::virtio::Interrupt;
use crate::virtio::Queue;

/// Worker that takes care of running the virtio video device.
pub struct Worker {
    /// VirtIO queue for Command queue
    cmd_queue: Queue,
    /// Device-to-driver notification for command queue
    cmd_queue_interrupt: Interrupt,
    /// VirtIO queue for Event queue
    event_queue: Queue,
    /// Device-to-driver notification for the event queue.
    event_queue_interrupt: Interrupt,
    /// Stores descriptor chains in which responses for asynchronous commands will be written
    desc_map: AsyncCmdDescMap,
}

/// Pair of a descriptor chain and a response to be written.
type WritableResp = (DescriptorChain, response::CmdResponse);

impl Worker {
    pub fn new(
        cmd_queue: Queue,
        cmd_queue_interrupt: Interrupt,
        event_queue: Queue,
        event_queue_interrupt: Interrupt,
    ) -> Self {
        Self {
            cmd_queue,
            cmd_queue_interrupt,
            event_queue,
            event_queue_interrupt,
            desc_map: Default::default(),
        }
    }

    /// Writes responses into the command queue.
    fn write_responses(&mut self, responses: &mut VecDeque<WritableResp>) -> Result<()> {
        if responses.is_empty() {
            return Ok(());
        }
        while let Some((mut desc, response)) = responses.pop_front() {
            if let Err(e) = response.write(&mut desc.writer) {
                error!(
                    "failed to write a command response for {:?}: {}",
                    response, e
                );
            }
            let len = desc.writer.bytes_written() as u32;
            self.cmd_queue.add_used(desc, len);
        }
        self.cmd_queue.trigger_interrupt(&self.cmd_queue_interrupt);
        Ok(())
    }

    /// Writes a `VideoEvt` into the event queue.
    fn write_event(&mut self, event: event::VideoEvt) -> Result<()> {
        let mut desc = self
            .event_queue
            .pop()
            .ok_or(Error::DescriptorNotAvailable)?;

        event
            .write(&mut desc.writer)
            .map_err(|error| Error::WriteEventFailure { event, error })?;
        let len = desc.writer.bytes_written() as u32;
        self.event_queue.add_used(desc, len);
        self.event_queue
            .trigger_interrupt(&self.event_queue_interrupt);
        Ok(())
    }

    /// Writes the `event_responses` into the command queue or the event queue according to
    /// each response's type.
    ///
    /// # Arguments
    ///
    /// * `event_responses` - Responses to write
    /// * `stream_id` - Stream session ID of the responses
    fn write_event_responses(
        &mut self,
        event_responses: Vec<VideoEvtResponseType>,
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
                    match self.desc_map.remove(&tag) {
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
                    self.write_event(evt)?;
                }
            }
        }

        if let Err(e) = self.write_responses(&mut responses) {
            error!("Failed to write event responses: {:?}", e);
            // Ignore result of write_event for a fatal error.
            let _ = self.write_event(VideoEvt {
                typ: EvtType::Error,
                stream_id,
            });
            return Err(e);
        }

        Ok(())
    }

    /// Handles a `DescriptorChain` value sent via the command queue and returns a `VecDeque`
    /// of `WritableResp` to be sent to the guest.
    ///
    /// # Arguments
    ///
    /// * `device` - Instance of backend device
    /// * `wait_ctx` - `device` may register a new `Token::Event` for a new stream session to
    ///   `wait_ctx`
    /// * `desc` - `DescriptorChain` to handle
    fn handle_command_desc(
        &mut self,
        device: &mut dyn Device,
        wait_ctx: &WaitContext<Token>,
        mut desc: DescriptorChain,
    ) -> Result<VecDeque<WritableResp>> {
        let mut responses: VecDeque<WritableResp> = Default::default();
        let cmd = VideoCmd::from_reader(&mut desc.reader).map_err(Error::ReadFailure)?;

        // If a destruction command comes, cancel pending requests.
        // TODO(b/161774071): Allow `process_cmd` to return multiple responses and move this
        // into encoder/decoder.
        let async_responses = match cmd {
            VideoCmd::ResourceDestroyAll {
                stream_id,
                queue_type,
            } => self
                .desc_map
                .create_cancellation_responses(&stream_id, Some(queue_type), None),
            VideoCmd::StreamDestroy { stream_id } => self
                .desc_map
                .create_cancellation_responses(&stream_id, None, None),
            VideoCmd::QueueClear {
                stream_id,
                queue_type: QueueType::Output,
            } => {
                // TODO(b/153406792): Due to a workaround for a limitation in the VDA api,
                // clearing the output queue doesn't go through the same Async path as clearing
                // the input queue. However, we still need to cancel the pending resources.
                self.desc_map.create_cancellation_responses(
                    &stream_id,
                    Some(QueueType::Output),
                    None,
                )
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
            match self.desc_map.remove(&tag) {
                Some(destroy_desc) => {
                    responses.push_back((destroy_desc, destroy_response));
                }
                None => error!("dropping response for an untracked command: {:?}", tag),
            }
        }

        // Process the command by the device.
        let (cmd_response, event_responses_with_id) = device.process_cmd(cmd, wait_ctx);
        match cmd_response {
            VideoCmdResponseType::Sync(r) => {
                responses.push_back((desc, r));
            }
            VideoCmdResponseType::Async(tag) => {
                // If the command expects an asynchronous response,
                // store `desc` to use it after the back-end device notifies the
                // completion.
                self.desc_map.insert(tag, desc);
            }
        }
        if let Some((stream_id, event_responses)) = event_responses_with_id {
            self.write_event_responses(event_responses, stream_id)?;
        }

        Ok(responses)
    }

    /// Handles each command in the command queue.
    ///
    /// # Arguments
    ///
    /// * `device` - Instance of backend device
    /// * `wait_ctx` - `device` may register a new `Token::Event` for a new stream session to
    ///   `wait_ctx`
    fn handle_command_queue(
        &mut self,
        device: &mut dyn Device,
        wait_ctx: &WaitContext<Token>,
    ) -> Result<()> {
        while let Some(desc) = self.cmd_queue.pop() {
            let mut resps = self.handle_command_desc(device, wait_ctx, desc)?;
            self.write_responses(&mut resps)?;
        }
        Ok(())
    }

    /// Handles an event notified via an event.
    ///
    /// # Arguments
    ///
    /// * `device` - Instance of backend device
    /// * `stream_id` - Stream session ID of the event
    /// * `wait_ctx` - `device` may register a new `Token::Buffer` for a new stream session to
    ///   `wait_ctx`
    fn handle_event(
        &mut self,
        device: &mut dyn Device,
        stream_id: u32,
        wait_ctx: &WaitContext<Token>,
    ) -> Result<()> {
        if let Some(event_responses) = device.process_event(&mut self.desc_map, stream_id, wait_ctx)
        {
            self.write_event_responses(event_responses, stream_id)?;
        }
        Ok(())
    }

    /// Handles a completed buffer barrier.
    ///
    /// # Arguments
    ///
    /// * `device` - Instance of backend device
    /// * `stream_id` - Stream session ID of the event
    /// * `wait_ctx` - `device` may deregister the completed `Token::BufferBarrier` from
    /// `wait_ctx`.
    fn handle_buffer_barrier(
        &mut self,
        device: &mut dyn Device,
        stream_id: u32,
        wait_ctx: &WaitContext<Token>,
    ) -> Result<()> {
        if let Some(event_responses) = device.process_buffer_barrier(stream_id, wait_ctx) {
            self.write_event_responses(event_responses, stream_id)?;
        }
        Ok(())
    }

    /// Runs the video device virtio queues in a blocking way.
    ///
    /// # Arguments
    ///
    /// * `device` - Instance of backend device
    /// * `kill_evt` - `Event` notified to make `run` stop and return
    pub fn run(&mut self, mut device: Box<dyn Device>, kill_evt: &Event) -> Result<()> {
        let wait_ctx: WaitContext<Token> = WaitContext::build_with(&[
            (self.cmd_queue.event(), Token::CmdQueue),
            (self.event_queue.event(), Token::EventQueue),
            (kill_evt, Token::Kill),
        ])
        .and_then(|wc| {
            // resampling event exists per-PCI-INTx basis, so the two queues have the same event.
            // Thus, checking only cmd_queue_interrupt suffices.
            if let Some(resample_evt) = self.cmd_queue_interrupt.get_resample_evt() {
                wc.add(resample_evt, Token::InterruptResample)?;
            }
            Ok(wc)
        })
        .map_err(Error::WaitContextCreationFailed)?;

        loop {
            let wait_events = wait_ctx.wait().map_err(Error::WaitError)?;

            for wait_event in wait_events.iter().filter(|e| e.is_readable) {
                match wait_event.token {
                    Token::CmdQueue => {
                        let _ = self.cmd_queue.event().wait();
                        self.handle_command_queue(device.as_mut(), &wait_ctx)?;
                    }
                    Token::EventQueue => {
                        let _ = self.event_queue.event().wait();
                    }
                    Token::Event { id } => {
                        self.handle_event(device.as_mut(), id, &wait_ctx)?;
                    }
                    Token::BufferBarrier { id } => {
                        self.handle_buffer_barrier(device.as_mut(), id, &wait_ctx)?;
                    }
                    Token::InterruptResample => {
                        // Clear the event. `expect` is ok since the token fires if and only if
                        // resample exists. resampling event exists per-PCI-INTx basis, so the
                        // two queues have the same event.
                        let _ = self
                            .cmd_queue_interrupt
                            .get_resample_evt()
                            .expect("resample event for the command queue doesn't exist")
                            .wait();
                        self.cmd_queue_interrupt.do_interrupt_resample();
                    }
                    Token::Kill => return Ok(()),
                }
            }
        }
    }

    /// Runs the video device virtio queues asynchronously.
    ///
    /// # Arguments
    ///
    /// * `device` - Instance of backend device
    /// * `ex` - Instance of `Executor` of asynchronous operations
    /// * `cmd_evt` - Driver-to-device kick event for the command queue
    /// * `event_evt` - Driver-to-device kick event for the event queue
    #[allow(dead_code)]
    pub async fn run_async(
        mut self,
        mut device: Box<dyn Device>,
        ex: Executor,
        cmd_evt: Event,
        event_evt: Event,
    ) -> Result<()> {
        let cmd_queue_evt =
            EventAsync::new(cmd_evt, &ex).map_err(Error::EventAsyncCreationFailed)?;
        let event_queue_evt =
            EventAsync::new(event_evt, &ex).map_err(Error::EventAsyncCreationFailed)?;

        // WaitContext to wait for the response from the encoder/decoder device.
        let device_wait_ctx = WaitContext::new().map_err(Error::WaitContextCreationFailed)?;
        let device_evt = ex
            .async_from(AsyncWrapper::new(
                clone_descriptor(&device_wait_ctx).map_err(Error::CloneDescriptorFailed)?,
            ))
            .map_err(Error::EventAsyncCreationFailed)?;

        loop {
            let (
                cmd_queue_evt,
                device_evt,
                // Ignore driver-to-device kicks since the event queue is write-only for a device.
                _event_queue_evt,
            ) = select3(
                cmd_queue_evt.next_val().boxed_local(),
                device_evt.wait_readable().boxed_local(),
                event_queue_evt.next_val().boxed_local(),
            )
            .await;

            if let SelectResult::Finished(_) = cmd_queue_evt {
                self.handle_command_queue(device.as_mut(), &device_wait_ctx)?;
            }

            if let SelectResult::Finished(_) = device_evt {
                let device_events = match device_wait_ctx.wait_timeout(Duration::from_secs(0)) {
                    Ok(device_events) => device_events,
                    Err(_) => {
                        error!("failed to read a device event");
                        continue;
                    }
                };
                for device_event in device_events {
                    // A Device must trigger only Token::Event. See [`Device::process_cmd()`].
                    if let Token::Event { id } = device_event.token {
                        self.handle_event(device.as_mut(), id, &device_wait_ctx)?;
                    } else {
                        error!(
                            "invalid event is triggered by a device {:?}",
                            device_event.token
                        );
                    }
                }
            }
        }
    }
}
