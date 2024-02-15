// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Definition of the trait `Device` that each backend video device must implement.

use base::EventToken;
use base::WaitContext;

use crate::virtio::video::async_cmd_desc_map::AsyncCmdDescMap;
use crate::virtio::video::command::QueueType;
use crate::virtio::video::command::VideoCmd;
use crate::virtio::video::error::*;
use crate::virtio::video::event::VideoEvt;
use crate::virtio::video::response;

#[derive(EventToken, Debug)]
pub enum Token {
    CmdQueue,
    EventQueue,
    Event {
        id: u32,
    },
    /// Signals that processing of a given buffer has completed. Used for cases where the guest CPU
    /// may access the buffer, in which case it cannot be handed over to the guest until operations
    /// on it have completed.
    BufferBarrier {
        id: u32,
    },
    Kill,
    InterruptResample,
}

/// A tag for commands being processed asynchronously in the back-end device.
///
/// TODO(b/149720783): Remove this enum by using async primitives.
#[derive(PartialEq, Eq, PartialOrd, Ord, Clone, Copy, Debug)]
pub enum AsyncCmdTag {
    Queue {
        stream_id: u32,
        queue_type: QueueType,
        resource_id: u32,
    },
    Drain {
        stream_id: u32,
    },
    Clear {
        stream_id: u32,
        queue_type: QueueType,
    },
    // Used exclusively by the encoder.
    #[cfg(feature = "video-encoder")]
    GetParams {
        stream_id: u32,
        queue_type: QueueType,
    },
}

/// A return value when a command from the guest is processed.
#[derive(Debug)]
pub enum VideoCmdResponseType {
    /// The response for a synchronous command. This can be returned to the guest immediately via
    /// command virtqueue.
    Sync(response::CmdResponse),
    /// The tag for an asynchronous command that the back-end device will complete.
    /// Once the command is completed, its result will be sent with the same tag.
    /// This can be seen as a poor man's future pattern.
    Async(AsyncCmdTag),
}

/// A response for an asynchronous command that was enqueued through `process_cmd` before.
/// The `tag` must be same as the one returned when the command was enqueued.
#[derive(Debug)]
pub struct AsyncCmdResponse {
    pub tag: AsyncCmdTag,
    pub response: VideoResult<response::CmdResponse>,
}

impl AsyncCmdResponse {
    pub fn from_response(tag: AsyncCmdTag, response: response::CmdResponse) -> Self {
        Self {
            tag,
            response: Ok(response),
        }
    }

    pub fn from_error(tag: AsyncCmdTag, error: VideoError) -> Self {
        Self {
            tag,
            response: Err(error),
        }
    }
}

/// A return value when processing a event the back-end device sent.
#[derive(Debug)]
pub enum VideoEvtResponseType {
    /// The responses for an asynchronous command.
    AsyncCmd(AsyncCmdResponse),
    /// The event that happened in the back-end device.
    Event(VideoEvt),
}

pub trait Device {
    /// Processes a virtio-video command.
    /// If the command expects a synchronous response, it returns a response as
    /// `VideoCmdResponseType::Sync`. Otherwise, it returns a name of the descriptor chain that
    /// will be used when a response is prepared. Implementations of this method is passed a
    /// WaitContext object which can be used to add or remove descriptors to wait on. It is
    /// expected that only Token::Event items would be added. When a Token::Event event arrives,
    /// process_event() will be invoked.
    ///
    /// TODO(b/149720783): Make this an async function.
    fn process_cmd(
        &mut self,
        cmd: VideoCmd,
        wait_ctx: &WaitContext<Token>,
    ) -> (
        VideoCmdResponseType,
        Option<(u32, Vec<VideoEvtResponseType>)>,
    );

    /// Processes an available `Token::Event` event and returns a list of `VideoEvtResponseType`
    /// responses. It returns None if an invalid event comes.
    /// For responses to be sent via command queue, the return type is
    /// `VideoEvtResponseType::AsyncCmd`. For responses to be sent via event queue, the return
    /// type is `VideoEvtResponseType::Event`.
    ///
    /// TODO(b/149720783): Make this an async function.
    fn process_event(
        &mut self,
        desc_map: &mut AsyncCmdDescMap,
        stream_id: u32,
        wait_ctx: &WaitContext<Token>,
    ) -> Option<Vec<VideoEvtResponseType>>;

    /// Processes a `Token::BufferBarrier` event and returns a list of `VideoEvtResponseType`
    /// responses. Only needs to be implemented for devices that adds `Token::BufferBarrier` tokens
    /// to the wait context.
    fn process_buffer_barrier(
        &mut self,
        _stream_id: u32,
        _wait_ctx: &WaitContext<Token>,
    ) -> Option<Vec<VideoEvtResponseType>> {
        None
    }
}
