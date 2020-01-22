// Copyright 2020 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Definition of the trait `Device` that each backend video device must implement.

use sys_util::{PollContext, PollToken};

use crate::virtio::resource_bridge::ResourceRequestSocket;
use crate::virtio::video::command::{QueueType, VideoCmd};
use crate::virtio::video::error::*;
use crate::virtio::video::event::VideoEvt;
use crate::virtio::video::response;

#[derive(PollToken, Debug)]
pub enum Token {
    CmdQueue,
    EventQueue,
    EventFd { id: u32 },
    Kill,
    InterruptResample,
}

/// A tag for commands being processed asynchronously in the back-end device.
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

/// A return value when processing a event the back-end device sent.
#[derive(Debug)]
pub enum VideoEvtResponseType {
    /// The response for an asynchronous command that was enqueued through `process_cmd` before.
    /// The `tag` must be same as the one returned when the command is enqueued.
    AsyncCmd {
        tag: AsyncCmdTag,
        resp: VideoResult<response::CmdResponse>,
    },
    /// The event that happened in the back-end device.
    Event(VideoEvt),
}

pub trait Device {
    /// Processes a virtio-video command.
    /// If the command expects a synchronous response, it returns a response as `VideoCmdResponseType::Sync`.
    /// Otherwise, it returns a name of the descriptor chain that will be used when a response is prepared.
    /// Implementations of this method is passed a PollContext object which can be used to add or remove
    /// FDs to poll. It is expected that only Token::EventFd items would be added. When a Token::EventFd
    /// event arrives, process_event_fd() will be invoked.
    /// TODO(b/149720783): Make this an async function.
    fn process_cmd(
        &mut self,
        cmd: VideoCmd,
        poll_ctx: &PollContext<Token>,
        resource_bridge: &ResourceRequestSocket,
    ) -> VideoResult<VideoCmdResponseType>;

    /// Processes an available Token::EventFd event.
    /// If the message is sent via commandq, the return value is `VideoEvtResponseType::AsyncCmd`.
    /// Otherwise (i.e. case of eventq), it's `VideoEvtResponseType::Event`.
    /// TODO(b/149720783): Make this an async function.
    fn process_event_fd(&mut self, stream_id: u32) -> Option<VideoEvtResponseType>;

    /// Returns an ID for an available output resource that can be used to notify EOS.
    /// Note that this resource must be enqueued by `ResourceQueue` and not be returned yet.
    fn take_resource_id_to_notify_eos(&mut self, stream_id: u32) -> Option<u32>;
}
