// Copyright 2020 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Implementation of the the `Encoder` struct, which is responsible for translation between the
//! virtio protocols and LibVDA APIs.

use base::PollContext;

use crate::virtio::resource_bridge::ResourceRequestSocket;
use crate::virtio::video::async_cmd_desc_map::AsyncCmdDescMap;
use crate::virtio::video::command::VideoCmd;
use crate::virtio::video::device::{Device, Token, VideoCmdResponseType, VideoEvtResponseType};
use crate::virtio::video::error::*;

pub struct Encoder;

impl Encoder {
    pub fn new() -> Self {
        Encoder {}
    }
}

impl Device for Encoder {
    fn process_cmd(
        &mut self,
        _cmd: VideoCmd,
        _poll_ctx: &PollContext<Token>,
        _resource_bridge: &ResourceRequestSocket,
    ) -> VideoResult<VideoCmdResponseType> {
        Err(VideoError::InvalidOperation)
    }

    fn process_event(
        &mut self,
        _desc_map: &mut AsyncCmdDescMap,
        _stream_id: u32,
    ) -> Option<Vec<VideoEvtResponseType>> {
        None
    }
}
