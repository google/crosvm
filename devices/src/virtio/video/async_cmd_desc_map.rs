// Copyright 2020 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::collections::BTreeMap;

use crate::virtio::queue::DescriptorChain;
use crate::virtio::video::device::{AsyncCmdResponse, AsyncCmdTag};
use crate::virtio::video::error::VideoError;
use crate::virtio::video::protocol;
use crate::virtio::video::response::CmdResponse;

/// AsyncCmdDescMap is a BTreeMap which stores descriptor chains in which asynchronous
/// responses will be written.
#[derive(Default)]
pub struct AsyncCmdDescMap(BTreeMap<AsyncCmdTag, DescriptorChain>);

impl AsyncCmdDescMap {
    pub fn insert(&mut self, tag: AsyncCmdTag, descriptor_chain: DescriptorChain) {
        self.0.insert(tag, descriptor_chain);
    }

    pub fn remove(&mut self, tag: &AsyncCmdTag) -> Option<DescriptorChain> {
        self.0.remove(tag)
    }

    /// Returns a list of `AsyncCmdResponse`s to cancel pending commands that target
    /// stream `target_stream_id`.
    /// If `processing_tag` is specified, a cancellation request for that tag will
    /// not be created.
    pub fn create_cancellation_responses(
        &self,
        target_stream_id: &u32,
        processing_tag: Option<AsyncCmdTag>,
    ) -> Vec<AsyncCmdResponse> {
        let mut responses = vec![];
        for tag in self.0.keys().filter(|&&k| Some(k) != processing_tag) {
            match tag {
                AsyncCmdTag::Queue { stream_id, .. } if stream_id == target_stream_id => {
                    responses.push(AsyncCmdResponse::from_response(
                        tag.clone(),
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
                    // TODO(b/1518105): Use more appropriate error code if a new protocol supports
                    // one.
                    responses.push(AsyncCmdResponse::from_error(
                        tag.clone(),
                        VideoError::InvalidOperation,
                    ));
                }
                _ => {
                    // Keep commands for other streams.
                }
            }
        }
        responses
    }
}
