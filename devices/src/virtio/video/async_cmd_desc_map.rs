// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::collections::BTreeMap;

use crate::virtio::video::command::QueueType;
use crate::virtio::video::device::AsyncCmdResponse;
use crate::virtio::video::device::AsyncCmdTag;
use crate::virtio::video::error::VideoError;
use crate::virtio::video::protocol;
use crate::virtio::video::response::CmdResponse;
use crate::virtio::DescriptorChain;

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
    /// If `target_queue_type` is specified, then only create the requests for the specified queue.
    /// Otherwise, create the requests for both input and output queue.
    /// If `processing_tag` is specified, a cancellation request for that tag will
    /// not be created.
    pub fn create_cancellation_responses(
        &self,
        target_stream_id: &u32,
        target_queue_type: Option<QueueType>,
        processing_tag: Option<AsyncCmdTag>,
    ) -> Vec<AsyncCmdResponse> {
        let mut responses = vec![];
        for tag in self.0.keys().filter(|&&k| Some(k) != processing_tag) {
            match tag {
                AsyncCmdTag::Queue {
                    stream_id,
                    queue_type,
                    ..
                } if stream_id == target_stream_id
                    && target_queue_type.as_ref().unwrap_or(queue_type) == queue_type =>
                {
                    responses.push(AsyncCmdResponse::from_response(
                        *tag,
                        CmdResponse::ResourceQueue {
                            timestamp: 0,
                            flags: protocol::VIRTIO_VIDEO_BUFFER_FLAG_ERR,
                            size: 0,
                        },
                    ));
                }
                AsyncCmdTag::Drain { stream_id } if stream_id == target_stream_id => {
                    // TODO(b/1518105): Use more appropriate error code if a new protocol supports
                    // one.
                    responses.push(AsyncCmdResponse::from_error(
                        *tag,
                        VideoError::InvalidOperation,
                    ));
                }
                AsyncCmdTag::Clear {
                    stream_id,
                    queue_type,
                } if stream_id == target_stream_id
                    && target_queue_type.as_ref().unwrap_or(queue_type) == queue_type =>
                {
                    // TODO(b/1518105): Use more appropriate error code if a new protocol supports
                    // one.
                    responses.push(AsyncCmdResponse::from_error(
                        *tag,
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
