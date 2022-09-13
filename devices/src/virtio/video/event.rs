// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Events can happen in virtio video devices.

use std::io;

use data_model::Le32;
use enumn::N;

use crate::virtio::video::protocol::*;
use crate::virtio::video::response::Response;
use crate::virtio::Writer;

#[derive(Debug, Copy, Clone, N)]
pub enum EvtType {
    Error = VIRTIO_VIDEO_EVENT_ERROR as isize,
    #[cfg(feature = "video-decoder")]
    DecResChanged = VIRTIO_VIDEO_EVENT_DECODER_RESOLUTION_CHANGED as isize,
}

#[derive(Debug, Clone)]
pub struct VideoEvt {
    pub typ: EvtType,
    pub stream_id: u32,
}

impl Response for VideoEvt {
    fn write(&self, w: &mut Writer) -> Result<(), io::Error> {
        w.write_obj(virtio_video_event {
            event_type: Le32::from(self.typ as u32),
            stream_id: Le32::from(self.stream_id),
        })
    }
}
