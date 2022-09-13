// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Utility features shared by both the decoder and encoder VDA backends.

use crate::virtio::video::error::VideoError;
use crate::virtio::video::format::Profile;

/// Transparent convertion from libvda error to VideoError backend failure.
impl From<libvda::Error> for VideoError {
    fn from(error: libvda::Error) -> Self {
        VideoError::BackendFailure(error.into())
    }
}

macro_rules! impl_libvda_conversion {
    ( $( ( $x:ident, $y:ident ) ),* ) => {
        pub fn from_libvda_profile(p: libvda::Profile) -> Option<Self> {
            match p {
                $(libvda::Profile::$x => Some(Self::$y),)*
                _ => None
            }
        }

        #[cfg(feature = "video-encoder")]
        pub fn to_libvda_profile(self) -> Option<libvda::Profile> {
            match self {
                $(Self::$y => Some(libvda::Profile::$x),)*
                _ => None
            }
        }
    }
}

impl Profile {
    impl_libvda_conversion!(
        (H264ProfileBaseline, H264Baseline),
        (H264ProfileMain, H264Main),
        (H264ProfileExtended, H264Extended),
        (H264ProfileHigh, H264High),
        (H264ProfileHigh10Profile, H264High10),
        (H264ProfileHigh422Profile, H264High422),
        (
            H264ProfileHigh444PredictiveProfile,
            H264High444PredictiveProfile
        ),
        (H264ProfileScalableBaseline, H264ScalableBaseline),
        (H264ProfileScalableHigh, H264ScalableHigh),
        (H264ProfileStereoHigh, H264StereoHigh),
        (H264ProfileMultiviewHigh, H264MultiviewHigh),
        (HevcProfileMain, HevcMain),
        (HevcProfileMain10, HevcMain10),
        (HevcProfileMainStillPicture, HevcMainStillPicture),
        (VP8, VP8Profile0),
        (VP9Profile0, VP9Profile0),
        (VP9Profile1, VP9Profile1),
        (VP9Profile2, VP9Profile2),
        (VP9Profile3, VP9Profile3)
    );
}
