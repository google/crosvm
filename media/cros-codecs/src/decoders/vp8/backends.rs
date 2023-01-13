// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use crate::decoders::vp8::parser::Header;
use crate::decoders::vp8::parser::MbLfAdjustments;
use crate::decoders::vp8::parser::Segmentation;
use crate::decoders::BlockingMode;
use crate::decoders::VideoDecoderBackend;

#[cfg(test)]
pub mod dummy;
#[cfg(feature = "vaapi")]
pub mod vaapi;

pub type Result<T> = crate::decoders::StatelessBackendResult<T>;

/// Trait for stateless decoder backends. The decoder will call into the backend
/// to request decode operations. The backend can operate in blocking mode,
/// where it will wait until the current decode finishes, or in non-blocking
/// mode, where it should return immediately with any previously decoded frames
/// that happen to be ready.
pub(crate) trait StatelessDecoderBackend: VideoDecoderBackend {
    /// Called when new stream parameters are found.
    fn new_sequence(&mut self, header: &Header) -> Result<()>;

    /// Called when the decoder wants the backend to finish the decoding
    /// operations for `picture`. The argument `block` dictates whether this
    /// call should wait until the current decode finishes, or whether it should
    /// return immediately.
    ///
    /// This call will assign the ownership of the BackendHandle to the Picture
    /// and then assign the ownership of the Picture to the Handle.
    fn submit_picture(
        &mut self,
        picture: &Header,
        last_ref: Option<&Self::Handle>,
        golden_ref: Option<&Self::Handle>,
        alt_ref: Option<&Self::Handle>,
        bitstream: &[u8],
        segmentation: &Segmentation,
        mb_lf_adjust: &MbLfAdjustments,
        timestamp: u64,
        block: BlockingMode,
    ) -> Result<Self::Handle>;

    /// Get the test parameters for the backend. The caller is reponsible for
    /// downcasting them to the correct type, which is backend-dependent.
    #[cfg(test)]
    fn get_test_params(&self) -> &dyn std::any::Any;
}
