// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::cell::RefCell;
use std::rc::Rc;

use crate::decoders::vp9::parser::Header;
use crate::decoders::vp9::parser::NUM_REF_FRAMES;
use crate::decoders::vp9::picture::Vp9Picture;
use crate::decoders::DecodedHandle;
use crate::decoders::VideoDecoderBackend;

#[cfg(test)]
pub mod dummy;
#[cfg(feature = "vaapi")]
pub mod vaapi;

pub type Result<T> = crate::decoders::StatelessBackendResult<T>;

/// The container type for the picture. Pictures must offer interior mutability
/// as they may be shared.
///
/// Pictures are contained as soon as they are submitted to the accelerator.
pub type ContainedPicture<T> = Rc<RefCell<Vp9Picture<T>>>;

/// A convenience type that casts using fully-qualified syntax.
pub type AsBackendHandle<Handle> = <Handle as DecodedHandle>::BackendHandle;

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
        picture: Vp9Picture<AsBackendHandle<Self::Handle>>,
        reference_frames: &[Option<Self::Handle>; NUM_REF_FRAMES],
        bitstream: &dyn AsRef<[u8]>,
        timestamp: u64,
        block: bool,
    ) -> Result<Self::Handle>;

    /// Get the test parameters for the backend. The caller is reponsible for
    /// downcasting them to the correct type, which is backend-dependent.
    #[cfg(test)]
    fn get_test_params(&self) -> &dyn std::any::Any;
}
