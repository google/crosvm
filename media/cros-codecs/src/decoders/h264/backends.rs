// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::cell::RefCell;
use std::rc::Rc;

use crate::decoders::h264::dpb::Dpb;
use crate::decoders::h264::parser::Pps;
use crate::decoders::h264::parser::Slice;
use crate::decoders::h264::parser::Sps;
use crate::decoders::h264::picture::H264Picture;
use crate::decoders::DecodedHandle;
use crate::decoders::VideoDecoderBackend;

pub type Result<T> = crate::decoders::StatelessBackendResult<T>;

#[cfg(test)]
pub mod dummy;
#[cfg(feature = "vaapi")]
pub mod vaapi;

/// The container type for the picture. Pictures must offer interior mutability
/// as they may be shared. This is notably the case when two fields reference
/// each other.
///
/// Pictures are contained as soon as they are submitted to the accelerator.
pub type ContainedPicture<T> = Rc<RefCell<H264Picture<T>>>;

/// A convenience type that casts using fully-qualified syntax.
pub type AsBackendHandle<Handle> = <Handle as DecodedHandle>::BackendHandle;

/// Trait for stateless decoder backends. The decoder will call into the backend
/// to request decode operations. The backend can operate in blocking mode,
/// where it will wait until the current decode finishes, or in non-blocking
/// mode, where it should return immediately with any previously decoded frames
/// that happen to be ready.
pub(crate) trait StatelessDecoderBackend: VideoDecoderBackend {
    /// Called when a new SPS is parsed.
    fn new_sequence(&mut self, sps: &Sps) -> Result<()>;

    /// Called when the decoder determines that a frame or field was found.
    fn new_picture(
        &mut self,
        picture: &H264Picture<AsBackendHandle<Self::Handle>>,
        timestamp: u64,
    ) -> Result<()>;

    /// Called when the decoder determines that a second field was found.
    /// Indicates that the underlying BackendHandle is to be shared between the
    /// two pictures. This is so both fields decode to the same underlying
    /// resource and can thus be presented together as a single frame.
    fn new_field_picture(
        &mut self,
        picture: &H264Picture<AsBackendHandle<Self::Handle>>,
        timestamp: u64,
        first_field: &Self::Handle,
    ) -> Result<()>;

    /// Called by the decoder for every frame or field found.
    fn handle_picture(
        &mut self,
        picture: &H264Picture<AsBackendHandle<Self::Handle>>,
        timestamp: u64,
        sps: &Sps,
        pps: &Pps,
        dpb: &Dpb<Self::Handle>,
        slice: &Slice<&[u8]>,
    ) -> Result<()>;

    /// Called to dispatch a decode operation to the backend.
    fn decode_slice(
        &mut self,
        slice: &Slice<&[u8]>,
        sps: &Sps,
        pps: &Pps,
        dpb: &Dpb<Self::Handle>,
        ref_pic_list0: &[Self::Handle],
        ref_pic_list1: &[Self::Handle],
    ) -> Result<()>;

    /// Called when the decoder has decided to split a frame into its
    /// constituent fields. `new_picture` represents the newly-created field.
    fn new_split_picture(
        &mut self,
        split_picture: ContainedPicture<AsBackendHandle<Self::Handle>>,
        new_picture: ContainedPicture<AsBackendHandle<Self::Handle>>,
    ) -> Result<()>;

    /// Called when the decoder wants the backend to finish the decoding
    /// operations for `picture`. At this point, `decode_slice` has been called
    /// for all slices. The argument `block` dictates whether this call should
    /// wait until the current decode finishes, or whether it should return
    /// immediately.
    ///
    /// This call will assign the ownership of the BackendHandle to the Picture
    /// and then assign the ownership of the Picture to the Handle.
    fn submit_picture(
        &mut self,
        picture: H264Picture<AsBackendHandle<Self::Handle>>,
        block: bool,
    ) -> Result<Self::Handle>;

    /// Indicates that the decoder has split a picture and that a new Handle
    /// must be obtained.
    fn new_handle(
        &mut self,
        picture: ContainedPicture<AsBackendHandle<Self::Handle>>,
    ) -> Result<Self::Handle>;

    /// Get the test parameters for the backend. The caller is reponsible for
    /// downcasting them to the correct type, which is backend-dependent.
    #[cfg(test)]
    fn get_test_params(&self) -> &dyn std::any::Any;
}
