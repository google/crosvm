// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::cell::RefCell;
use std::collections::VecDeque;
use std::rc::Rc;

use crate::decoders::vp9::parser::Header;
use crate::decoders::vp9::parser::NUM_REF_FRAMES;
use crate::decoders::vp9::picture::Vp9Picture;
use crate::decoders::BlockingMode;
use crate::decoders::DecodedHandle;
use crate::decoders::VideoDecoderBackend;

#[cfg(test)]
pub mod dummy;
#[cfg(feature = "vaapi")]
pub mod vaapi;

pub type Result<T> = std::result::Result<T, crate::decoders::StatelessBackendError>;

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
pub trait StatelessDecoderBackend: VideoDecoderBackend + downcast_rs::Downcast {
    /// The type that the backend returns as a result of a decode operation.
    /// This will usually be some backend-specific type with a resource and a
    /// resource pool so that said buffer can be reused for another decode
    /// operation when it goes out of scope.
    type Handle: DecodedHandle;

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

    /// Poll for any ready pictures. `block` dictates whether this call should
    /// block on the operation or return immediately.
    fn poll(&mut self, blocking_mode: BlockingMode) -> Result<VecDeque<Self::Handle>>;

    /// Whether the handle is ready for presentation. The decoder will check
    /// this before returning the handle to clients.
    fn handle_is_ready(&self, handle: &Self::Handle) -> bool;

    /// Block on handle `handle`.
    fn block_on_handle(&mut self, handle: &Self::Handle) -> Result<()>;

    /// Upcast to &mut dyn VideoDecoderBackend. This interface is the one
    /// exposed to client code. StatelessDecoderBackend is the interface exposed
    /// to the decoder.
    fn as_video_decoder_backend_mut(&mut self) -> &mut dyn VideoDecoderBackend;
    /// Upcast to &dyn VideoDecoderBackend. This interface is the one
    /// exposed to client code. StatelessDecoderBackend is the interface exposed
    /// to the decoder.
    fn as_video_decoder_backend(&self) -> &dyn VideoDecoderBackend;
}
downcast_rs::impl_downcast!(StatelessDecoderBackend assoc Handle where Handle: DecodedHandle);
