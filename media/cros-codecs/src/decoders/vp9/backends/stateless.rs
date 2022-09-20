// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::cell::Ref;
use std::cell::RefCell;
use std::cell::RefMut;
use std::collections::VecDeque;
use std::rc::Rc;

use crate::decoders::vp9::parser::Header;
use crate::decoders::vp9::parser::NUM_REF_FRAMES;
use crate::decoders::vp9::picture::Picture;
use crate::decoders::BlockingMode;
use crate::decoders::MappableHandle;
use crate::decoders::VideoDecoderBackend;
use crate::Resolution;

#[cfg(test)]
pub mod dummy;
#[cfg(feature = "vaapi")]
pub mod vaapi;

pub type Result<T> = std::result::Result<T, crate::decoders::StatelessBackendError>;

/// The container type for the picture. Pictures must offer interior mutability
/// as they may be shared.
///
/// Pictures are contained as soon as they are submitted to the accelerator.
pub type ContainedPicture<T> = Rc<RefCell<Picture<T>>>;

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
        picture: Picture<AsBackendHandle<Self::Handle>>,
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

/// The handle type used by the stateless decoder backend. The only requirement
/// from implementors is that they give access to the underlying Picture and
/// that they can be (cheaply) cloned.
pub trait DecodedHandle: Clone {
    /// The type of the handle used by the backend.
    type BackendHandle: MappableHandle;

    /// Returns a shared reference to the inner `Picture`.
    fn picture(&self) -> Ref<Picture<Self::BackendHandle>>;
    /// Returns a mutable reference to the inner `Picture`.
    fn picture_mut(&self) -> RefMut<Picture<Self::BackendHandle>>;
    /// Returns the actual container of the inner `Picture`.
    fn picture_container(&self) -> ContainedPicture<Self::BackendHandle>;
    /// Returns the timestamp for the picture.
    fn timestamp(&self) -> u64;
    /// Returns the display resolution at the time this handle was decoded.
    fn display_resolution(&self) -> Resolution;
    /// Returns the display order for this picture, if set by the decoder.
    fn display_order(&self) -> Option<u64>;
    /// Sets the display order for this picture.
    fn set_display_order(&mut self, display_order: u64);
}
