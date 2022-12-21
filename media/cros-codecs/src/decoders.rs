// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::cell::Ref;
use std::cell::RefCell;
use std::cell::RefMut;
use std::rc::Rc;

use thiserror::Error;

use crate::DecodedFormat;
use crate::Resolution;

pub mod h264;
pub mod vp8;
pub mod vp9;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Error, Debug)]
pub enum Error {
    #[error(transparent)]
    StatelessBackendError(#[from] StatelessBackendError),
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

#[derive(Error, Debug)]
pub enum StatelessBackendError {
    #[error("not enough resources to proceed with the operation now")]
    OutOfResources,
    #[error("this resource is not ready")]
    ResourceNotReady,
    #[error("this format is not supported")]
    UnsupportedFormat,
    #[error("negotiation failed")]
    NegotiationFailed(anyhow::Error),
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

pub(crate) trait VideoDecoderBackend {
    /// Returns the current coded resolution of the bitstream being processed.
    /// This may be None if we have not read the stream parameters yet.
    fn coded_resolution(&self) -> Option<Resolution>;

    /// Returns the current display resolution of the bitstream being processed.
    /// This may be None if we have not read the stream parameters yet.
    fn display_resolution(&self) -> Option<Resolution>;

    /// Gets the number of output resources allocated by the backend.
    fn num_resources_total(&self) -> usize;

    /// Gets the number of output resources left in the backend.
    fn num_resources_left(&self) -> usize;

    /// Gets the chosen format. This is set to a default after the decoder reads
    /// enough stream metadata from the bitstream. Some buffers need to be
    /// processed first before the default format can be set.
    fn format(&self) -> Option<DecodedFormat>;

    /// Try altering the decoded format.
    fn try_format(&mut self, format: DecodedFormat) -> Result<()>;
}

pub trait VideoDecoder {
    /// Decode the `bitstream` represented by `timestamp`. Returns zero or more
    /// decoded handles representing the decoded data.
    fn decode(
        &mut self,
        timestamp: u64,
        bitstream: &dyn AsRef<[u8]>,
    ) -> Result<Vec<Box<dyn DynDecodedHandle>>>;

    /// Flush the decoder i.e. finish processing all queued decode requests and
    /// emit frames for them.
    fn flush(&mut self) -> Result<Vec<Box<dyn DynDecodedHandle>>>;

    /// Whether negotiation of the decoded format is possible. In particular, a
    /// decoder will indicate that negotiation is possible after enough metadata
    /// is collected from parsing the bitstream through calls to the `decode()`
    /// method.
    ///
    /// The negotiation process will start as soon as `negotiation_possible()`
    /// returns true. At this moment, the client and the backend can settle on a
    /// format by using the `supported_formats_for_stream()`, `format()` and
    /// `try_format()` methods.
    ///
    /// When `negotiation_possible()` returns true, the client may also query
    /// the backend for new values for the coded resolution, display resolution
    /// and/or to the number of resources allocated.
    ///
    /// The negotiation process ends as soon as another call to `decode()` is
    /// made, at which point any queued data will be processed first in order to
    /// generate any frames that might have been pending while the negotiation
    /// process was under way and `negotiation_possible()` will from then on
    /// return false.
    ///
    /// If no action is undertaken by the client in the window of time where
    /// `negotiation_possible()` returns true, it is assumed that the default
    /// format chosen by the backend is acceptable.
    ///
    /// The negotiation process can happen more than once if new stream metadata
    /// indicate a change of the stream parameters such that the current decoded
    /// format becomes incompatible with the stream. In this case,
    /// `negotiation_possible()` will once again return true and the same
    /// process described above will take place.
    fn negotiation_possible(&self) -> bool;

    /// Gets the number of output resources left in the backend after accounting
    /// for any buffers that might be queued in the decoder.
    fn num_resources_left(&self) -> Option<usize>;

    /// Gets the number of output resources allocated by the backend.
    fn num_resources_total(&self) -> usize;
    ///
    /// Returns the current coded resolution of the bitstream being processed.
    /// This may be None if we have not read the stream parameters yet.
    fn coded_resolution(&self) -> Option<Resolution>;

    /// Polls the decoder, emitting frames for all queued decode requests. This
    /// is similar to flush, but it does not change the state of the decoded
    /// picture buffer nor does it reset any internal state.
    fn poll(&mut self, blocking_mode: BlockingMode) -> Result<Vec<Box<dyn DynDecodedHandle>>>;
}

pub trait DynDecodedHandle {
    fn dyn_picture_mut(&self) -> RefMut<dyn DynPicture>;
    fn timestamp(&self) -> u64;
    fn display_resolution(&self) -> Resolution;
    fn display_order(&self) -> Option<u64>;
}

impl<T> DynDecodedHandle for T
where
    T: DecodedHandle,
    Picture<T::CodecData, T::BackendHandle>: DynPicture,
{
    fn dyn_picture_mut(&self) -> RefMut<dyn DynPicture> {
        DecodedHandle::picture_mut(self)
    }

    fn timestamp(&self) -> u64 {
        DecodedHandle::timestamp(self)
    }

    fn display_resolution(&self) -> Resolution {
        DecodedHandle::display_resolution(self)
    }

    fn display_order(&self) -> Option<u64> {
        DecodedHandle::display_order(self)
    }
}

pub trait DynPicture {
    /// Gets an exclusive reference to the backend handle of this picture.
    /// Assumes that this picture is backed by a handle and panics if not the case.
    fn dyn_mappable_handle_mut<'a>(&'a mut self) -> Box<dyn MappableHandle + 'a>;
}

/// A trait for types that can be mapped into the client's address space.
pub trait MappableHandle {
    /// Read the contents of `self` into `buffer`.
    ///
    /// The size of `buffer` must be equal to `image_size()`, or an error will be returned.
    fn read(&mut self, buffer: &mut [u8]) -> Result<()>;

    /// Returns the size of the `buffer` argument required to call `read` on this handle.
    fn image_size(&mut self) -> usize;
}

/// Instructs the decoder on whether it should block on the decode operations.
/// Nonblocking mode is conditional on backend support.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockingMode {
    Blocking,
    NonBlocking,
}

impl Default for BlockingMode {
    fn default() -> Self {
        Self::Blocking
    }
}

/// Codec-specific information for a single frame.
pub trait FrameInfo {
    /// Returns the display resolution of this frame.
    fn display_resolution(&self) -> Resolution;
}

/// Type for a picture being decoded by a stateless codec.
///
/// This contains the codec-specific state of the picture, as well as the backend-specific handle
/// representing the memory into which the frame will be decoded.
pub struct Picture<CodecData: FrameInfo, BackendHandle> {
    /// Codec-specific data for this picture.
    pub data: CodecData,
    /// Backend-specific handle with the memory needed by the backend to back this picture.
    pub backend_handle: Option<BackendHandle>,
    /// A number that identifies the picture.
    timestamp: u64,
}

impl<CodecData: FrameInfo, BackendHandle> Picture<CodecData, BackendHandle> {
    /// Whether two pictures are the same.
    pub fn same(lhs: &Rc<RefCell<Self>>, rhs: &Rc<RefCell<Self>>) -> bool {
        Rc::ptr_eq(lhs, rhs)
    }

    /// Get a reference to the picture's timestamp.
    pub fn timestamp(&self) -> u64 {
        self.timestamp
    }
}

/// The handle type used by the stateless decoder backend. The only requirement
/// from implementors is that they give access to the underlying Picture and
/// that they can be (cheaply) cloned.
pub trait DecodedHandle: Clone {
    /// Codec-specific data for the handle.
    type CodecData: FrameInfo;
    /// The type of the handle used by the backend.
    type BackendHandle;

    /// Returns the actual container of the inner `Picture`.
    fn picture_container(&self) -> &Rc<RefCell<Picture<Self::CodecData, Self::BackendHandle>>>;
    /// Returns the display order for this picture, if set by the decoder.
    fn display_order(&self) -> Option<u64>;
    /// Sets the display order for this picture.
    fn set_display_order(&mut self, display_order: u64);

    /// Returns a shared reference to the inner `Picture`.
    fn picture(&self) -> Ref<Picture<Self::CodecData, Self::BackendHandle>> {
        self.picture_container().borrow()
    }
    /// Returns a mutable reference to the inner `Picture`.
    fn picture_mut(&self) -> RefMut<Picture<Self::CodecData, Self::BackendHandle>> {
        self.picture_container().borrow_mut()
    }
    /// Returns the timestamp for the picture.
    fn timestamp(&self) -> u64 {
        self.picture().timestamp()
    }

    /// Returns the display resolution at the time this handle was decoded.
    fn display_resolution(&self) -> Resolution {
        self.picture().data.display_resolution()
    }
}
