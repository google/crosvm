// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::cell::Ref;
use std::cell::RefMut;
use std::collections::HashSet;

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
    #[error("Not enough resources to proceed with the operation now.")]
    OutOfResources,
    #[error("This resource is not ready.")]
    ResourceNotReady,
    #[error("This format is not supported.")]
    UnsupportedFormat,
    #[error("Negotiation failed")]
    NegotiationFailed(anyhow::Error),
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

pub trait VideoDecoderBackend {
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

    /// Gets a set of supported formats for the particular stream being
    /// processed. This required that some buffers be processed before this call
    /// is made. Only formats that are compatible with the current color space,
    /// bit depth, and chroma format are returned such that no conversion is
    /// needed.
    ///
    /// The format can be altered by calling `try_format` if the new format is
    /// supported by the implementation.
    fn supported_formats_for_stream(&self) -> Result<HashSet<DecodedFormat>>;

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

    /// Gets a shared handle to the backend in use.
    fn backend(&self) -> &dyn VideoDecoderBackend;

    /// Gets a mutable handle to the backend in use.
    fn backend_mut(&mut self) -> &mut dyn VideoDecoderBackend;

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

    /// Polls the decoder, emitting frames for all queued decode requests. This
    /// is similar to flush, but it does not change the state of the decoded
    /// picture buffer nor does it reset any internal state.
    fn poll(&mut self, block: bool) -> Result<Vec<Box<dyn DynDecodedHandle>>>;
}

pub trait DynDecodedHandle {
    fn dyn_picture(&self) -> Ref<dyn DynPicture>;
    fn dyn_picture_mut(&self) -> RefMut<dyn DynPicture>;
    fn timestamp(&self) -> u64;
    fn display_resolution(&self) -> Resolution;
    fn display_order(&self) -> Option<u64>;
}

pub trait DynPicture {
    fn dyn_mappable_handle(&self) -> &dyn MappableHandle;
    fn dyn_mappable_handle_mut(&mut self) -> &mut dyn MappableHandle;
}

/// A trait for types that can be mapped into the client's address space.
pub trait MappableHandle: downcast_rs::Downcast {
    /// Map &self as-is into the client's address space. The bytes may be laid out
    /// in a hardware-optimized way.
    fn map(&mut self) -> Result<Box<dyn AsRef<[u8]> + '_>>;

    /// Read the contents of `self` into `buffer`.
    fn read(&mut self, buffer: &mut [u8]) -> Result<()>;

    fn mapped_resolution(&mut self) -> Result<Resolution>;
}
downcast_rs::impl_downcast!(MappableHandle);

/// Instructs the decoder on whether it should block on the decode operations.
/// Nonblocking mode is conditional on backend support.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum BlockingMode {
    Blocking,
    NonBlocking,
}

impl Default for BlockingMode {
    fn default() -> Self {
        Self::Blocking
    }
}
