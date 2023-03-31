// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! This module implements a lightweight and safe decoder interface over `libavcodec`. It is
//! designed to concentrate all calls to unsafe methods in one place, while providing the same
//! low-level access as the libavcodec functions do.

use std::ffi::CStr;
use std::fmt::Debug;
use std::fmt::Display;
use std::marker::PhantomData;
use std::mem::ManuallyDrop;
use std::ops::Deref;

use libc::c_char;
use libc::c_int;
use libc::c_void;
use thiserror::Error as ThisError;

use super::*;
use crate::ffi::AVPictureType;

/// An error returned by a low-level libavcodec function.
#[derive(Debug, ThisError)]
pub struct AvError(pub libc::c_int);

impl AvError {
    pub fn result(ret: c_int) -> Result<(), Self> {
        if ret >= 0 {
            Ok(())
        } else {
            Err(AvError(ret))
        }
    }
}

impl Display for AvError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut buffer = [0u8; 255];
        // Safe because we are passing valid bounds for the buffer.
        let ret =
            unsafe { ffi::av_strerror(self.0, buffer.as_mut_ptr() as *mut c_char, buffer.len()) };
        match ret {
            ret if ret >= 0 => {
                let end_of_string = buffer.iter().position(|i| *i == 0).unwrap_or(buffer.len());
                let error_string = std::string::String::from_utf8_lossy(&buffer[..end_of_string]);
                f.write_str(&error_string)
            }
            _ => f.write_fmt(format_args!("Unknown avcodec error {}", self.0)),
        }
    }
}

/// Lightweight abstraction over libavcodec's `AVCodec` struct, allowing the query the capabilities
/// of supported codecs and opening a session to work with them.
///
/// `AVCodec` instances in libavcodec are all static, hence we can safely use a static reference
/// lifetime here.
pub struct AvCodec(&'static ffi::AVCodec);

#[derive(Debug, ThisError)]
pub enum AvCodecOpenError {
    #[error("failed to allocate AVContext object")]
    ContextAllocation,
    #[error("failed to open AVContext object")]
    ContextOpen,
    #[error("ContextBuilder variant does not match codec type")]
    UnexpectedCodecType,
}

/// Dimensions of a frame, used in AvCodecContext and AvFrame.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Dimensions {
    pub width: u32,
    pub height: u32,
}

impl AvCodec {
    /// Returns whether the codec is a decoder.
    pub fn is_decoder(&self) -> bool {
        // Safe because `av_codec_is_decoder` is called on a valid static `AVCodec` reference.
        (unsafe { ffi::av_codec_is_decoder(self.0) } != 0)
    }

    /// Returns whether the codec is an encoder.
    pub fn is_encoder(&self) -> bool {
        // Safe because `av_codec_is_encoder` is called on a valid static `AVCodec` reference.
        (unsafe { ffi::av_codec_is_encoder(self.0) } != 0)
    }

    /// Returns the name of the codec.
    pub fn name(&self) -> &'static str {
        const INVALID_CODEC_STR: &str = "invalid codec";

        // Safe because `CStr::from_ptr` is called on a valid zero-terminated C string.
        unsafe { CStr::from_ptr(self.0.name).to_str() }.unwrap_or(INVALID_CODEC_STR)
    }

    /// Returns the capabilities of the codec, as a mask of AV_CODEC_CAP_* bits.
    pub fn capabilities(&self) -> u32 {
        self.0.capabilities as u32
    }

    /// Returns an iterator over the profiles supported by this codec.
    pub fn profile_iter(&self) -> AvProfileIterator {
        AvProfileIterator(self.0.profiles)
    }

    /// Returns an iterator over the pixel formats supported by this codec.
    ///
    /// For a decoder, the returned array will likely be empty. This means that ffmpeg's native
    /// pixel format (YUV420) will be used.
    pub fn pixel_format_iter(&self) -> AvPixelFormatIterator {
        AvPixelFormatIterator(self.0.pix_fmts)
    }

    /// Get a builder for a encoder [`AvCodecContext`] using this codec.
    pub fn build_encoder(&self) -> Result<EncoderContextBuilder, AvCodecOpenError> {
        if !self.is_encoder() {
            return Err(AvCodecOpenError::UnexpectedCodecType);
        }

        Ok(EncoderContextBuilder {
            codec: self.0,
            context: self.alloc_context()?,
        })
    }

    /// Get a builder for a decoder [`AvCodecContext`] using this codec.
    pub fn build_decoder(&self) -> Result<DecoderContextBuilder, AvCodecOpenError> {
        if !self.is_decoder() {
            return Err(AvCodecOpenError::UnexpectedCodecType);
        }

        Ok(DecoderContextBuilder {
            codec: self.0,
            context: self.alloc_context()?,
        })
    }

    /// Internal helper for `build_decoder` to allocate an [`AvCodecContext`]. This needs to be
    /// paired with a later call to [`AvCodecContext::init`].
    fn alloc_context(&self) -> Result<AvCodecContext, AvCodecOpenError> {
        let context = unsafe { ffi::avcodec_alloc_context3(self.0).as_mut() }
            .ok_or(AvCodecOpenError::ContextAllocation)?;

        Ok(AvCodecContext(context))
    }
}

/// A builder to create a [`AvCodecContext`] suitable for decoding.
// This struct wraps an AvCodecContext directly, but the only way it can be taken out is to call
// `build()`, which finalizes the context and prevent further modification to the callback, etc.
pub struct DecoderContextBuilder {
    codec: *const ffi::AVCodec,
    context: AvCodecContext,
}

impl DecoderContextBuilder {
    /// Set a custom callback that provides output buffers.
    ///
    /// `get_buffer2` is a function that decides which buffer is used to render a frame (see
    /// libavcodec's documentation for `get_buffer2` for more details). If provided, this function
    /// must be thread-safe.
    /// `opaque` is a pointer that will be passed as first argument to `get_buffer2` when it is called.
    pub fn set_get_buffer_2(
        &mut self,
        get_buffer2: unsafe extern "C" fn(*mut ffi::AVCodecContext, *mut ffi::AVFrame, i32) -> i32,
        opaque: *mut libc::c_void,
    ) {
        // Safe because self.context.0 is a pointer to a live AVCodecContext allocation.
        let context = unsafe { &mut *(self.context.0) };
        context.get_buffer2 = Some(get_buffer2);
        context.opaque = opaque;
        context.thread_safe_callbacks = 1;
    }

    /// Build a decoder AvCodecContext from the configured options.
    pub fn build(mut self) -> Result<AvCodecContext, AvCodecOpenError> {
        self.context.init(self.codec)?;
        Ok(self.context)
    }
}

/// A builder to create a [`AvCodecContext`] suitable for encoding.
// This struct wraps an AvCodecContext directly, but the only way it can be taken out is to call
// `build()`, which finalizes the context and prevent further modification to the callback, etc.
pub struct EncoderContextBuilder {
    codec: *const ffi::AVCodec,
    context: AvCodecContext,
}

impl EncoderContextBuilder {
    /// Set the width of input frames for this encoding context.
    pub fn set_dimensions(&mut self, dimensions: Dimensions) {
        let context = unsafe { &mut *(self.context.0) };
        context.width = dimensions.width as _;
        context.height = dimensions.height as _;
    }

    /// Set the time base for this encoding context.
    pub fn set_time_base(&mut self, time_base: ffi::AVRational) {
        let context = unsafe { &mut *(self.context.0) };
        context.time_base = time_base;
    }

    /// Set the input pixel format for this encoding context.
    pub fn set_pix_fmt(&mut self, fmt: AvPixelFormat) {
        let context = unsafe { &mut *(self.context.0) };
        context.pix_fmt = fmt.pix_fmt();
    }

    /// Build a encoder AvCodecContext from the configured options.
    pub fn build(mut self) -> Result<AvCodecContext, AvCodecOpenError> {
        self.context.init(self.codec)?;
        Ok(self.context)
    }
}

/// Lightweight abstraction over libavcodec's `av_codec_iterate` function that can be used to
/// enumerate all the supported codecs.
pub struct AvCodecIterator(*mut libc::c_void);

impl AvCodecIterator {
    pub fn new() -> Self {
        Self(std::ptr::null_mut())
    }
}

impl Iterator for AvCodecIterator {
    type Item = AvCodec;

    fn next(&mut self) -> Option<Self::Item> {
        // Safe because our pointer was initialized to `NULL` and we only use it with
        // `av_codec_iterate`, which will update it to a valid value.
        unsafe { ffi::av_codec_iterate(&mut self.0 as *mut *mut libc::c_void).as_ref() }
            .map(AvCodec)
    }
}

/// Simple wrapper over `AVProfile` that provides helpful methods.
pub struct AvProfile(&'static ffi::AVProfile);

impl AvProfile {
    /// Return the profile id, which can be matched against FF_PROFILE_*.
    pub fn profile(&self) -> u32 {
        self.0.profile as u32
    }

    /// Return the name of this profile.
    pub fn name(&self) -> &'static str {
        const INVALID_PROFILE_STR: &str = "invalid profile";

        // Safe because `CStr::from_ptr` is called on a valid zero-terminated C string.
        unsafe { CStr::from_ptr(self.0.name).to_str() }.unwrap_or(INVALID_PROFILE_STR)
    }
}

impl Display for AvProfile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

impl Debug for AvProfile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Display::fmt(self, f)
    }
}

/// Lightweight abstraction over the array of supported profiles for a given codec.
pub struct AvProfileIterator(*const ffi::AVProfile);

impl Iterator for AvProfileIterator {
    type Item = AvProfile;

    fn next(&mut self) -> Option<Self::Item> {
        // Safe because the contract of `new` stipulates we have received a valid `AVCodec`
        // reference, thus the `profiles` pointer must either be NULL or point to a valid array
        // or `VAProfile`s.
        match unsafe { self.0.as_ref() } {
            None => None,
            Some(profile) => {
                match profile.profile {
                    ffi::FF_PROFILE_UNKNOWN => None,
                    _ => {
                        // Safe because we have been initialized to a static, valid profiles array
                        // which is terminated by FF_PROFILE_UNKNOWN.
                        self.0 = unsafe { self.0.offset(1) };
                        Some(AvProfile(profile))
                    }
                }
            }
        }
    }
}

#[derive(Clone, Copy)]
/// Simple wrapper over `AVPixelFormat` that provides helpful methods.
pub struct AvPixelFormat(ffi::AVPixelFormat);

impl AvPixelFormat {
    /// Return the name of this pixel format.
    pub fn name(&self) -> &'static str {
        const INVALID_FORMAT_STR: &str = "invalid pixel format";

        // Safe because `av_get_pix_fmt_name` returns either NULL or a valid C string.
        let pix_fmt_name = unsafe { ffi::av_get_pix_fmt_name(self.0) };
        // Safe because `pix_fmt_name` is a valid pointer to a C string.
        match unsafe {
            pix_fmt_name
                .as_ref()
                .and_then(|s| CStr::from_ptr(s).to_str().ok())
        } {
            None => INVALID_FORMAT_STR,
            Some(string) => string,
        }
    }

    /// Return the avcodec profile id, which can be matched against AV_PIX_FMT_*.
    ///
    /// Note that this is **not** the same as a fourcc.
    pub fn pix_fmt(&self) -> ffi::AVPixelFormat {
        self.0
    }

    /// Return the fourcc of the pixel format, or a series of zeros if its fourcc is unknown.
    pub fn fourcc(&self) -> [u8; 4] {
        // Safe because `avcodec_pix_fmt_to_codec_tag` does not take any pointer as input and
        // handles any value passed as argument.
        unsafe { ffi::avcodec_pix_fmt_to_codec_tag(self.0) }.to_le_bytes()
    }

    /// Given the width and plane index, returns the line size (data pointer increment per row) in
    /// bytes.
    pub fn line_size(&self, width: u32, plane: usize) -> Result<usize, AvError> {
        av_image_line_size(*self, width, plane)
    }

    /// Given an iterator of line sizes and height, return the size required for each plane's buffer
    /// in bytes.
    pub fn plane_sizes<I: IntoIterator<Item = u32>>(
        &self,
        linesizes: I,
        height: u32,
    ) -> Result<Vec<usize>, AvError> {
        av_image_plane_sizes(*self, linesizes, height)
    }
}

#[derive(Debug)]
pub struct FromAVPixelFormatError(());

impl TryFrom<ffi::AVPixelFormat> for AvPixelFormat {
    type Error = FromAVPixelFormatError;

    fn try_from(value: ffi::AVPixelFormat) -> Result<Self, Self::Error> {
        if value > ffi::AVPixelFormat_AV_PIX_FMT_NONE && value < ffi::AVPixelFormat_AV_PIX_FMT_NB {
            Ok(AvPixelFormat(value))
        } else {
            Err(FromAVPixelFormatError(()))
        }
    }
}

impl Display for AvPixelFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

impl Debug for AvPixelFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let fourcc = self.fourcc();
        f.write_fmt(format_args!(
            "{}{}{}{}",
            fourcc[0] as char, fourcc[1] as char, fourcc[2] as char, fourcc[3] as char
        ))
    }
}

/// Lightweight abstraction over the array of supported pixel formats for a given codec.
pub struct AvPixelFormatIterator(*const ffi::AVPixelFormat);

impl Iterator for AvPixelFormatIterator {
    type Item = AvPixelFormat;

    fn next(&mut self) -> Option<Self::Item> {
        // Safe because the contract of `AvCodec::new` and `AvCodec::pixel_format_iter` guarantees
        // that we have been built from a valid `AVCodec` reference, which `pix_fmts` pointer
        // must either be NULL or point to a valid array or `VAPixelFormat`s.
        match unsafe { self.0.as_ref() } {
            None => None,
            Some(&pixfmt) => {
                match pixfmt {
                    // Array of pixel formats is terminated by AV_PIX_FMT_NONE.
                    ffi::AVPixelFormat_AV_PIX_FMT_NONE => None,
                    _ => {
                        // Safe because we have been initialized to a static, valid profiles array
                        // which is terminated by AV_PIX_FMT_NONE.
                        self.0 = unsafe { self.0.offset(1) };
                        Some(AvPixelFormat(pixfmt))
                    }
                }
            }
        }
    }
}

/// A codec context from which decoding can be performed.
pub struct AvCodecContext(*mut ffi::AVCodecContext);

impl Drop for AvCodecContext {
    fn drop(&mut self) {
        // Safe because our context member is properly allocated and owned by us.
        // Note: `avcodec_open2` might not have been called in case we're wrapped by a
        //       `DecoderContextBuilder` but avcodec_free_context works on both opened and closed
        //       contexts.
        unsafe { ffi::avcodec_free_context(&mut self.0) };
    }
}

impl AsRef<ffi::AVCodecContext> for AvCodecContext {
    fn as_ref(&self) -> &ffi::AVCodecContext {
        // Safe because our context member is properly initialized and fully owned by us.
        unsafe { &*self.0 }
    }
}

pub enum TryReceiveResult {
    Received,
    TryAgain,
    FlushCompleted,
}

impl AvCodecContext {
    /// Internal helper for [`DecoderContextBuilder`] to initialize the context.
    fn init(&mut self, codec: *const ffi::AVCodec) -> Result<(), AvCodecOpenError> {
        // Safe because `codec` is a valid static AVCodec reference, and `self.0` is a valid
        // AVCodecContext allocation.
        if unsafe { ffi::avcodec_open2(self.0, codec, std::ptr::null_mut()) } < 0 {
            return Err(AvCodecOpenError::ContextOpen);
        }

        Ok(())
    }

    /// Send a packet to be decoded by the codec.
    ///
    /// Returns `true` if the packet has been accepted and will be decoded, `false` if the codec can
    /// not accept frames at the moment - in this case `try_receive_frame` must be called before
    /// the packet can be submitted again.
    ///
    /// Error codes are the same as those returned by `avcodec_send_packet` with the exception of
    /// EAGAIN which is converted into `Ok(false)` as it is not actually an error.
    pub fn try_send_packet(&mut self, packet: &AvPacket) -> Result<bool, AvError> {
        // Safe because the context is valid through the life of this object, and `packet`'s
        // lifetime properties ensures its memory area is readable.
        match unsafe { ffi::avcodec_send_packet(self.0, &packet.packet) } {
            AVERROR_EAGAIN => Ok(false),
            ret if ret >= 0 => Ok(true),
            err => Err(AvError(err)),
        }
    }

    /// Attempt to write a decoded frame in `frame` if the codec has enough data to do so.
    ///
    /// Returned `Received` if `frame` has been filled with the next decoded frame, `TryAgain` if
    /// no frame could be returned at that time (in which case `try_send_packet` should be called to
    /// submit more input to decode), or `FlushCompleted` to signal that a previous flush triggered
    /// by calling the `flush` method has completed.
    ///
    /// Error codes are the same as those returned by `avcodec_receive_frame` with the exception of
    /// EAGAIN and EOF which are handled as `TryAgain` and `FlushCompleted` respectively.
    pub fn try_receive_frame(&mut self, frame: &mut AvFrame) -> Result<TryReceiveResult, AvError> {
        // Safe because the context is valid through the life of this object, and `avframe` is
        // guaranteed to contain a properly initialized frame.
        match unsafe { ffi::avcodec_receive_frame(self.0, frame.0) } {
            AVERROR_EAGAIN => Ok(TryReceiveResult::TryAgain),
            AVERROR_EOF => Ok(TryReceiveResult::FlushCompleted),
            ret if ret >= 0 => Ok(TryReceiveResult::Received),
            err => Err(AvError(err)),
        }
    }

    /// Send a frame to be encoded by the codec.
    ///
    /// Returns `true` if the frame has been accepted and will be encoded, `false` if the codec can
    /// not accept input at the moment - in this case `try_receive_frame` must be called before
    /// the frame can be submitted again.
    ///
    /// Error codes are the same as those returned by `avcodec_send_frame` with the exception of
    /// EAGAIN which is converted into `Ok(false)` as it is not actually an error.
    pub fn try_send_frame(&mut self, frame: &AvFrame) -> Result<bool, AvError> {
        match unsafe { ffi::avcodec_send_frame(self.0, frame.0 as *const _) } {
            AVERROR_EAGAIN => Ok(false),
            ret if ret >= 0 => Ok(true),
            err => Err(AvError(err)),
        }
    }

    /// Attempt to write an encoded frame in `packet` if the codec has enough data to do so.
    ///
    /// Returned `Received` if `packet` has been filled with encoded data, `TryAgain` if
    /// no packet could be returned at that time (in which case `try_send_frame` should be called to
    /// submit more input to decode), or `FlushCompleted` to signal that a previous flush triggered
    /// by calling the `flush` method has completed.
    ///
    /// Error codes are the same as those returned by `avcodec_receive_packet` with the exception of
    /// EAGAIN and EOF which are handled as `TryAgain` and `FlushCompleted` respectively.
    pub fn try_receive_packet(
        &mut self,
        packet: &mut AvPacket,
    ) -> Result<TryReceiveResult, AvError> {
        // Safe because the context is valid through the life of this object, and `avframe` is
        // guaranteed to contain a properly initialized frame.
        match unsafe { ffi::avcodec_receive_packet(self.0, &mut packet.packet) } {
            AVERROR_EAGAIN => Ok(TryReceiveResult::TryAgain),
            AVERROR_EOF => Ok(TryReceiveResult::FlushCompleted),
            ret if ret >= 0 => Ok(TryReceiveResult::Received),
            err => Err(AvError(err)),
        }
    }

    /// Reset the internal codec state/flush internal buffers.
    /// Should be called e.g. when seeking or switching to a different stream.
    pub fn reset(&mut self) {
        // Safe because the context is valid through the life of this object.
        unsafe { ffi::avcodec_flush_buffers(self.0) }
    }

    /// Ask the context to start flushing, i.e. to process all pending input packets and produce
    /// frames for them.
    ///
    /// The flush process is complete when `try_receive_frame` returns `FlushCompleted`,
    pub fn flush_decoder(&mut self) -> Result<(), AvError> {
        // Safe because the context is valid through the life of this object.
        AvError::result(unsafe { ffi::avcodec_send_packet(self.0, std::ptr::null()) })
    }

    /// Ask the context to start flushing, i.e. to process all pending input frames and produce
    /// packets for them.
    ///
    /// The flush process is complete when `try_receive_packet` returns `FlushCompleted`,
    pub fn flush_encoder(&mut self) -> Result<(), AvError> {
        // Safe because the context is valid through the life of this object.
        AvError::result(unsafe { ffi::avcodec_send_frame(self.0, std::ptr::null()) })
    }

    /// Set the time base for this context.
    pub fn set_time_base(&mut self, time_base: AVRational) {
        let context = unsafe { &mut *(self.0) };
        context.time_base = time_base;
    }

    /// Set the bit rate for this context.
    pub fn set_bit_rate(&mut self, bit_rate: u64) {
        let context = unsafe { &mut *(self.0) };
        context.bit_rate = bit_rate as _;
    }

    /// Set the max bit rate (rc_max_rate) for this context.
    pub fn set_max_bit_rate(&mut self, bit_rate: u64) {
        let context = unsafe { &mut *(self.0) };
        context.rc_max_rate = bit_rate as _;
    }
}

/// Trait for types that can be used as data provider for a `AVBuffer`.
///
/// `AVBuffer` is an owned buffer type, so all the type needs to do is being able to provide a
/// stable pointer to its own data as well as its length. Implementors need to be sendable across
/// threads because avcodec is allowed to use threads in its codec implementations.
pub trait AvBufferSource: Send {
    fn as_ptr(&self) -> *const u8;
    fn as_mut_ptr(&mut self) -> *mut u8 {
        self.as_ptr() as *mut u8
    }
    fn len(&self) -> usize;
}

/// Wrapper around `AVBuffer` and `AVBufferRef`.
///
/// libavcodec can manage its own memory for input and output data. Doing so implies a transparent
/// copy of user-provided data (packets or frames) from and to this memory, which is wasteful.
///
/// This copy can be avoided by explicitly providing our own buffers to libavcodec using
/// `AVBufferRef`. Doing so means that the lifetime of these buffers becomes managed by avcodec.
/// This struct helps make this process safe by taking full ownership of an `AvBufferSource` and
/// dropping it when libavcodec is done with it.
pub struct AvBuffer(*mut ffi::AVBufferRef);

impl AvBuffer {
    /// Create a new `AvBuffer` from an `AvBufferSource`.
    ///
    /// Ownership of `source` is transferred to libavcodec, which will drop it when the number of
    /// references to this buffer reaches zero.
    ///
    /// Returns `None` if the buffer could not be created due to an error in libavcodec.
    pub fn new<D: AvBufferSource + 'static>(source: D) -> Option<Self> {
        // Move storage to the heap so we find it at the same place in `avbuffer_free`
        let mut storage = Box::new(source);

        extern "C" fn avbuffer_free<D>(opaque: *mut c_void, _data: *mut u8) {
            // Safe because `opaque` has been created from `Box::into_raw`. `storage` will be
            // dropped immediately which will release any resources held by the storage.
            let _ = unsafe { Box::from_raw(opaque as *mut D) };
        }

        // Safe because storage points to valid data throughout the lifetime of AVBuffer and we are
        // checking the return value against NULL, which signals an error.
        Some(Self(unsafe {
            ffi::av_buffer_create(
                storage.as_mut_ptr(),
                storage.len(),
                Some(avbuffer_free::<D>),
                Box::into_raw(storage) as *mut c_void,
                0,
            )
            .as_mut()?
        }))
    }

    /// Return a slice to the data contained in this buffer.
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        // Safe because the data has been initialized from valid storage in the constructor.
        unsafe { std::slice::from_raw_parts_mut((*self.0).data, (*self.0).size) }
    }

    /// Consumes the `AVBuffer`, returning a `AVBufferRef` that can be used in `AVFrame`, `AVPacket`
    /// and others.
    ///
    /// After calling, the caller is responsible for unref-ing the returned AVBufferRef, either
    /// directly or through one of the automatic management facilities in `AVFrame`, `AVPacket` or
    /// others.
    pub fn into_raw(self) -> *mut ffi::AVBufferRef {
        ManuallyDrop::new(self).0
    }
}

impl Drop for AvBuffer {
    fn drop(&mut self) {
        // Safe because `self.0` is a valid pointer to an AVBufferRef.
        unsafe { ffi::av_buffer_unref(&mut self.0) };
    }
}

/// An encoded input packet that can be submitted to `AvCodecContext::try_send_packet`.
pub struct AvPacket<'a> {
    packet: ffi::AVPacket,
    _buffer_data: PhantomData<&'a ()>,
}

impl<'a> Drop for AvPacket<'a> {
    fn drop(&mut self) {
        // Safe because `self.packet` is a valid `AVPacket` instance.
        unsafe {
            ffi::av_packet_unref(&mut self.packet);
        }
    }
}

impl<'a> AsRef<ffi::AVPacket> for AvPacket<'a> {
    fn as_ref(&self) -> &ffi::AVPacket {
        &self.packet
    }
}

impl<'a> AvPacket<'a> {
    /// Create an empty AvPacket without buffers.
    ///
    /// This packet should be only used with an encoder; in which case the encoder will
    /// automatically allocate a buffer of appropriate size and store it inside this `AvPacket`.
    pub fn empty() -> Self {
        Self {
            packet: ffi::AVPacket {
                pts: AV_NOPTS_VALUE as i64,
                dts: AV_NOPTS_VALUE as i64,
                pos: -1,
                // Safe because all the other elements of this struct can be zeroed.
                ..unsafe { std::mem::zeroed() }
            },
            _buffer_data: PhantomData,
        }
    }

    /// Create a new AvPacket that borrows the `input_data`.
    ///
    /// The returned `AvPacket` will hold a reference to `input_data`, meaning that libavcodec might
    /// perform a copy from/to it.
    pub fn new<T: AvBufferSource>(pts: i64, input_data: &'a mut T) -> Self {
        Self {
            packet: ffi::AVPacket {
                buf: std::ptr::null_mut(),
                pts,
                dts: AV_NOPTS_VALUE as i64,
                data: input_data.as_mut_ptr(),
                size: input_data.len() as c_int,
                side_data: std::ptr::null_mut(),
                pos: -1,
                // Safe because all the other elements of this struct can be zeroed.
                ..unsafe { std::mem::zeroed() }
            },
            _buffer_data: PhantomData,
        }
    }

    /// Create a new AvPacket that owns the `av_buffer`.
    ///
    /// The returned `AvPacket` will have a `'static` lifetime and will keep `input_data` alive for
    /// as long as libavcodec needs it.
    pub fn new_owned(pts: i64, mut av_buffer: AvBuffer) -> Self {
        let data_slice = av_buffer.as_mut_slice();
        let data = data_slice.as_mut_ptr();
        let size = data_slice.len() as i32;

        Self {
            packet: ffi::AVPacket {
                buf: av_buffer.into_raw(),
                pts,
                dts: AV_NOPTS_VALUE as i64,
                data,
                size,
                side_data: std::ptr::null_mut(),
                pos: -1,
                // Safe because all the other elements of this struct can be zeroed.
                ..unsafe { std::mem::zeroed() }
            },
            _buffer_data: PhantomData,
        }
    }
}

/// An owned AVFrame, i.e. one decoded frame from libavcodec that can be converted into a
/// destination buffer.
pub struct AvFrame(*mut ffi::AVFrame);

/// A builder for AVFrame that allows specifying buffers and image metadata.
pub struct AvFrameBuilder(AvFrame);

/// A descriptor describing a subslice of `buffers` in [`AvFrameBuilder::build_owned`] that
/// represents a plane's image data.
pub struct PlaneDescriptor {
    /// The index within `buffers`.
    pub buffer_index: usize,
    /// The offset from the start of `buffers[buffer_index]`.
    pub offset: usize,
    /// The increment of data pointer in bytes per row of the plane.
    pub stride: usize,
}

#[derive(Debug, ThisError)]
pub enum AvFrameError {
    #[error("failed to allocate AVFrame object")]
    FrameAllocationFailed,
    #[error("dimension is negative or too large")]
    DimensionOverflow,
    #[error("a row does not fit in the specified stride")]
    InvalidStride,
    #[error("buffer index out of range")]
    BufferOutOfRange,
    #[error("specified dimensions overflow the buffer size")]
    BufferTooSmall,
    #[error("plane reference to buffer alias each other")]
    BufferAlias,
    #[error("error while calling libavcodec")]
    AvError(#[from] AvError),
}

impl AvFrame {
    /// Create a new AvFrame. The frame's parameters and backing memory will be assigned when it is
    /// decoded into.
    pub fn new() -> Result<Self, AvFrameError> {
        Ok(Self(
            // Safe because `av_frame_alloc` does not take any input.
            unsafe { ffi::av_frame_alloc().as_mut() }.ok_or(AvFrameError::FrameAllocationFailed)?,
        ))
    }

    /// Create a new AvFrame builder that allows setting the frame's parameters and backing memory
    /// through its methods.
    pub fn builder() -> Result<AvFrameBuilder, AvFrameError> {
        AvFrame::new().map(AvFrameBuilder)
    }

    /// Return the frame's width and height.
    pub fn dimensions(&self) -> Dimensions {
        Dimensions {
            width: self.as_ref().width as _,
            height: self.as_ref().height as _,
        }
    }

    /// Return the frame's pixel format.
    pub fn format(&self) -> AvPixelFormat {
        AvPixelFormat(self.as_ref().format)
    }

    /// Set the picture type (I-frame, P-frame etc.) on this frame.
    pub fn set_pict_type(&mut self, ty: AVPictureType) {
        // Safe because self.0 is a valid AVFrame reference.
        unsafe {
            (*self.0).pict_type = ty;
        }
    }

    /// Set the presentation timestamp (PTS) of this frame.
    pub fn set_pts(&mut self, ts: i64) {
        // Safe because self.0 is a valid AVFrame reference.
        unsafe {
            (*self.0).pts = ts;
        }
    }

    /// Query if this AvFrame is writable, i.e. it is refcounted and the refcounts are 1.
    pub fn is_writable(&self) -> bool {
        // Safe because self.0 is a valid AVFrame reference.
        unsafe { ffi::av_frame_is_writable(self.0) != 0 }
    }

    /// If the frame is not writable already (see [`is_writable`]), make a copy of its buffer to
    /// make it writable.
    ///
    /// [`is_writable`]: AvFrame::is_writable
    pub fn make_writable(&mut self) -> Result<(), AvFrameError> {
        // Safe because self.0 is a valid AVFrame reference.
        AvError::result(unsafe { ffi::av_frame_make_writable(self.0) }).map_err(Into::into)
    }
}

impl AvFrameBuilder {
    /// Set the frame's width and height.
    ///
    /// The dimensions must not be greater than `i32::MAX`.
    pub fn set_dimensions(&mut self, dimensions: Dimensions) -> Result<(), AvFrameError> {
        // Safe because self.0 is a valid AVFrame instance and width and height are in range.
        unsafe {
            (*self.0 .0).width = dimensions
                .width
                .try_into()
                .map_err(|_| AvFrameError::DimensionOverflow)?;
            (*self.0 .0).height = dimensions
                .height
                .try_into()
                .map_err(|_| AvFrameError::DimensionOverflow)?;
        }
        Ok(())
    }

    /// Set the frame's format.
    pub fn set_format(&mut self, format: AvPixelFormat) -> Result<(), AvFrameError> {
        // Safe because self.0 is a valid AVFrame instance and format is a valid pixel format.
        unsafe {
            (*self.0 .0).format = format.pix_fmt();
        }
        Ok(())
    }

    /// Build an AvFrame from iterators of [`AvBuffer`]s and subslice of buffers describing the
    /// planes.
    ///
    /// The frame will own the `buffers`.
    ///
    /// This function checks that:
    /// - Each plane fits inside the bounds of the associated buffer.
    /// - Different planes do not overlap each other's buffer slice.
    ///   In this check, all planes are assumed to be potentially mutable, regardless of whether
    ///   the AvFrame is actually used for read or write access. Aliasing reference to the same
    ///   buffer will be rejected, since it can potentially allow routines to overwrite each
    //    other's result.
    ///   An exception to this is when the same buffer is passed multiple times in `buffers`. In
    ///   this case, each buffer is treated as a different buffer. Since clones have to be made to
    ///   be passed multiple times in `buffers`, the frame will not be considered [writable]. Hence
    ///   aliasing is safe in this case, but the caller is required to explicit opt-in to this
    ///   read-only handling by passing clones of the buffer into `buffers` and have a different
    ///   buffer index for each plane combination that could overlap in their range.
    ///
    /// [writable]: AvFrame::is_writable
    pub fn build_owned<
        BI: IntoIterator<Item = AvBuffer>,
        PI: IntoIterator<Item = PlaneDescriptor>,
    >(
        mut self,
        buffers: BI,
        planes: PI,
    ) -> Result<AvFrame, AvFrameError> {
        let mut buffers: Vec<_> = buffers.into_iter().collect();
        let planes: Vec<_> = planes.into_iter().collect();
        let format = self.0.format();
        let plane_sizes = format.plane_sizes(
            planes.iter().map(|x| x.stride as u32),
            self.0.dimensions().height,
        )?;
        let mut ranges = vec![];

        for (
            plane,
            PlaneDescriptor {
                buffer_index,
                offset,
                stride,
            },
        ) in planes.into_iter().enumerate()
        {
            if buffer_index > buffers.len() {
                return Err(AvFrameError::BufferOutOfRange);
            }
            let end = offset + plane_sizes[plane];
            if end > buffers[buffer_index].as_mut_slice().len() {
                return Err(AvFrameError::BufferTooSmall);
            }
            if stride < format.line_size(self.0.dimensions().width, plane)? {
                return Err(AvFrameError::InvalidStride);
            }
            unsafe {
                (*self.0 .0).data[plane] =
                    buffers[buffer_index].as_mut_slice()[offset..].as_mut_ptr();
                (*self.0 .0).linesize[plane] = stride as c_int;
            }
            ranges.push((buffer_index, offset, end));
        }

        // Check for range overlaps.
        // See function documentation for the exact rule and reasoning.
        ranges.sort_unstable();
        for pair in ranges.windows(2) {
            // (buffer_index, start, end)
            let (b0, _s0, e0) = pair[0];
            let (b1, s1, _e1) = pair[1];

            if b0 != b1 {
                continue;
            }
            // Note that s0 <= s1 always holds, so we only need to check
            // that the start of the second range is before the end of the first range.
            if s1 < e0 {
                return Err(AvFrameError::BufferAlias);
            }
        }

        for (i, buf) in buffers.into_iter().enumerate() {
            // Safe because self.0 is a valid AVFrame instance and buffers contains valid AvBuffers.
            unsafe {
                (*self.0 .0).buf[i] = buf.into_raw();
            }
        }
        Ok(self.0)
    }
}

impl AsRef<ffi::AVFrame> for AvFrame {
    fn as_ref(&self) -> &ffi::AVFrame {
        // Safe because the AVFrame has been properly initialized during construction.
        unsafe { &*self.0 }
    }
}

impl Deref for AvFrame {
    type Target = ffi::AVFrame;

    fn deref(&self) -> &Self::Target {
        // Safe because the AVFrame has been properly initialized during construction.
        unsafe { self.0.as_ref().unwrap() }
    }
}

impl Drop for AvFrame {
    fn drop(&mut self) {
        // Safe because the AVFrame is valid through the life of this object and fully owned by us.
        unsafe { ffi::av_frame_free(&mut self.0) };
    }
}

#[cfg(test)]
mod tests {
    use std::ptr;
    use std::sync::atomic::AtomicBool;
    use std::sync::atomic::Ordering;
    use std::sync::Arc;

    use super::*;

    #[test]
    fn test_averror() {
        // Just test that the error is wrapper properly. The bindings test module already checks
        // that the error bindings correspond to the right ffmpeg errors.
        let averror = AvError(AVERROR_EOF);
        let msg = format!("{}", averror);
        assert_eq!(msg, "End of file");

        let averror = AvError(0);
        let msg = format!("{}", averror);
        assert_eq!(msg, "Success");

        let averror = AvError(10);
        let msg = format!("{}", averror);
        assert_eq!(msg, "Unknown avcodec error 10");
    }

    // Test that the AVPacket wrapper frees the owned AVBuffer on drop.
    #[test]
    fn test_avpacket_drop() {
        struct DropTestBufferSource {
            dropped: Arc<AtomicBool>,
        }
        impl Drop for DropTestBufferSource {
            fn drop(&mut self) {
                self.dropped.store(true, Ordering::SeqCst);
            }
        }
        impl AvBufferSource for DropTestBufferSource {
            fn as_ptr(&self) -> *const u8 {
                ptr::null()
            }

            fn len(&self) -> usize {
                0
            }
        }

        let dropped = Arc::new(AtomicBool::new(false));

        let pkt = AvPacket::new_owned(
            0,
            AvBuffer::new(DropTestBufferSource {
                dropped: dropped.clone(),
            })
            .unwrap(),
        );
        assert!(!dropped.load(Ordering::SeqCst));
        drop(pkt);
        assert!(dropped.load(Ordering::SeqCst));
    }
}
