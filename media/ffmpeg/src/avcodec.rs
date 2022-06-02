// Copyright 2022 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! This module implements a lightweight and safe decoder interface over `libavcodec`. It is
//! designed to concentrate all calls to unsafe methods in one place, while providing the same
//! low-level access as the libavcodec functions do.

use std::{ffi::CStr, fmt::Display, marker::PhantomData, ops::Deref};

use base::MappedRegion;
use libc::{c_char, c_int};
use thiserror::Error as ThisError;

use super::*;

/// An error returned by a low-level libavcodec function.
#[derive(Debug, ThisError)]
pub struct AvError(pub libc::c_int);

impl Display for AvError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut buffer = [0u8; 255];
        // Safe because we are passing valid bounds for the buffer.
        let ret = unsafe {
            ffi::av_strerror(
                self.0,
                buffer.as_mut_ptr() as *mut c_char,
                buffer.len() as ffi::size_t,
            )
        };
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
}

impl AvCodec {
    /// Returns whether the codec is a decoder codec.
    pub fn is_decoder(&self) -> bool {
        // Safe because `av_codec_is_decoder` is called on a valid static `AVCodec` reference.
        (unsafe { ffi::av_codec_is_decoder(self.0) } != 0)
    }

    /// Returns the name of the codec.
    pub fn name(&self) -> Option<&'static str> {
        // Safe because `CStr::from_ptr` is called on a valid zero-terminated C string.
        match unsafe { CStr::from_ptr(self.0.name).to_str() } {
            Ok(name) => Some(name),
            Err(_) => None,
        }
    }

    /// Returns the capabilities of the codec, as a mask of AV_CODEC_CAP_* bits.
    pub fn capabilities(&self) -> u32 {
        self.0.capabilities as u32
    }

    /// Returns an iterator over the profiles supported by this codec.
    pub fn profile_iter(&self) -> AvProfileIterator {
        AvProfileIterator(self.0.profiles)
    }

    /// Obtain a context that can be used to decode using this codec.
    ///
    /// `get_buffer`'s first element is an optional function that decides which buffer is used to
    /// render a frame (see libavcodec's documentation for `get_buffer2` for more details). If
    /// provided, this function must be thread-safe. If none is provided, avcodec's default function
    /// is used. The second element is a pointer that will be passed as first argument to the
    /// function when it is called.
    pub fn open(
        &self,
        get_buffer: Option<(
            unsafe extern "C" fn(*mut ffi::AVCodecContext, *mut ffi::AVFrame, i32) -> i32,
            *mut libc::c_void,
        )>,
    ) -> Result<AvCodecContext, AvCodecOpenError> {
        // Safe because `self.0` is a valid static AVCodec reference.
        let mut context = unsafe { ffi::avcodec_alloc_context3(self.0).as_mut() }
            .ok_or(AvCodecOpenError::ContextAllocation)?;

        if let Some((get_buffer2, opaque)) = get_buffer {
            context.get_buffer2 = Some(get_buffer2);
            context.opaque = opaque;
            context.thread_safe_callbacks = 1;
        }

        // Safe because `self.0` is a valid static AVCodec reference, and `context` has been
        // successfully allocated above.
        if unsafe { ffi::avcodec_open2(context, self.0, std::ptr::null_mut()) } < 0 {
            return Err(AvCodecOpenError::ContextOpen);
        }

        Ok(AvCodecContext(context))
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

/// Lightweight abstraction over the array of supported profiles for a given codec.
pub struct AvProfileIterator(*const ffi::AVProfile);

impl Iterator for AvProfileIterator {
    type Item = &'static ffi::AVProfile;

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
                        Some(profile)
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
        // Safe because our context member is properly initialized, fully owned by us, and has not
        // leaked in any form.
        unsafe { ffi::avcodec_free_context(&mut self.0) };
    }
}

impl AsRef<ffi::AVCodecContext> for AvCodecContext {
    fn as_ref(&self) -> &ffi::AVCodecContext {
        // Safe because our context member is properly initialized and fully owned by us.
        unsafe { &*self.0 }
    }
}

pub enum TryReceiveFrameResult {
    Received,
    TryAgain,
    FlushCompleted,
}

impl AvCodecContext {
    /// Send a packet to be decoded to the codec.
    ///
    /// Returns `true` if the packet has been accepted and will be decoded, `false` if the codec can
    /// not accept frames at the moment - in this case `try_receive_frame` must be called before
    /// the packet can be submitted again.
    ///
    /// Error codes are the same as those returned by `avcodec_send_packet` with the exception of
    /// EAGAIN which is converted into `Ok(false)` as it is not actually an error.
    pub fn try_send_packet<'a, T: MappedRegion>(
        &mut self,
        packet: &AvPacket<'a, T>,
    ) -> Result<bool, AvError> {
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
    /// Error codes are the same as those returned by `avcodec_receive_frame`.
    pub fn try_receive_frame(
        &mut self,
        frame: &mut AvFrame,
    ) -> Result<TryReceiveFrameResult, AvError> {
        // Safe because the context is valid through the life of this object, and `avframe` is
        // guaranteed to contain a properly initialized frame.
        match unsafe { ffi::avcodec_receive_frame(self.0, frame.as_mut()) } {
            AVERROR_EAGAIN => Ok(TryReceiveFrameResult::TryAgain),
            AVERROR_EOF => Ok(TryReceiveFrameResult::FlushCompleted),
            ret if ret >= 0 => Ok(TryReceiveFrameResult::Received),
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
    pub fn flush(&mut self) -> Result<(), AvError> {
        // Safe because the context is valid through the life of this object.
        match unsafe { ffi::avcodec_send_packet(self.0, std::ptr::null()) } {
            ret if ret >= 0 => Ok(()),
            err => Err(AvError(err)),
        }
    }
}

/// An encoded input packet that can be submitted to `AvCodecContext::try_send_packet`.
pub struct AvPacket<'a, T: MappedRegion> {
    packet: ffi::AVPacket,
    _phantom: PhantomData<&'a T>,
}

impl<'a, T: MappedRegion> AvPacket<'a, T> {
    /// Create a new AvPacket.
    ///
    /// `input_data` is the encoded data we want to send to the codec for decoding. The data is not
    /// copied by the AvPacket itself, however a copy may happen when the packet is submitted.
    pub fn new(pts: i64, input_data: &'a T) -> Self {
        Self {
            packet: ffi::AVPacket {
                buf: std::ptr::null_mut(),
                pts,
                dts: AV_NOPTS_VALUE as i64,
                data: input_data.as_ptr(),
                size: input_data.size() as c_int,
                side_data: std::ptr::null_mut(),
                pos: -1,
                // Safe because all the other elements of this struct can be zeroed.
                ..unsafe { std::mem::zeroed() }
            },
            _phantom: PhantomData,
        }
    }
}

/// An owned AVFrame, i.e. one decoded frame from libavcodec that can be converted into a
/// destination buffer.
pub struct AvFrame(*mut ffi::AVFrame);

#[derive(Debug, ThisError)]
pub enum AvFrameError {
    #[error("failed to allocate AVFrame object")]
    FrameAllocationFailed,
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
}

impl AsRef<ffi::AVFrame> for AvFrame {
    fn as_ref(&self) -> &ffi::AVFrame {
        // Safe because the AVFrame has been properly initialized during construction.
        unsafe { &*self.0 }
    }
}

impl AsMut<ffi::AVFrame> for AvFrame {
    fn as_mut(&mut self) -> &mut ffi::AVFrame {
        // Safe because the AVFrame has been properly initialized during construction.
        unsafe { &mut *self.0 }
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
}
