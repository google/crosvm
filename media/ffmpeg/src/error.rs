// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use libc::c_int;

// Equivalent of FFmpeg's `FFERRTAG` macro to generate error codes.
#[allow(non_snake_case)]
const fn FFERRTAG(tag: &[u8; 4]) -> c_int {
    -(tag[0] as c_int | (tag[1] as c_int) << 8 | (tag[2] as c_int) << 16 | (tag[3] as c_int) << 24)
}

pub const AVERROR_EOF: c_int = FFERRTAG(b"EOF ");
pub const AVERROR_INVALIDDATA: c_int = FFERRTAG(b"INDA");
pub const AVERROR_EAGAIN: c_int = -11;

#[cfg(test)]
mod test {
    use libc::c_char;

    use super::*;
    use crate::ffi;

    fn test_averror(averror: c_int, expected_message: &str) {
        let mut buffer = [0u8; 255];
        let ret = unsafe {
            ffi::av_strerror(
                averror,
                buffer.as_mut_ptr() as *mut c_char,
                buffer.len() as usize,
            )
        };
        assert_eq!(ret, 0);

        let end_of_string = buffer.iter().position(|i| *i == 0).unwrap_or(buffer.len());
        let error_string = std::str::from_utf8(&buffer[0..end_of_string]).unwrap();
        assert_eq!(error_string, expected_message);
    }

    #[test]
    // Check that we got our error bindings correctly.
    fn test_error_bindings() {
        test_averror(AVERROR_EOF, "End of file");
        test_averror(
            AVERROR_INVALIDDATA,
            "Invalid data found when processing input",
        );
        test_averror(AVERROR_EAGAIN, "Resource temporarily unavailable");
    }
}
