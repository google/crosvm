// Copyright 2022 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

/// Trait that can be used to associate events with arbitrary enums when using
/// EventContext.
///
/// Simple enums that have no or primitive variant data data can use the `#[derive(PollToken)]`
/// custom derive to implement this trait. See
/// [poll_token_derive::poll_token](../poll_token_derive/fn.poll_token.html) for details.
pub trait PollToken {
    /// Converts this token into a u64 that can be turned back into a token via `from_raw_token`.
    fn as_raw_token(&self) -> u64;

    /// Converts a raw token as returned from `as_raw_token` back into a token.
    ///
    /// It is invalid to give a raw token that was not returned via `as_raw_token` from the same
    /// `Self`. The implementation can expect that this will never happen as a result of its usage
    /// in `EventContext`.
    fn from_raw_token(data: u64) -> Self;
}

impl PollToken for usize {
    fn as_raw_token(&self) -> u64 {
        *self as u64
    }

    fn from_raw_token(data: u64) -> Self {
        data as Self
    }
}

impl PollToken for u64 {
    fn as_raw_token(&self) -> u64 {
        *self as u64
    }

    fn from_raw_token(data: u64) -> Self {
        data as Self
    }
}

impl PollToken for u32 {
    fn as_raw_token(&self) -> u64 {
        u64::from(*self)
    }

    fn from_raw_token(data: u64) -> Self {
        data as Self
    }
}

impl PollToken for u16 {
    fn as_raw_token(&self) -> u64 {
        u64::from(*self)
    }

    fn from_raw_token(data: u64) -> Self {
        data as Self
    }
}

impl PollToken for u8 {
    fn as_raw_token(&self) -> u64 {
        u64::from(*self)
    }

    fn from_raw_token(data: u64) -> Self {
        data as Self
    }
}

impl PollToken for () {
    fn as_raw_token(&self) -> u64 {
        0
    }

    fn from_raw_token(_data: u64) -> Self {}
}

#[cfg(test)]
mod tests {
    use super::*;
    use base_poll_token_derive::PollToken;

    #[test]
    #[allow(dead_code)]
    fn poll_token_derive() {
        #[derive(PollToken)]
        enum EmptyToken {}

        #[derive(PartialEq, Debug, PollToken)]
        enum Token {
            Alpha,
            Beta,
            // comments
            Gamma(u32),
            Delta { index: usize },
            Omega,
        }

        assert_eq!(
            Token::from_raw_token(Token::Alpha.as_raw_token()),
            Token::Alpha
        );
        assert_eq!(
            Token::from_raw_token(Token::Beta.as_raw_token()),
            Token::Beta
        );
        assert_eq!(
            Token::from_raw_token(Token::Gamma(55).as_raw_token()),
            Token::Gamma(55)
        );
        assert_eq!(
            Token::from_raw_token(Token::Delta { index: 100 }.as_raw_token()),
            Token::Delta { index: 100 }
        );
        assert_eq!(
            Token::from_raw_token(Token::Omega.as_raw_token()),
            Token::Omega
        );
    }
}
