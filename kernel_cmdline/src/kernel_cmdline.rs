// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Helper for creating valid kernel command line strings.

use std::result;

use remain::sorted;
use thiserror::Error;

/// The error type for command line building operations.
#[sorted]
#[derive(Error, PartialEq, Eq, Debug)]
pub enum Error {
    /// Key/Value Operation would have had an equals sign in it.
    #[error("string contains an equals sign")]
    HasEquals,
    /// Key/Value Operation would have had a space in it.
    #[error("string contains a space")]
    HasSpace,
    /// Operation would have resulted in a non-printable ASCII character.
    #[error("string contains non-printable ASCII character")]
    InvalidAscii,
    /// Operation would have made the command line too large.
    #[error("command line length {0} exceeds maximum {1}")]
    TooLarge(usize, usize),
}

/// Specialized Result type for command line operations.
pub type Result<T> = result::Result<T, Error>;

fn valid_char(c: char) -> bool {
    matches!(c, ' '..='~')
}

fn valid_str(s: &str) -> Result<()> {
    if s.chars().all(valid_char) {
        Ok(())
    } else {
        Err(Error::InvalidAscii)
    }
}

fn valid_element(s: &str) -> Result<()> {
    if !s.chars().all(valid_char) {
        Err(Error::InvalidAscii)
    } else if s.contains(' ') {
        Err(Error::HasSpace)
    } else if s.contains('=') {
        Err(Error::HasEquals)
    } else {
        Ok(())
    }
}

/// A builder for a kernel command line string that validates the string as it is built.
#[derive(Default)]
pub struct Cmdline {
    line: String,
}

impl Cmdline {
    /// Constructs an empty Cmdline.
    pub fn new() -> Cmdline {
        Cmdline::default()
    }

    fn push_space_if_needed(&mut self) {
        if !self.line.is_empty() {
            self.line.push(' ');
        }
    }

    /// Validates and inserts a key value pair into this command line
    pub fn insert<T: AsRef<str>>(&mut self, key: T, val: T) -> Result<()> {
        let k = key.as_ref();
        let v = val.as_ref();

        valid_element(k)?;
        valid_element(v)?;

        self.push_space_if_needed();
        self.line.push_str(k);
        self.line.push('=');
        self.line.push_str(v);

        Ok(())
    }

    /// Validates and inserts a string to the end of the current command line
    pub fn insert_str<T: AsRef<str>>(&mut self, slug: T) -> Result<()> {
        let s = slug.as_ref();
        valid_str(s)?;

        self.push_space_if_needed();
        self.line.push_str(s);

        Ok(())
    }

    /// Returns the cmdline in progress without nul termination
    pub fn as_str(&self) -> &str {
        self.line.as_str()
    }

    /// Returns the current command line as a string with a maximum length.
    ///
    /// # Arguments
    ///
    /// `max_len`: maximum number of bytes (not including NUL terminator)
    pub fn as_str_with_max_len(&self, max_len: usize) -> Result<&str> {
        let s = self.line.as_str();
        if s.len() <= max_len {
            Ok(s)
        } else {
            Err(Error::TooLarge(s.len(), max_len))
        }
    }

    /// Converts the command line into a `Vec<u8>` with a maximum length.
    ///
    /// # Arguments
    ///
    /// `max_len`: maximum number of bytes (not including NUL terminator)
    pub fn into_bytes_with_max_len(self, max_len: usize) -> Result<Vec<u8>> {
        let bytes: Vec<u8> = self.line.into_bytes();
        if bytes.len() <= max_len {
            Ok(bytes)
        } else {
            Err(Error::TooLarge(bytes.len(), max_len))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn insert_hello_world() {
        let mut cl = Cmdline::new();
        assert_eq!(cl.as_str(), "");
        assert!(cl.insert("hello", "world").is_ok());
        assert_eq!(cl.as_str(), "hello=world");

        let bytes = cl
            .into_bytes_with_max_len(100)
            .expect("failed to convert Cmdline into bytes");
        assert_eq!(bytes, b"hello=world");
    }

    #[test]
    fn insert_multi() {
        let mut cl = Cmdline::new();
        assert!(cl.insert("hello", "world").is_ok());
        assert!(cl.insert("foo", "bar").is_ok());
        assert_eq!(cl.as_str(), "hello=world foo=bar");
    }

    #[test]
    fn insert_space() {
        let mut cl = Cmdline::new();
        assert_eq!(cl.insert("a ", "b"), Err(Error::HasSpace));
        assert_eq!(cl.insert("a", "b "), Err(Error::HasSpace));
        assert_eq!(cl.insert("a ", "b "), Err(Error::HasSpace));
        assert_eq!(cl.insert(" a", "b"), Err(Error::HasSpace));
        assert_eq!(cl.as_str(), "");
    }

    #[test]
    fn insert_equals() {
        let mut cl = Cmdline::new();
        assert_eq!(cl.insert("a=", "b"), Err(Error::HasEquals));
        assert_eq!(cl.insert("a", "b="), Err(Error::HasEquals));
        assert_eq!(cl.insert("a=", "b "), Err(Error::HasEquals));
        assert_eq!(cl.insert("=a", "b"), Err(Error::HasEquals));
        assert_eq!(cl.insert("a", "=b"), Err(Error::HasEquals));
        assert_eq!(cl.as_str(), "");
    }

    #[test]
    fn insert_emoji() {
        let mut cl = Cmdline::new();
        assert_eq!(cl.insert("heart", "💖"), Err(Error::InvalidAscii));
        assert_eq!(cl.insert("💖", "love"), Err(Error::InvalidAscii));
        assert_eq!(cl.as_str(), "");
    }

    #[test]
    fn insert_string() {
        let mut cl = Cmdline::new();
        assert_eq!(cl.as_str(), "");
        assert!(cl.insert_str("noapic").is_ok());
        assert_eq!(cl.as_str(), "noapic");
        assert!(cl.insert_str("nopci").is_ok());
        assert_eq!(cl.as_str(), "noapic nopci");
    }

    #[test]
    fn as_str_too_large() {
        let mut cl = Cmdline::new();
        assert!(cl.insert("a", "b").is_ok()); // start off with 3.
        assert_eq!(cl.as_str(), "a=b");
        assert_eq!(cl.as_str_with_max_len(2), Err(Error::TooLarge(3, 2)));
        assert_eq!(cl.as_str_with_max_len(3), Ok("a=b"));

        let mut cl = Cmdline::new();
        assert!(cl.insert("ab", "ba").is_ok()); // adds 5 length
        assert!(cl.insert("c", "d").is_ok()); // adds 4 (including space) length
        assert_eq!(cl.as_str(), "ab=ba c=d");
        assert_eq!(cl.as_str_with_max_len(8), Err(Error::TooLarge(9, 8)));
        assert_eq!(cl.as_str_with_max_len(9), Ok("ab=ba c=d"));

        let mut cl = Cmdline::new();
        assert!(cl.insert("ab", "ba").is_ok()); // adds 5 length
        assert!(cl.insert_str("123").is_ok()); // adds 4 (including space) length
        assert_eq!(cl.as_str(), "ab=ba 123");
        assert_eq!(cl.as_str_with_max_len(8), Err(Error::TooLarge(9, 8)));
        assert_eq!(cl.as_str_with_max_len(9), Ok("ab=ba 123"));
    }
}
