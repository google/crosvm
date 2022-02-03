// Copyright 2022 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::borrow::Cow;
use std::fmt::{self, Debug, Display};
use std::num::{IntErrorKind, ParseIntError};
use std::str::FromStr;

use remain::sorted;
use serde::de;
use serde::Deserialize;
use thiserror::Error;

#[derive(Debug, Error, PartialEq)]
#[sorted]
#[non_exhaustive]
#[allow(missing_docs)]
/// Different kinds of errors that can be returned by the parser.
pub enum ErrorKind {
    #[error("unexpected end of input")]
    Eof,
    #[error("expected a boolean")]
    ExpectedBoolean,
    #[error("expected ','")]
    ExpectedComma,
    #[error("expected '='")]
    ExpectedEqual,
    #[error("expected an identifier")]
    ExpectedIdentifier,
    #[error("expected a number")]
    ExpectedNumber,
    #[error("expected a string")]
    ExpectedString,
    #[error("\" and ' can only be used in quoted strings")]
    InvalidCharInString,
    #[error("non-terminated string")]
    NonTerminatedString,
    #[error("provided number does not fit in the destination type")]
    NumberOverflow,
    #[error("serde error: {0}")]
    SerdeError(String),
    #[error("remaining characters in input")]
    TrailingCharacters,
}

/// Error that may be thown while parsing a key-values string.
#[derive(Debug, Error, PartialEq)]
pub struct ParseError {
    /// Detailed error that occurred.
    pub kind: ErrorKind,
    /// Index of the error in the input string.
    pub pos: usize,
}

impl Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.kind {
            ErrorKind::SerdeError(s) => write!(f, "{}", s),
            _ => write!(f, "{} at position {}", self.kind, self.pos),
        }
    }
}

impl de::Error for ParseError {
    fn custom<T>(msg: T) -> Self
    where
        T: fmt::Display,
    {
        Self {
            kind: ErrorKind::SerdeError(msg.to_string()),
            pos: 0,
        }
    }
}

type Result<T> = std::result::Result<T, ParseError>;

/// Serde deserializer for key-values strings.
struct KeyValueDeserializer<'de> {
    /// Full input originally received for parsing.
    original_input: &'de str,
    /// Input currently remaining to parse.
    input: &'de str,
    /// If set, then `deserialize_identifier` will take and return its content the next time it is
    /// called instead of trying to parse an identifier from the input. This is needed to allow the
    /// name of the first field of a struct to be omitted, e.g.
    ///
    ///   --block "/path/to/disk.img,ro=true"
    ///
    /// instead of
    ///
    ///   --block "path=/path/to/disk.img,ro=true"
    next_identifier: Option<&'de str>,
}

impl<'de> From<&'de str> for KeyValueDeserializer<'de> {
    fn from(input: &'de str) -> Self {
        Self {
            original_input: input,
            input,
            next_identifier: None,
        }
    }
}

impl<'de> KeyValueDeserializer<'de> {
    /// Return an `kind` error for the current position of the input.
    fn error_here(&self, kind: ErrorKind) -> ParseError {
        ParseError {
            kind,
            pos: self.original_input.len() - self.input.len(),
        }
    }

    /// Returns the next char in the input string without consuming it, or None
    /// if we reached the end of input.
    fn peek_char(&self) -> Option<char> {
        self.input.chars().next()
    }

    /// Skip the next char in the input string.
    fn skip_char(&mut self) {
        let _ = self.next_char();
    }

    /// Returns the next char in the input string and consume it, or returns
    /// None if we reached the end of input.
    fn next_char(&mut self) -> Option<char> {
        let c = self.peek_char()?;
        self.input = &self.input[c.len_utf8()..];
        Some(c)
    }

    /// Try to peek the next element in the input as an identifier, without consuming it.
    ///
    /// Returns the parsed indentifier, an `ExpectedIdentifier` error if the next element is not
    /// an identifier, or `Eof` if we were at the end of the input string.
    fn peek_identifier(&self) -> Result<&'de str> {
        // End of input?
        if self.input.is_empty() {
            return Err(self.error_here(ErrorKind::Eof));
        }

        let res = self.input;
        let mut len = 0;
        let mut iter = self.input.chars();
        loop {
            match iter.next() {
                None | Some(',' | '=') => break,
                Some(c) if c.is_ascii_alphanumeric() || c == '_' || (c == '-' && len > 0) => {
                    len += c.len_utf8();
                }
                Some(_) => return Err(self.error_here(ErrorKind::ExpectedIdentifier)),
            }
        }

        // An identifier cannot be empty.
        if len == 0 {
            Err(self.error_here(ErrorKind::ExpectedIdentifier))
        } else {
            Ok(&res[0..len])
        }
    }

    /// Peek the next value, i.e. anything until the next comma or the end of the input string.
    ///
    /// This can be used to reliably peek any value, except strings which may contain commas in
    /// quotes.
    fn peek_value(&self) -> Result<&'de str> {
        let res = self.input;
        let mut len = 0;
        let mut iter = self.input.chars();
        loop {
            match iter.next() {
                None | Some(',') => break,
                Some(c) => len += c.len_utf8(),
            }
        }

        if len > 0 {
            Ok(&res[0..len])
        } else {
            Err(self.error_here(ErrorKind::Eof))
        }
    }

    /// Attempts to parse an identifier, either for a key or for the value of an enum type.
    ///
    /// Usually identifiers are not allowed to start with a number, but we chose to allow this
    /// here otherwise options like "mode=2d" won't parse if "2d" is an alias for an enum variant.
    fn parse_identifier(&mut self) -> Result<&'de str> {
        let res = self.peek_identifier()?;
        self.input = &self.input[res.len()..];
        Ok(res)
    }

    /// Attempts to parse a string.
    ///
    /// A string can be quoted (using single or double quotes) or not. If it is not, we consume
    /// input until the next ',' separating character. If it is, we consume input until the next
    /// non-escaped quote.
    ///
    /// The returned value is a slice into the current input if no characters to unescape were met,
    /// or a fully owned string if we had to unescape some characters.
    fn parse_string(&mut self) -> Result<Cow<'de, str>> {
        let (s, quote) = match self.peek_char() {
            // Beginning of quoted string.
            quote @ Some('"' | '\'') => {
                // Safe because we just matched against `Some`.
                let quote = quote.unwrap();
                // Skip the opening quote.
                self.skip_char();
                let mut len = 0;
                let mut iter = self.input.chars();
                let mut escaped = false;
                loop {
                    let c = match iter.next() {
                        Some('\\') if !escaped => {
                            escaped = true;
                            '\\'
                        }
                        // Found end of quoted string if we meet a non-escaped quote.
                        Some(c) if c == quote && !escaped => break,
                        Some(c) => {
                            escaped = false;
                            c
                        }
                        None => return Err(self.error_here(ErrorKind::NonTerminatedString)),
                    };
                    len += c.len_utf8();
                }
                let s = &self.input[0..len];
                self.input = &self.input[len..];
                // Skip the closing quote
                self.skip_char();
                (s, Some(quote))
            }
            // Empty strings must use quotes.
            None | Some(',') => return Err(self.error_here(ErrorKind::ExpectedString)),
            // Non-quoted string.
            Some(_) => {
                let s = self
                    .input
                    .split(&[',', '"', '\''])
                    .next()
                    .unwrap_or(self.input);
                self.input = &self.input[s.len()..];
                // If a string was not quoted, it shall not contain a quote.
                if let Some('"' | '\'') = self.peek_char() {
                    return Err(self.error_here(ErrorKind::InvalidCharInString));
                }
                (s, None)
            }
        };

        if quote.is_some() {
            let mut escaped = false;
            let unescaped_string: String = s
                .chars()
                .filter_map(|c| match c {
                    '\\' if !escaped => {
                        escaped = true;
                        None
                    }
                    c => {
                        escaped = false;
                        Some(c)
                    }
                })
                .collect();
            Ok(Cow::Owned(unescaped_string))
        } else {
            Ok(Cow::Borrowed(s))
        }
    }

    /// A boolean can be 'true', 'false', or nothing (which is equivalent to 'true').
    fn parse_bool(&mut self) -> Result<bool> {
        // 'true' and 'false' can be picked by peek_value.
        let s = match self.peek_value() {
            Ok(s) => s,
            // Consider end of input as an empty string, which will be evaluated to `true`.
            Err(ParseError {
                kind: ErrorKind::Eof,
                ..
            }) => "",
            Err(_) => return Err(self.error_here(ErrorKind::ExpectedBoolean)),
        };
        let res = match s {
            "" => Ok(true),
            s => bool::from_str(s).map_err(|_| self.error_here(ErrorKind::ExpectedBoolean)),
        };

        self.input = &self.input[s.len()..];

        res
    }

    /// Parse a positive or negative number.
    // TODO support 0x or 0b notation?
    fn parse_number<T>(&mut self) -> Result<T>
    where
        T: FromStr<Err = ParseIntError>,
    {
        let num_str = self.peek_value()?;
        let val = T::from_str(num_str).map_err(|e| {
            self.error_here(
                if let IntErrorKind::PosOverflow | IntErrorKind::NegOverflow = e.kind() {
                    ErrorKind::NumberOverflow
                } else {
                    ErrorKind::ExpectedNumber
                },
            )
        })?;
        self.input = &self.input[num_str.len()..];
        Ok(val)
    }
}

impl<'de> de::MapAccess<'de> for KeyValueDeserializer<'de> {
    type Error = ParseError;

    fn next_key_seed<K>(&mut self, seed: K) -> Result<Option<K::Value>>
    where
        K: de::DeserializeSeed<'de>,
    {
        let has_next_identifier = self.next_identifier.is_some();

        if self.peek_char().is_none() {
            return Ok(None);
        }
        let val = seed.deserialize(&mut *self).map(Some)?;

        // We just "deserialized" the content of `next_identifier`, so there should be no equal
        // character in the input. We can return now.
        if has_next_identifier {
            return Ok(val);
        }

        match self.peek_char() {
            // We expect an equal after an identifier.
            Some('=') => {
                self.skip_char();
                Ok(val)
            }
            // Ok if we are parsing a boolean where an empty value means true.
            Some(',') | None => Ok(val),
            Some(_) => Err(self.error_here(ErrorKind::ExpectedEqual)),
        }
    }

    fn next_value_seed<V>(&mut self, seed: V) -> Result<V::Value>
    where
        V: de::DeserializeSeed<'de>,
    {
        let val = seed.deserialize(&mut *self)?;

        // We must have a comma or end of input after a value.
        match self.next_char() {
            Some(',') | None => Ok(val),
            Some(_) => Err(self.error_here(ErrorKind::ExpectedComma)),
        }
    }
}

struct Enum<'a, 'de: 'a>(&'a mut KeyValueDeserializer<'de>);

impl<'a, 'de> Enum<'a, 'de> {
    fn new(de: &'a mut KeyValueDeserializer<'de>) -> Self {
        Self(de)
    }
}

impl<'a, 'de> de::EnumAccess<'de> for Enum<'a, 'de> {
    type Error = ParseError;
    type Variant = Self;

    fn variant_seed<V>(self, seed: V) -> Result<(V::Value, Self::Variant)>
    where
        V: de::DeserializeSeed<'de>,
    {
        let val = seed.deserialize(&mut *self.0)?;
        Ok((val, self))
    }
}

impl<'a, 'de> de::VariantAccess<'de> for Enum<'a, 'de> {
    type Error = ParseError;

    fn unit_variant(self) -> Result<()> {
        Ok(())
    }

    fn newtype_variant_seed<T>(self, _seed: T) -> Result<T::Value>
    where
        T: de::DeserializeSeed<'de>,
    {
        unimplemented!()
    }

    fn tuple_variant<V>(self, _len: usize, _visitor: V) -> Result<V::Value>
    where
        V: de::Visitor<'de>,
    {
        unimplemented!()
    }

    fn struct_variant<V>(self, _fields: &'static [&'static str], _visitor: V) -> Result<V::Value>
    where
        V: de::Visitor<'de>,
    {
        unimplemented!()
    }
}

impl<'de, 'a> de::Deserializer<'de> for &'a mut KeyValueDeserializer<'de> {
    type Error = ParseError;

    fn deserialize_any<V>(self, visitor: V) -> Result<V::Value>
    where
        V: serde::de::Visitor<'de>,
    {
        match self.peek_char() {
            Some('0'..='9') => self.deserialize_u64(visitor),
            Some('-') => self.deserialize_i64(visitor),
            Some('"') => self.deserialize_string(visitor),
            // Only possible option here is boolean flag.
            Some(',') | None => self.deserialize_bool(visitor),
            _ => {
                // We probably have an unquoted string, but possibly a boolean as well.
                match self.peek_identifier() {
                    Ok("true") | Ok("false") => self.deserialize_bool(visitor),
                    _ => self.deserialize_str(visitor),
                }
            }
        }
    }

    fn deserialize_bool<V>(self, visitor: V) -> Result<V::Value>
    where
        V: serde::de::Visitor<'de>,
    {
        visitor.visit_bool(self.parse_bool()?)
    }

    fn deserialize_i8<V>(self, visitor: V) -> Result<V::Value>
    where
        V: serde::de::Visitor<'de>,
    {
        visitor.visit_i8(self.parse_number()?)
    }

    fn deserialize_i16<V>(self, visitor: V) -> Result<V::Value>
    where
        V: serde::de::Visitor<'de>,
    {
        visitor.visit_i16(self.parse_number()?)
    }

    fn deserialize_i32<V>(self, visitor: V) -> Result<V::Value>
    where
        V: serde::de::Visitor<'de>,
    {
        visitor.visit_i32(self.parse_number()?)
    }

    fn deserialize_i64<V>(self, visitor: V) -> Result<V::Value>
    where
        V: serde::de::Visitor<'de>,
    {
        visitor.visit_i64(self.parse_number()?)
    }

    fn deserialize_u8<V>(self, visitor: V) -> Result<V::Value>
    where
        V: serde::de::Visitor<'de>,
    {
        visitor.visit_u8(self.parse_number()?)
    }

    fn deserialize_u16<V>(self, visitor: V) -> Result<V::Value>
    where
        V: serde::de::Visitor<'de>,
    {
        visitor.visit_u16(self.parse_number()?)
    }

    fn deserialize_u32<V>(self, visitor: V) -> Result<V::Value>
    where
        V: serde::de::Visitor<'de>,
    {
        visitor.visit_u32(self.parse_number()?)
    }

    fn deserialize_u64<V>(self, visitor: V) -> Result<V::Value>
    where
        V: serde::de::Visitor<'de>,
    {
        visitor.visit_u64(self.parse_number()?)
    }

    fn deserialize_f32<V>(self, _visitor: V) -> Result<V::Value>
    where
        V: serde::de::Visitor<'de>,
    {
        unimplemented!()
    }

    fn deserialize_f64<V>(self, _visitor: V) -> Result<V::Value>
    where
        V: serde::de::Visitor<'de>,
    {
        unimplemented!()
    }

    fn deserialize_char<V>(self, visitor: V) -> Result<V::Value>
    where
        V: serde::de::Visitor<'de>,
    {
        visitor.visit_char(
            self.next_char()
                .ok_or_else(|| self.error_here(ErrorKind::Eof))?,
        )
    }

    fn deserialize_str<V>(self, visitor: V) -> Result<V::Value>
    where
        V: serde::de::Visitor<'de>,
    {
        match self.parse_string()? {
            Cow::Borrowed(s) => visitor.visit_borrowed_str(s),
            Cow::Owned(s) => visitor.visit_string(s),
        }
    }

    fn deserialize_string<V>(self, visitor: V) -> Result<V::Value>
    where
        V: serde::de::Visitor<'de>,
    {
        self.deserialize_str(visitor)
    }

    fn deserialize_bytes<V>(self, _visitor: V) -> Result<V::Value>
    where
        V: serde::de::Visitor<'de>,
    {
        unimplemented!()
    }

    fn deserialize_byte_buf<V>(self, visitor: V) -> Result<V::Value>
    where
        V: serde::de::Visitor<'de>,
    {
        self.deserialize_bytes(visitor)
    }

    fn deserialize_option<V>(self, visitor: V) -> Result<V::Value>
    where
        V: serde::de::Visitor<'de>,
    {
        // The fact that an option is specified implies that is exists, hence we always visit
        // Some() here.
        visitor.visit_some(self)
    }

    fn deserialize_unit<V>(self, visitor: V) -> Result<V::Value>
    where
        V: serde::de::Visitor<'de>,
    {
        visitor.visit_unit()
    }

    fn deserialize_unit_struct<V>(self, _name: &'static str, visitor: V) -> Result<V::Value>
    where
        V: serde::de::Visitor<'de>,
    {
        self.deserialize_unit(visitor)
    }

    fn deserialize_newtype_struct<V>(self, _name: &'static str, visitor: V) -> Result<V::Value>
    where
        V: serde::de::Visitor<'de>,
    {
        visitor.visit_newtype_struct(self)
    }

    fn deserialize_seq<V>(self, _visitor: V) -> Result<V::Value>
    where
        V: serde::de::Visitor<'de>,
    {
        unimplemented!()
    }

    fn deserialize_tuple<V>(self, _len: usize, _visitor: V) -> Result<V::Value>
    where
        V: serde::de::Visitor<'de>,
    {
        unimplemented!()
    }

    fn deserialize_tuple_struct<V>(
        self,
        _name: &'static str,
        _len: usize,
        _visitor: V,
    ) -> Result<V::Value>
    where
        V: serde::de::Visitor<'de>,
    {
        unimplemented!()
    }

    fn deserialize_map<V>(self, visitor: V) -> Result<V::Value>
    where
        V: serde::de::Visitor<'de>,
    {
        visitor.visit_map(self)
    }

    fn deserialize_struct<V>(
        self,
        _name: &'static str,
        fields: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value>
    where
        V: serde::de::Visitor<'de>,
    {
        // The name of the first field of a struct can be omitted (see documentation of
        // `next_identifier` for details).
        //
        // To detect this, peek the next identifier, and check if the character following is '='. If
        // it is not, then we may have a value in first position, unless the value is identical to
        // one of the field's name - in this case, assume this is a boolean using the flag syntax.
        self.next_identifier = match self.peek_identifier() {
            Ok(s) => match self.input.chars().nth(s.chars().count()) {
                Some('=') => None,
                _ => {
                    if fields.contains(&s) {
                        None
                    } else {
                        fields.get(0).copied()
                    }
                }
            },
            // Not an identifier, probably means this is a value for the first field then.
            Err(_) => fields.get(0).copied(),
        };
        visitor.visit_map(self)
    }

    fn deserialize_enum<V>(
        self,
        _name: &'static str,
        _variants: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value>
    where
        V: serde::de::Visitor<'de>,
    {
        visitor.visit_enum(Enum::new(self))
    }

    fn deserialize_identifier<V>(self, visitor: V) -> Result<V::Value>
    where
        V: serde::de::Visitor<'de>,
    {
        let identifier = self
            .next_identifier
            .take()
            .map_or_else(|| self.parse_identifier(), Ok)?;

        visitor.visit_borrowed_str(identifier)
    }

    fn deserialize_ignored_any<V>(self, visitor: V) -> Result<V::Value>
    where
        V: serde::de::Visitor<'de>,
    {
        self.deserialize_any(visitor)
    }
}

/// Attempts to deserialize `T` from the key-values string `input`.
pub fn from_key_values<'a, T>(input: &'a str) -> Result<T>
where
    T: Deserialize<'a>,
{
    let mut deserializer = KeyValueDeserializer::from(input);
    let t = T::deserialize(&mut deserializer)?;
    if deserializer.input.is_empty() {
        Ok(t)
    } else {
        Err(deserializer.error_here(ErrorKind::TrailingCharacters))
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;

    #[derive(Deserialize, PartialEq, Debug)]
    struct SingleStruct<T> {
        m: T,
    }

    #[test]
    fn deserialize_number() {
        let res = from_key_values::<SingleStruct<usize>>("m=54").unwrap();
        assert_eq!(res.m, 54);

        let res = from_key_values::<SingleStruct<isize>>("m=-54").unwrap();
        assert_eq!(res.m, -54);

        // Parsing a signed into an unsigned?
        let res = from_key_values::<SingleStruct<u32>>("m=-54").unwrap_err();
        assert_eq!(
            res,
            ParseError {
                kind: ErrorKind::ExpectedNumber,
                pos: 2
            }
        );

        // Value too big for a signed?
        let val = i32::MAX as u32 + 1;
        let res = from_key_values::<SingleStruct<i32>>(&format!("m={}", val)).unwrap_err();
        assert_eq!(
            res,
            ParseError {
                kind: ErrorKind::NumberOverflow,
                pos: 2
            }
        );

        let res = from_key_values::<SingleStruct<usize>>("m=test").unwrap_err();
        assert_eq!(
            res,
            ParseError {
                kind: ErrorKind::ExpectedNumber,
                pos: 2,
            }
        );
    }

    #[test]
    fn deserialize_string() {
        let kv = "m=John";
        let res = from_key_values::<SingleStruct<String>>(kv).unwrap();
        assert_eq!(res.m, "John".to_string());

        // Spaces are valid (but not recommended) in unquoted strings.
        let kv = "m=John Doe";
        let res = from_key_values::<SingleStruct<String>>(kv).unwrap();
        assert_eq!(res.m, "John Doe".to_string());

        // Empty string is not valid if unquoted
        let kv = "m=";
        let err = from_key_values::<SingleStruct<String>>(kv).unwrap_err();
        assert_eq!(
            err,
            ParseError {
                kind: ErrorKind::ExpectedString,
                pos: 2
            }
        );

        // Quoted strings.
        let kv = r#"m="John Doe""#;
        let res = from_key_values::<SingleStruct<String>>(kv).unwrap();
        assert_eq!(res.m, "John Doe".to_string());
        let kv = r#"m='John Doe'"#;
        let res = from_key_values::<SingleStruct<String>>(kv).unwrap();
        assert_eq!(res.m, "John Doe".to_string());

        // Empty quoted strings.
        let kv = r#"m="""#;
        let res = from_key_values::<SingleStruct<String>>(kv).unwrap();
        assert_eq!(res.m, "".to_string());
        let kv = r#"m=''"#;
        let res = from_key_values::<SingleStruct<String>>(kv).unwrap();
        assert_eq!(res.m, "".to_string());

        // "=", "," and "'"" in quote.
        let kv = r#"m="val = [10, 20, 'a']""#;
        let res = from_key_values::<SingleStruct<String>>(kv).unwrap();
        assert_eq!(res.m, r#"val = [10, 20, 'a']"#.to_string());

        // Quotes in unquoted strings are forbidden.
        let kv = r#"m=val="a""#;
        let err = from_key_values::<SingleStruct<String>>(kv).unwrap_err();
        assert_eq!(
            err,
            ParseError {
                kind: ErrorKind::InvalidCharInString,
                pos: 6
            }
        );
        let kv = r#"m=val='a'"#;
        let err = from_key_values::<SingleStruct<String>>(kv).unwrap_err();
        assert_eq!(
            err,
            ParseError {
                kind: ErrorKind::InvalidCharInString,
                pos: 6
            }
        );

        // Numbers and booleans are technically valid strings.
        let kv = "m=10";
        let res = from_key_values::<SingleStruct<String>>(kv).unwrap();
        assert_eq!(res.m, "10".to_string());
        let kv = "m=false";
        let res = from_key_values::<SingleStruct<String>>(kv).unwrap();
        assert_eq!(res.m, "false".to_string());

        // Escaped quote.
        let kv = r#"m="Escaped \" quote""#;
        let res = from_key_values::<SingleStruct<String>>(kv).unwrap();
        assert_eq!(res.m, r#"Escaped " quote"#.to_string());

        // Escaped slash at end of string.
        let kv = r#"m="Escaped slash\\""#;
        let res = from_key_values::<SingleStruct<String>>(kv).unwrap();
        assert_eq!(res.m, r#"Escaped slash\"#.to_string());
    }

    #[test]
    fn deserialize_bool() {
        let res = from_key_values::<SingleStruct<bool>>("m=true").unwrap();
        assert_eq!(res.m, true);

        let res = from_key_values::<SingleStruct<bool>>("m=false").unwrap();
        assert_eq!(res.m, false);

        let res = from_key_values::<SingleStruct<bool>>("m").unwrap();
        assert_eq!(res.m, true);

        let res = from_key_values::<SingleStruct<bool>>("m=10").unwrap_err();
        assert_eq!(
            res,
            ParseError {
                kind: ErrorKind::ExpectedBoolean,
                pos: 2,
            }
        );
    }

    #[test]
    fn deserialize_complex_struct() {
        #[derive(Deserialize, PartialEq, Debug)]
        struct TestStruct {
            num: usize,
            path: PathBuf,
            enable: bool,
        }
        let kv = "num=54,path=/dev/foomatic,enable=false";
        let res = from_key_values::<TestStruct>(kv).unwrap();
        assert_eq!(
            res,
            TestStruct {
                num: 54,
                path: "/dev/foomatic".into(),
                enable: false,
            }
        );

        let kv = "enable,path=/usr/lib/libossom.so.1,num=12";
        let res = from_key_values::<TestStruct>(kv).unwrap();
        assert_eq!(
            res,
            TestStruct {
                num: 12,
                path: "/usr/lib/libossom.so.1".into(),
                enable: true,
            }
        );
    }

    #[test]
    fn deserialize_unknown_field() {
        #[derive(Deserialize, PartialEq, Debug)]
        #[serde(deny_unknown_fields)]
        struct TestStruct {
            num: usize,
            path: PathBuf,
            enable: bool,
        }

        let kv = "enable,path=/usr/lib/libossom.so.1,num=12,foo=bar";
        assert!(from_key_values::<TestStruct>(kv).is_err());
    }

    #[test]
    fn deserialize_option() {
        #[derive(Deserialize, PartialEq, Debug)]
        struct TestStruct {
            num: u32,
            opt: Option<u32>,
        }
        let kv = "num=16,opt=12";
        let res: TestStruct = from_key_values(kv).unwrap();
        assert_eq!(
            res,
            TestStruct {
                num: 16,
                opt: Some(12),
            }
        );

        let kv = "num=16";
        let res: TestStruct = from_key_values(kv).unwrap();
        assert_eq!(res, TestStruct { num: 16, opt: None });

        let kv = "";
        assert!(from_key_values::<TestStruct>(kv).is_err());
    }

    #[test]
    fn deserialize_enum() {
        #[derive(Deserialize, PartialEq, Debug)]
        enum TestEnum {
            #[serde(rename = "first")]
            FirstVariant,
            #[serde(rename = "second")]
            SecondVariant,
        }
        let res: TestEnum = from_key_values("first").unwrap();
        assert_eq!(res, TestEnum::FirstVariant,);

        let res: TestEnum = from_key_values("second").unwrap();
        assert_eq!(res, TestEnum::SecondVariant,);

        from_key_values::<TestEnum>("third").unwrap_err();
    }

    #[test]
    fn deserialize_embedded_enum() {
        #[derive(Deserialize, PartialEq, Debug)]
        enum TestEnum {
            #[serde(rename = "first")]
            FirstVariant,
            #[serde(rename = "second")]
            SecondVariant,
        }
        #[derive(Deserialize, PartialEq, Debug)]
        struct TestStruct {
            variant: TestEnum,
            #[serde(default)]
            active: bool,
        }
        let res: TestStruct = from_key_values("variant=first").unwrap();
        assert_eq!(
            res,
            TestStruct {
                variant: TestEnum::FirstVariant,
                active: false,
            }
        );
        let res: TestStruct = from_key_values("variant=second,active=true").unwrap();
        assert_eq!(
            res,
            TestStruct {
                variant: TestEnum::SecondVariant,
                active: true,
            }
        );
        let res: TestStruct = from_key_values("active=true,variant=second").unwrap();
        assert_eq!(
            res,
            TestStruct {
                variant: TestEnum::SecondVariant,
                active: true,
            }
        );
        let res: TestStruct = from_key_values("active,variant=second").unwrap();
        assert_eq!(
            res,
            TestStruct {
                variant: TestEnum::SecondVariant,
                active: true,
            }
        );
        let res: TestStruct = from_key_values("active=false,variant=second").unwrap();
        assert_eq!(
            res,
            TestStruct {
                variant: TestEnum::SecondVariant,
                active: false,
            }
        );
    }

    #[test]
    fn deserialize_first_arg_string() {
        #[derive(Deserialize, PartialEq, Debug)]
        struct TestStruct {
            name: String,
            num: u8,
        }
        let res: TestStruct = from_key_values("name=foo,num=12").unwrap();
        assert_eq!(
            res,
            TestStruct {
                name: "foo".into(),
                num: 12,
            }
        );

        let res: TestStruct = from_key_values("foo,num=12").unwrap();
        assert_eq!(
            res,
            TestStruct {
                name: "foo".into(),
                num: 12,
            }
        );
    }

    #[test]
    fn deserialize_first_arg_int() {
        #[derive(Deserialize, PartialEq, Debug)]
        struct TestStruct {
            num: u8,
            name: String,
        }
        let res: TestStruct = from_key_values("name=foo,num=12").unwrap();
        assert_eq!(
            res,
            TestStruct {
                num: 12,
                name: "foo".into(),
            }
        );

        let res: TestStruct = from_key_values("12,name=foo").unwrap();
        assert_eq!(
            res,
            TestStruct {
                num: 12,
                name: "foo".into(),
            }
        );
    }
}
