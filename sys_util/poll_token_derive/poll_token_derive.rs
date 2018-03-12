// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

extern crate proc_macro;

use proc_macro::TokenStream;
use std::fmt::Write;
use std::mem;
use std::str::FromStr;

#[cfg(test)]
mod tests;

// This file is meant to be read from top to bottom to reflect how this code processes and generates
// Rust enum definitions and implementations. The algorithm overview:
// 1) Split the rust source by whitespace (`str::split_whitespace`).
// 2a) Attempt to tokenize each piece (see: `Tokenized`, all functions starting with `matches`).
// 2b) Feed the token to the `ParseState` (see `ParseState::handle_token`).
// 3) After the source is fully processed, the `ParseState` has an `EnumModel` representing the
//    input enum.
// 4) Glue together an implementation of PollToken using a template.

// A single token after splitting input source by white space and simple stateless matching.
#[derive(Clone, Debug, PartialEq)]
enum Tokenized {
    // `enum`
    Enum,

    // `pub' | `pub(crate)`
    Visiblity,

    // `Hello`, `index`, `data,`
    Ident(String),

    // `index:`, 'first:`
    FieldIdent(String),

    // `Socket(u32)`, `Client(usize),`,
    IdentAndType(String, String),

    // `{`
    OpenBrace,

    // `}`, `},`
    CloseBrace,
}

// Attempts to match strings of the form "identifier" with optional trailing comma.
fn matches_ident(s: &str) -> Option<String> {
    let ident = s.trim_right_matches(',');
    if !ident.is_empty() && ident.chars().all(char::is_alphanumeric) {
        Some(ident.to_owned())
    } else {
        None
    }
}

// Attempts to match strings of the form "Identifier(Type)" with optional trailing comma. If the
// given string matches, the identifier and type are returned as a 2-tuple receptively.
fn matches_ident_and_type(s: &str) -> Option<(String, String)> {
    let mut buffer = String::new();
    let mut ident = String::new();
    let mut type_ = String::new();
    let mut brace_depth = 0;
    for c in s.chars() {
        match c {
            '(' if brace_depth == 0 && !buffer.is_empty() && ident.is_empty() => {
                mem::swap(&mut ident, &mut buffer);
                brace_depth += 1;
            }
            ')' if brace_depth == 1 && !buffer.is_empty() && type_.is_empty() => {
                mem::swap(&mut type_, &mut buffer);
                brace_depth -= 1;
            }
            ',' => {}
            c if c.is_alphanumeric() => buffer.push(c),
            _ => return None,
        }
    }
    if !ident.is_empty() && !type_.is_empty() {
        Some((ident, type_))
    } else {
        None
    }
}

// Attempts to match strings of the form "identifier:".
fn matches_field_ident(s: &str) -> Option<String> {
    let field_ident = s.trim_right_matches(':');
    if s.ends_with(':') && field_ident.chars().all(char::is_alphanumeric) {
        Some(field_ident.to_owned())
    } else {
        None
    }
}

impl Tokenized {
    fn from_str(s: &str) -> Tokenized {
        if s.starts_with("pub(") {
            return Tokenized::Visiblity;
        }
        match s {
            "enum" => Tokenized::Enum,
            "pub" => Tokenized::Visiblity,
            "{" => Tokenized::OpenBrace,
            "}" | "}," => Tokenized::CloseBrace,
            _ => {
                // Try to match from most specific to least specific.
                if let Some(ident) = matches_field_ident(s) {
                    Tokenized::FieldIdent(ident)
                } else if let Some((ident, type_)) = matches_ident_and_type(s) {
                    Tokenized::IdentAndType(ident, type_)
                } else if let Some(ident) = matches_ident(s) {
                    Tokenized::Ident(ident)
                } else {
                    panic!("unable to parse token: {}", s)
                }
            }
        }
    }
}

// Data field for an enum, with possible field name.
#[derive(Debug, PartialEq)]
struct EnumVariantData {
    type_: String,
    name: Option<String>,
}

// Data for one variant of an enum, with optional single data field.
#[derive(Debug, PartialEq)]
struct EnumVariant {
    name: String,
    data: Option<EnumVariantData>,
}

// Data for an entire enum type.
#[derive(Debug, Default, PartialEq)]
struct EnumModel {
    name: String,
    variants: Vec<EnumVariant>,
}
// Note: impl for EnumModel is below the parsing code and definitions because all of the methods are
// for generating the PollToken impl.

// Labels for each of the states in the parsing state machine. The '->` symbol means that the given
// state may transition to the state pointed to.
#[derive(PartialEq, Debug)]
enum States {
    // Initial state, expecting to see visibility rules (e.g. `pub`) or `enum` keyword.
    Start, // -> Ident

    // Expect to see the name of the enum field.
    Ident, // -> Brace

    // Expect to see an opening brace.
    Brace, // -> VariantIdent, -> End

    // Expect to see a variant's name.
    VariantIdent, // -> VariantIdent, -> VariantData, -> End

    // Expect to see the field name of a variant's data.
    VariantData, // -> VariantIdent, -> VariantDataType

    // Expect to see the tye name of a variant's data.
    VariantDataType, // -> VariantData

    // Expect to see no more tokens.
    End,
}

// The state machine for parsing a stream of `Tokenized`. After the States::End state is reached, a
// complete `EnumModel` is ready to be used for generating an implementation.
struct ParseState {
    current_state: States,
    current_variant: Option<EnumVariant>,
    model: EnumModel,
}

impl ParseState {
    fn new() -> ParseState {
        ParseState {
            current_state: States::Start,
            current_variant: Default::default(),
            model: Default::default(),
        }
    }

    // Handles the next token in the stream of tokens.
    fn handle_token(&mut self, tok: Tokenized) {
        match self.current_state {
            States::Start => self.handle_start(tok),
            States::Ident => self.handle_ident(tok),
            States::Brace => self.handle_brace(tok),
            States::VariantIdent => self.handle_variant_ident(tok),
            States::VariantData => self.handle_variant_data(tok),
            States::VariantDataType => self.handle_variant_data_type(tok),
            States::End => self.handle_end(tok),
        }
    }

    // All the following are handlers name after the current state that handle the next token.

    fn handle_start(&mut self, tok: Tokenized) {
        self.current_state = match tok {
            Tokenized::Enum => States::Ident,
            Tokenized::Visiblity => States::Start,
            _ => panic!("derives for enum types only"),

        };
    }

    fn handle_ident(&mut self, tok: Tokenized) {
        self.current_state = match tok {
            Tokenized::Ident(ident) => {
                self.model.name = ident;
                States::Brace
            }
            _ => panic!("unexpected token: {:?}", tok),
        };
    }

    fn handle_brace(&mut self, tok: Tokenized) {
        self.current_state = match tok {
            Tokenized::OpenBrace => States::VariantIdent,
            Tokenized::CloseBrace => States::End,
            _ => panic!("unexpected token: {:?}", tok),
        };
    }

    fn handle_variant_ident(&mut self, tok: Tokenized) {
        // This handler is the most complex because it has the most branches for the new
        // `current_state`. Adding to that complexity is that many branches indicate a new variant
        // is being handled, which means the old `current_variant` needs to be added to `variants`
        // and a fresh one needs to be started with the fresh data embedded in the token.
        self.current_state = match tok {
            Tokenized::Ident(ident) => {
                let mut variant = Some(EnumVariant {
                                           name: ident,
                                           data: None,
                                       });
                mem::swap(&mut variant, &mut self.current_variant);
                if let Some(variant) = variant {
                    self.model.variants.push(variant);
                }
                States::VariantIdent
            }
            Tokenized::IdentAndType(ident, type_) => {
                let variant_data = EnumVariantData {
                    type_: type_,
                    name: None,
                };
                let mut variant = Some(EnumVariant {
                                           name: ident,
                                           data: Some(variant_data),
                                       });
                mem::swap(&mut variant, &mut self.current_variant);
                if let Some(variant) = variant {
                    self.model.variants.push(variant);
                }
                States::VariantIdent
            }
            Tokenized::OpenBrace => States::VariantData,
            Tokenized::CloseBrace => {
                let mut variant = Default::default();
                mem::swap(&mut variant, &mut self.current_variant);
                if let Some(variant) = variant {
                    self.model.variants.push(variant);
                }
                States::End
            }
            _ => panic!("unexpected token: {:?}", tok),
        };
    }

    fn handle_variant_data(&mut self, tok: Tokenized) {
        let variant = self.current_variant.as_mut().unwrap();
        self.current_state = match tok {
            Tokenized::FieldIdent(ident) => {
                assert!(variant.data.is_none(),
                        "enum variant can only have one field");
                variant.data = Some(EnumVariantData {
                                        type_: "".to_owned(),
                                        name: Some(ident),
                                    });
                States::VariantDataType
            }
            Tokenized::CloseBrace => States::VariantIdent,
            _ => panic!("unexpected token: {:?}", tok),
        };
    }

    fn handle_variant_data_type(&mut self, tok: Tokenized) {
        let variant = self.current_variant.as_mut().unwrap();
        let variant_data = variant.data.as_mut().unwrap();
        self.current_state = match tok {
            Tokenized::Ident(ident) => {
                variant_data.type_ = ident;
                States::VariantData
            }
            _ => panic!("unexpected token: {:?}", tok),
        };
    }

    fn handle_end(&mut self, tok: Tokenized) {
        panic!("unexpected tokens past ending brace: {:?}", tok);
    }
}

// Continued from the above `EnumModel` definition. All methods are used for generating PollToken
// implementation. The method for packing an enum into a u64 is as follows:
// 1) Reserve the lowest "ceil(log_2(x))" bits where x is the number of enum variants.
// 2) Store the enum variant's index (0-based index based on order in the enum definition) in
//    reserved bits.
// 3) If there is data in the enum variant, store the data in remaining bits.
// The method for unpacking is as follows
// 1) Mask the raw token to just the reserved bits
// 2) Match the reserved bits to the enum variant token.
// 3) If the indicated enum variant had data, extract it from the unreserved bits.
impl EnumModel {
    // Calculates the number of bits needed to store the variant index. Essentially the log base 2
    // of the number of variants, rounded up.
    fn variant_bits(&self) -> u32 {
        // The degenerate case of no variants.
        if self.variants.is_empty() {
            return 0;
        }
        self.variants.len().next_power_of_two().trailing_zeros()
    }

    // Generates the function body for `as_raw_token`.
    fn generate_as_raw_token(&self) -> String {
        let variant_bits = self.variant_bits();
        let mut match_statement = "match *self {\n".to_owned();

        // Each iteration corresponds to one variant's match arm.
        for (index, variant) in self.variants.iter().enumerate() {
            // The capture string is for everything between the variant identifier and the `=>` in
            // the match arm: the variant's data capture.
            let capture = match variant.data.as_ref() {
                Some(&EnumVariantData { name: Some(ref name), .. }) => {
                    format!("{{ {}: data }}", name)
                }
                Some(&EnumVariantData { .. }) => "(data)".to_owned(),
                None => "".to_owned(),
            };

            // The modifier string ORs the variant index with extra bits from the variant data
            // field.
            let modifer = if variant.data.is_some() {
                format!(" | ((data as u64) << {})", variant_bits)
            } else {
                "".to_owned()
            };

            // Assembly of the match arm.
            write!(match_statement,
                   "{}::{}{} => {}{},\n",
                   self.name,
                   variant.name,
                   capture,
                   index,
                   modifer)
                    .unwrap();
        }
        match_statement.push_str("}");
        match_statement
    }

    // Generates the function body for `from_raw_token`.
    fn generate_from_raw_token(&self) -> String {
        let variant_bits = self.variant_bits();
        let variant_mask = (1 << variant_bits) - 1;

        // The match expression only matches the bits for the variant index.
        let mut match_statement = format!("match data & 0x{:02x} {{\n", variant_mask);

        // Each iteration corresponds to one variant's match arm.
        for (index, variant) in self.variants.iter().enumerate() {
            // The data string is for extracting the enum variant's data bits out of the raw token
            // data, which includes both variant index and data bits.
            let data = match variant.data.as_ref() {
                Some(&EnumVariantData {
                          name: Some(ref name),
                          ref type_,
                      }) => format!("{{ {}: (data >> {}) as {} }}", name, variant_bits, type_),
                Some(&EnumVariantData {
                          name: None,
                          ref type_,
                      }) => format!("((data >> {}) as {})", variant_bits, type_),
                None => "".to_owned(),
            };

            // Assembly of the match arm.
            write!(match_statement,
                   "{} => {}::{}{},\n",
                   index,
                   self.name,
                   variant.name,
                   data)
                    .unwrap();
        }
        match_statement.push_str("_ => unreachable!()\n}");
        match_statement
    }
}

// Because unit tests cannot create `TokenStream`s (apparently), we have an inner implementation
// that deals in strings.
fn poll_token_inner(src: &str) -> String {
    let src_tokens = src.split_whitespace();

    // Parsing is done in two interleaved stages, tokenizing without context, followed by parsing
    // via state machine.
    let mut state = ParseState::new();
    for src_tok in src_tokens {
        let tok = Tokenized::from_str(src_tok);
        state.handle_token(tok);
    }

    assert_eq!(state.current_state,
               States::End,
               "unexpected end after parsing source enum");

    // Given our basic model of a user given enum that is suitable as a token, we generate the
    // implementation. The implementation is NOT always well formed, such as when a variant's data
    // type is not bit shiftable or castable to u64, but we let Rust generate such errors as it
    // would be difficult to detect every kind of error. Importantly, every implementation that we
    // generate here and goes on to compile succesfully is sound.
    let model = state.model;
    format!("impl PollToken for {} {{
    fn as_raw_token(&self) -> u64 {{
{}
    }}

    fn from_raw_token(data: u64) -> Self {{
{}
    }}
}}",
            model.name,
            model.generate_as_raw_token(),
            model.generate_from_raw_token())
}

/// Implements the PollToken trait for a given `enum`.
///
/// There are limitations on what `enum`s this custom derive will work on:
///
/// * Each variant must be a unit variant (no data), or have a single (un)named data field.
/// * If a variant has data, it must be a primitive type castable to and from a `u64`.
/// * If a variant data has size greater than or equal to a `u64`, its most significant bits must be
///   zero. The number of bits truncated is equal to the number of bits used to store the variant
///   index plus the number of bits above 64.
#[proc_macro_derive(PollToken)]
pub fn poll_token(input: TokenStream) -> TokenStream {
    // The token stream gets converted to a string in a rather regular way, which makes parsing
    // simpler. In particular, whitespace from the source enum is not carried over, instead replaced
    // with whatever the token stream's to_string function outputs. The rust parser has already
    // validated the syntax, so we can make lots of assumptions about the source being well formed.
    TokenStream::from_str(&poll_token_inner(&input.to_string())).unwrap()
}
