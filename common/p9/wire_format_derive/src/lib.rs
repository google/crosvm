// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Derives a 9P wire format encoding for a struct by recursively calling
//! `WireFormat::encode` or `WireFormat::decode` on the fields of the struct.
//! This is only intended to be used from within the `p9` crate.

#![recursion_limit = "256"]

extern crate proc_macro;
extern crate proc_macro2;

#[macro_use]
extern crate quote;

#[macro_use]
extern crate syn;

use proc_macro2::Span;
use proc_macro2::TokenStream;
use syn::spanned::Spanned;
use syn::Data;
use syn::DeriveInput;
use syn::Fields;
use syn::Ident;

/// The function that derives the actual implementation.
#[proc_macro_derive(P9WireFormat)]
pub fn p9_wire_format(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    p9_wire_format_inner(input).into()
}

fn p9_wire_format_inner(input: DeriveInput) -> TokenStream {
    if !input.generics.params.is_empty() {
        return quote! {
            compile_error!("derive(P9WireFormat) does not support generic parameters");
        };
    }

    let container = input.ident;

    let byte_size_impl = byte_size_sum(&input.data);
    let encode_impl = encode_wire_format(&input.data);
    let decode_impl = decode_wire_format(&input.data, &container);

    let scope = format!("wire_format_{}", container).to_lowercase();
    let scope = Ident::new(&scope, Span::call_site());
    quote! {
        mod #scope {
            extern crate std;
            use self::std::io;
            use self::std::result::Result::Ok;

            use super::#container;

            use protocol::WireFormat;

            impl WireFormat for #container {
                fn byte_size(&self) -> u32 {
                    #byte_size_impl
                }

                fn encode<W: io::Write>(&self, _writer: &mut W) -> io::Result<()> {
                    #encode_impl
                }

                fn decode<R: io::Read>(_reader: &mut R) -> io::Result<Self> {
                    #decode_impl
                }
            }
        }
    }
}

// Generate code that recursively calls byte_size on every field in the struct.
fn byte_size_sum(data: &Data) -> TokenStream {
    if let Data::Struct(ref data) = *data {
        if let Fields::Named(ref fields) = data.fields {
            let fields = fields.named.iter().map(|f| {
                let field = &f.ident;
                let span = field.span();
                quote_spanned! {span=>
                    WireFormat::byte_size(&self.#field)
                }
            });

            quote! {
                0 #(+ #fields)*
            }
        } else {
            unimplemented!();
        }
    } else {
        unimplemented!();
    }
}

// Generate code that recursively calls encode on every field in the struct.
fn encode_wire_format(data: &Data) -> TokenStream {
    if let Data::Struct(ref data) = *data {
        if let Fields::Named(ref fields) = data.fields {
            let fields = fields.named.iter().map(|f| {
                let field = &f.ident;
                let span = field.span();
                quote_spanned! {span=>
                    WireFormat::encode(&self.#field, _writer)?;
                }
            });

            quote! {
                #(#fields)*

                Ok(())
            }
        } else {
            unimplemented!();
        }
    } else {
        unimplemented!();
    }
}

// Generate code that recursively calls decode on every field in the struct.
fn decode_wire_format(data: &Data, container: &Ident) -> TokenStream {
    if let Data::Struct(ref data) = *data {
        if let Fields::Named(ref fields) = data.fields {
            let values = fields.named.iter().map(|f| {
                let field = &f.ident;
                let span = field.span();
                quote_spanned! {span=>
                    let #field = WireFormat::decode(_reader)?;
                }
            });

            let members = fields.named.iter().map(|f| {
                let field = &f.ident;
                quote! {
                    #field: #field,
                }
            });

            quote! {
                #(#values)*

                Ok(#container {
                    #(#members)*
                })
            }
        } else {
            unimplemented!();
        }
    } else {
        unimplemented!();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn byte_size() {
        let input: DeriveInput = parse_quote! {
            struct Item {
                ident: u32,
                with_underscores: String,
                other: u8,
            }
        };

        let expected = quote! {
            0
                + WireFormat::byte_size(&self.ident)
                + WireFormat::byte_size(&self.with_underscores)
                + WireFormat::byte_size(&self.other)
        };

        assert_eq!(byte_size_sum(&input.data).to_string(), expected.to_string());
    }

    #[test]
    fn encode() {
        let input: DeriveInput = parse_quote! {
            struct Item {
                ident: u32,
                with_underscores: String,
                other: u8,
            }
        };

        let expected = quote! {
            WireFormat::encode(&self.ident, _writer)?;
            WireFormat::encode(&self.with_underscores, _writer)?;
            WireFormat::encode(&self.other, _writer)?;
            Ok(())
        };

        assert_eq!(
            encode_wire_format(&input.data).to_string(),
            expected.to_string(),
        );
    }

    #[test]
    fn decode() {
        let input: DeriveInput = parse_quote! {
            struct Item {
                ident: u32,
                with_underscores: String,
                other: u8,
            }
        };

        let container = Ident::new("Item", Span::call_site());
        let expected = quote! {
            let ident = WireFormat::decode(_reader)?;
            let with_underscores = WireFormat::decode(_reader)?;
            let other = WireFormat::decode(_reader)?;
            Ok(Item {
                ident: ident,
                with_underscores: with_underscores,
                other: other,
            })
        };

        assert_eq!(
            decode_wire_format(&input.data, &container).to_string(),
            expected.to_string(),
        );
    }

    #[test]
    fn end_to_end() {
        let input: DeriveInput = parse_quote! {
            struct Niijima_先輩 {
                a: u8,
                b: u16,
                c: u32,
                d: u64,
                e: String,
                f: Vec<String>,
                g: Nested,
            }
        };

        let expected = quote! {
            mod wire_format_niijima_先輩 {
                extern crate std;
                use self::std::io;
                use self::std::result::Result::Ok;

                use super::Niijima_先輩;

                use protocol::WireFormat;

                impl WireFormat for Niijima_先輩 {
                    fn byte_size(&self) -> u32 {
                        0
                        + WireFormat::byte_size(&self.a)
                        + WireFormat::byte_size(&self.b)
                        + WireFormat::byte_size(&self.c)
                        + WireFormat::byte_size(&self.d)
                        + WireFormat::byte_size(&self.e)
                        + WireFormat::byte_size(&self.f)
                        + WireFormat::byte_size(&self.g)
                    }

                    fn encode<W: io::Write>(&self, _writer: &mut W) -> io::Result<()> {
                        WireFormat::encode(&self.a, _writer)?;
                        WireFormat::encode(&self.b, _writer)?;
                        WireFormat::encode(&self.c, _writer)?;
                        WireFormat::encode(&self.d, _writer)?;
                        WireFormat::encode(&self.e, _writer)?;
                        WireFormat::encode(&self.f, _writer)?;
                        WireFormat::encode(&self.g, _writer)?;
                        Ok(())
                    }
                    fn decode<R: io::Read>(_reader: &mut R) -> io::Result<Self> {
                        let a = WireFormat::decode(_reader)?;
                        let b = WireFormat::decode(_reader)?;
                        let c = WireFormat::decode(_reader)?;
                        let d = WireFormat::decode(_reader)?;
                        let e = WireFormat::decode(_reader)?;
                        let f = WireFormat::decode(_reader)?;
                        let g = WireFormat::decode(_reader)?;
                        Ok(Niijima_先輩 {
                            a: a,
                            b: b,
                            c: c,
                            d: d,
                            e: e,
                            f: f,
                            g: g,
                        })
                    }
                }
            }
        };

        assert_eq!(
            p9_wire_format_inner(input).to_string(),
            expected.to_string(),
        );
    }
}
