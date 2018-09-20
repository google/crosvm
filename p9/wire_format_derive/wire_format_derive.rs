// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Derives a 9P wire format encoding for a struct by recursively calling
//! `WireFormat::encode` or `WireFormat::decode` on the fields of the struct.
//! This is only intended to be used from within the `p9` crate.

#![recursion_limit = "256"]

extern crate proc_macro2;
extern crate proc_macro;

#[macro_use]
extern crate quote;

#[cfg_attr(test, macro_use)]
extern crate syn;

use proc_macro::TokenStream;
use proc_macro2::Span;
use quote::Tokens;
use syn::{Data, DeriveInput, Fields, Ident};
use syn::spanned::Spanned;

/// The function that derives the actual implementation.
#[proc_macro_derive(P9WireFormat)]
pub fn p9_wire_format(input: TokenStream) -> TokenStream {
    p9_wire_format_inner(syn::parse(input).unwrap()).into()
}

fn p9_wire_format_inner(input: DeriveInput) -> Tokens {
    if !input.generics.params.is_empty() {
        return quote! {
            compile_error!("derive(P9WireFormat) does not support generic parameters");
        };
    }

    let var = quote!(self);
    let ident = input.ident;
    let name = quote!(#ident);

    let call_site = Span::call_site();
    let import = quote_spanned!(call_site=> use protocol::WireFormat; );
    let wire_format = quote_spanned!(call_site=> WireFormat);

    let byte_size_impl = byte_size_sum(&input.data, &wire_format, &var);
    let encode_impl = encode_wire_format(&input.data, &wire_format, &var);
    let decode_impl = decode_wire_format(&input.data, &wire_format, &name);

    let scope = Ident::from(format!("wire_format_{}", ident).to_lowercase());
    quote! {
        mod #scope {
            extern crate std;
            use self::std::io;
            use self::std::result::Result::Ok;

            use super::#name;

            #import

            impl #wire_format for #name {
                fn byte_size(&#var) -> u32 {
                    #byte_size_impl
                }

                fn encode<W: io::Write>(&#var, _writer: &mut W) -> io::Result<()> {
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
fn byte_size_sum(data: &Data, wire_format: &Tokens, var: &Tokens) -> Tokens {
    let def_site = Span::def_site();
    let call_site = Span::call_site();

    if let Data::Struct(ref data) = *data {
        if let Fields::Named(ref fields) = data.fields {
            let fields = fields.named.iter().map(|f| {
                let name = f.ident;
                let access = quote_spanned!(call_site=> #var.#name);
                let span = f.span().resolved_at(def_site);
                quote_spanned!(span=> #wire_format::byte_size(&#access) )
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
fn encode_wire_format(data: &Data, wire_format: &Tokens, var: &Tokens) -> Tokens {
    let def_site = Span::def_site();
    let call_site = Span::call_site();

    if let Data::Struct(ref data) = *data {
        if let Fields::Named(ref fields) = data.fields {
            let fields = fields.named.iter().map(|f| {
                let name = f.ident;
                let access = quote_spanned!(call_site=> #var.#name);
                let span = f.span().resolved_at(def_site);
                quote_spanned!(span=> #wire_format::encode(&#access, _writer)?; )
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
fn decode_wire_format(data: &Data, wire_format: &Tokens, name: &Tokens) -> Tokens {
    let def_site = Span::def_site();
    let call_site = Span::call_site();

    if let Data::Struct(ref data) = *data {
        if let Fields::Named(ref fields) = data.fields {
            let values = fields.named.iter().map(|f| {
                let name = f.ident;
                let access = quote_spanned!(call_site=> #name);
                let span = f.span().resolved_at(def_site);
                quote_spanned!(span=> let #access = #wire_format::decode(_reader)?; )
            });

            let members = fields.named.iter().map(|f| {
                let name = f.ident;
                quote_spanned!(call_site=>
                    #name: #name,
                )
            });

            quote! {
                #(#values)*

                Ok(#name {
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

        let var = quote!(self);
        let wire_format = quote!(WireFormat);
        let expected = quote! {
            0
                + WireFormat::byte_size(&self.ident)
                + WireFormat::byte_size(&self.with_underscores)
                + WireFormat::byte_size(&self.other)
        };

        assert_eq!(byte_size_sum(&input.data, &wire_format, &var), expected);
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

        let var = quote!(self);
        let wire_format = quote!(WireFormat);
        let expected = quote! {
            WireFormat::encode(&self.ident, _writer)?;
            WireFormat::encode(&self.with_underscores, _writer)?;
            WireFormat::encode(&self.other, _writer)?;
            Ok(())
        };

        assert_eq!(
            encode_wire_format(&input.data, &wire_format, &var),
            expected
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

        let name = quote!(Item);
        let wire_format = quote!(WireFormat);
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
            decode_wire_format(&input.data, &wire_format, &name),
            expected
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

        assert_eq!(p9_wire_format_inner(input), expected);
    }
}
