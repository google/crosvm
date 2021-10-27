// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#![recursion_limit = "128"]

extern crate proc_macro;

use proc_macro2::{Ident, TokenStream};
use quote::quote;
use syn::{parse_macro_input, Data, DeriveInput, Field, Fields, Index, Member, Variant};

#[cfg(test)]
mod tests;

// The method for packing an enum into a u64 is as follows:
// 1) Reserve the lowest "ceil(log_2(x))" bits where x is the number of enum variants.
// 2) Store the enum variant's index (0-based index based on order in the enum definition) in
//    reserved bits.
// 3) If there is data in the enum variant, store the data in remaining bits.
// The method for unpacking is as follows
// 1) Mask the raw token to just the reserved bits
// 2) Match the reserved bits to the enum variant token.
// 3) If the indicated enum variant had data, extract it from the unreserved bits.

// Calculates the number of bits needed to store the variant index. Essentially the log base 2
// of the number of variants, rounded up.
fn variant_bits(variants: &[Variant]) -> u32 {
    if variants.is_empty() {
        // The degenerate case of no variants.
        0
    } else {
        variants.len().next_power_of_two().trailing_zeros()
    }
}

// Name of the field if it has one, otherwise 0 assuming this is the zeroth
// field of a tuple variant.
fn field_member(field: &Field) -> Member {
    match &field.ident {
        Some(name) => Member::Named(name.clone()),
        None => Member::Unnamed(Index::from(0)),
    }
}

// Generates the function body for `as_raw_token`.
fn generate_as_raw_token(enum_name: &Ident, variants: &[Variant]) -> TokenStream {
    let variant_bits = variant_bits(variants);

    // Each iteration corresponds to one variant's match arm.
    let cases = variants.iter().enumerate().map(|(index, variant)| {
        let variant_name = &variant.ident;
        let index = index as u64;

        // The capture string is for everything between the variant identifier and the `=>` in
        // the match arm: the variant's data capture.
        let capture = variant.fields.iter().next().map(|field| {
            let member = field_member(&field);
            quote!({ #member: data })
        });

        // The modifier string ORs the variant index with extra bits from the variant data
        // field.
        let modifier = match variant.fields {
            Fields::Named(_) | Fields::Unnamed(_) => Some(quote! {
                | ((data as u64) << #variant_bits)
            }),
            Fields::Unit => None,
        };

        // Assembly of the match arm.
        quote! {
            #enum_name::#variant_name #capture => #index #modifier
        }
    });

    quote! {
        match *self {
            #(
                #cases,
            )*
        }
    }
}

// Generates the function body for `from_raw_token`.
fn generate_from_raw_token(enum_name: &Ident, variants: &[Variant]) -> TokenStream {
    let variant_bits = variant_bits(variants);
    let variant_mask = ((1 << variant_bits) - 1) as u64;

    // Each iteration corresponds to one variant's match arm.
    let cases = variants.iter().enumerate().map(|(index, variant)| {
        let variant_name = &variant.ident;
        let index = index as u64;

        // The data string is for extracting the enum variant's data bits out of the raw token
        // data, which includes both variant index and data bits.
        let data = variant.fields.iter().next().map(|field| {
            let member = field_member(&field);
            let ty = &field.ty;
            quote!({ #member: (data >> #variant_bits) as #ty })
        });

        // Assembly of the match arm.
        quote! {
            #index => #enum_name::#variant_name #data
        }
    });

    quote! {
        // The match expression only matches the bits for the variant index.
        match data & #variant_mask {
            #(
                #cases,
            )*
            _ => unreachable!(),
        }
    }
}

// The proc_macro::TokenStream type can only be constructed from within a
// procedural macro, meaning that unit tests are not able to invoke `fn
// poll_token` below as an ordinary Rust function. We factor out the logic into
// a signature that deals with Syn and proc-macro2 types only which are not
// restricted to a procedural macro invocation.
fn poll_token_inner(input: DeriveInput) -> TokenStream {
    let variants: Vec<Variant> = match input.data {
        Data::Enum(data) => data.variants.into_iter().collect(),
        Data::Struct(_) | Data::Union(_) => panic!("input must be an enum"),
    };

    for variant in &variants {
        assert!(variant.fields.iter().count() <= 1);
    }

    // Given our basic model of a user given enum that is suitable as a token, we generate the
    // implementation. The implementation is NOT always well formed, such as when a variant's data
    // type is not bit shiftable or castable to u64, but we let Rust generate such errors as it
    // would be difficult to detect every kind of error. Importantly, every implementation that we
    // generate here and goes on to compile succesfully is sound.

    let enum_name = input.ident;
    let as_raw_token = generate_as_raw_token(&enum_name, &variants);
    let from_raw_token = generate_from_raw_token(&enum_name, &variants);

    quote! {
        impl PollToken for #enum_name {
            fn as_raw_token(&self) -> u64 {
                #as_raw_token
            }

            fn from_raw_token(data: u64) -> Self {
                #from_raw_token
            }
        }
    }
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
pub fn poll_token(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    poll_token_inner(input).into()
}
