// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use quote::quote;
use syn::parse_macro_input;
use syn::DeriveInput;

/// Implement `argh`'s `FromArgValue` trait for a struct or enum using `from_key_values`.
#[proc_macro_derive(FromKeyValues)]
pub fn keyvalues_derive(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let DeriveInput {
        ident, generics, ..
    } = parse_macro_input!(input);
    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();

    quote! {
        impl #impl_generics ::serde_keyvalue::argh::FromArgValue for #ident #ty_generics #where_clause {
            fn from_arg_value(value: &str) -> std::result::Result<Self, std::string::String> {
                ::serde_keyvalue::from_key_values(value).map_err(|e| e.to_string())
            }
        }
    }
    .into()
}
