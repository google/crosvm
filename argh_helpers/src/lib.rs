// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::fmt::Write;

use quote::quote;

/// A helper derive proc macro to flatten multiple subcommand enums into one
/// Note that it is unable to check for duplicate commands and they will be
/// tried in order of declaration
#[proc_macro_derive(FlattenSubcommand)]
pub fn flatten_subcommand(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let ast = syn::parse_macro_input!(input as syn::DeriveInput);
    let de = match ast.data {
        syn::Data::Enum(v) => v,
        _ => unreachable!(),
    };
    let name = &ast.ident;

    // An enum variant like `<name>(<ty>)`
    struct SubCommandVariant<'a> {
        name: &'a syn::Ident,
        ty: &'a syn::Type,
    }

    let variants: Vec<SubCommandVariant<'_>> = de
        .variants
        .iter()
        .map(|variant| {
            let name = &variant.ident;
            let ty = match &variant.fields {
                syn::Fields::Unnamed(field) => {
                    if field.unnamed.len() != 1 {
                        unreachable!()
                    }

                    &field.unnamed.first().unwrap().ty
                }
                _ => unreachable!(),
            };
            SubCommandVariant { name, ty }
        })
        .collect();

    let variant_ty = variants.iter().map(|x| x.ty).collect::<Vec<_>>();
    let variant_names = variants.iter().map(|x| x.name).collect::<Vec<_>>();

    (quote! {
        impl argh::FromArgs for #name {
            fn from_args(command_name: &[&str], args: &[&str])
                -> std::result::Result<Self, argh::EarlyExit>
            {
                let subcommand_name = if let Some(subcommand_name) = command_name.last() {
                    *subcommand_name
                } else {
                    return Err(argh::EarlyExit::from("no subcommand name".to_owned()));
                };

                #(
                    if <#variant_ty as argh::SubCommands>::COMMANDS
                    .iter()
                    .find(|ci| ci.name.eq(subcommand_name))
                    .is_some()
                    {
                        return <#variant_ty as argh::FromArgs>::from_args(command_name, args)
                            .map(|v| Self::#variant_names(v));
                    }
                )*

                Err(argh::EarlyExit::from("no subcommand matched".to_owned()))
            }

            fn redact_arg_values(command_name: &[&str], args: &[&str]) -> std::result::Result<Vec<String>, argh::EarlyExit> {
                let subcommand_name = if let Some(subcommand_name) = command_name.last() {
                    *subcommand_name
                } else {
                    return Err(argh::EarlyExit::from("no subcommand name".to_owned()));
                };

                #(
                    if <#variant_ty as argh::SubCommands>::COMMANDS
                    .iter()
                    .find(|ci| ci.name.eq(subcommand_name))
                    .is_some()
                    {
                        return <#variant_ty as argh::FromArgs>::redact_arg_values(
                            command_name,
                            args,
                        );
                    }

                )*

                Err(argh::EarlyExit::from("no subcommand matched".to_owned()))
            }
        }

        impl argh::SubCommands for #name {
            const COMMANDS: &'static [&'static argh::CommandInfo] = {
                const TOTAL_LEN: usize = #(<#variant_ty as argh::SubCommands>::COMMANDS.len())+*;
                const COMMANDS: [&'static argh::CommandInfo; TOTAL_LEN] = {
                    let slices = &[#(<#variant_ty as argh::SubCommands>::COMMANDS,)*];
                    // Its not possible for slices[0][0] to be invalid
                    let mut output = [slices[0][0]; TOTAL_LEN];

                    let mut output_index = 0;
                    let mut which_slice = 0;
                    while which_slice < slices.len() {
                        let slice = &slices[which_slice];
                        let mut index_in_slice = 0;
                        while index_in_slice < slice.len() {
                            output[output_index] = slice[index_in_slice];
                            output_index += 1;
                            index_in_slice += 1;
                        }
                        which_slice += 1;
                    }
                    output
                };
                &COMMANDS
            };
        }
    })
    .into()
}

/// A helper proc macro to pad strings so that argh would break them at intended points
#[proc_macro_attribute]
pub fn pad_description_for_argh(
    _attr: proc_macro::TokenStream,
    item: proc_macro::TokenStream,
) -> proc_macro::TokenStream {
    let mut item = syn::parse_macro_input!(item as syn::Item);
    if let syn::Item::Struct(s) = &mut item {
        if let syn::Fields::Named(fields) = &mut s.fields {
            for f in fields.named.iter_mut() {
                for a in f.attrs.iter_mut() {
                    if a.path
                        .get_ident()
                        .map(|i| i.to_string())
                        .unwrap_or_default()
                        == *"doc"
                    {
                        if let Ok(syn::Meta::NameValue(nv)) = a.parse_meta() {
                            if let syn::Lit::Str(s) = nv.lit {
                                let doc = s.value().lines().fold(String::new(), |mut output, s| {
                                    let _ = write!(output, "{: <61}", s);
                                    output
                                });
                                *a = syn::parse_quote! { #[doc= #doc] };
                            }
                        }
                    }
                }
            }
        } else {
            unreachable!()
        }
    } else {
        unreachable!()
    }
    quote! {
        #item
    }
    .into()
}
