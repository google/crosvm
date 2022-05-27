// Copyright 2022 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use quote::quote;
use syn::parse::Parser;

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

/// attribute macro to allow using `catch-all` style subcommand structs to
/// use temporarily before migrating to real ones
/// Note: USE ONLY ON EMPTY STRUCTS
/// Adds a field 'pub args: Vec<String>' containing all remaining arguments.
#[proc_macro_attribute]
pub fn generate_catchall_args(
    _attr: proc_macro::TokenStream,
    item: proc_macro::TokenStream,
) -> proc_macro::TokenStream {
    let mut internal_struct = syn::parse_macro_input!(item as syn::Item);
    let mut wrapper_struct = internal_struct.clone();
    // add args field
    let mut internal_struct = match &mut internal_struct {
        syn::Item::Struct(ref mut s) => {
            match &mut s.fields {
                syn::Fields::Named(fields) => fields.named.push(
                    syn::Field::parse_named
                        .parse2(quote! { #[argh(positional)] pub args: Vec<String> })
                        .unwrap(),
                ),
                _ => unreachable!(),
            };
            s
        }
        _ => unreachable!(),
    };
    // add args field
    let wrapper_struct = match &mut wrapper_struct {
        syn::Item::Struct(ref mut s) => {
            match &mut s.fields {
                syn::Fields::Named(fields) => fields.named.push(
                    syn::Field::parse_named
                        .parse2(quote! { pub args: Vec<String> })
                        .unwrap(),
                ),
                _ => unreachable!(),
            };
            s
        }
        _ => unreachable!(),
    };

    // Rename internal
    let name = internal_struct.ident.clone();
    internal_struct.ident = quote::format_ident!("{}CatchAllInternal", name);
    let internal_name = &internal_struct.ident;
    // Remove argh from wrapper
    wrapper_struct.attrs.clear();

    // Generate FromArgs and SubCommand for Wrapper

    let wrapper_impl = quote! {
        impl argh::FromArgs for #name {
            fn from_args(cmd_name: &[&str], args: &[&str]) -> std::result::Result<Self, argh::EarlyExit> {
                let args: Vec<&str> = std::iter::once("--").chain(args.iter().copied()).collect();
                <#internal_name as argh::FromArgs>::from_args(cmd_name, &args[..])
                    .map(|v| Self { args: v.args })
            }
            fn redact_arg_values(cmd_name: &[&str], args: &[&str]) -> std::result::Result<Vec<String>, argh::EarlyExit> {
                let args: Vec<&str> = std::iter::once("--").chain(args.iter().copied()).collect();
                <#internal_name as argh::FromArgs>::redact_arg_values(cmd_name, &args[..])
            }
        }
        impl argh::SubCommand for #name {
            const COMMAND: &'static argh::CommandInfo = <#internal_name as argh::SubCommand>::COMMAND;
        }
    };

    quote! {
        #[derive(argh::FromArgs)]
        #internal_struct
        #wrapper_struct
        #wrapper_impl
    }
    .into()
}
