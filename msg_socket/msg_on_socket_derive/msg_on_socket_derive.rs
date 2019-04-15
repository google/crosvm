// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#![recursion_limit = "256"]
extern crate proc_macro;

use std::vec::Vec;

use proc_macro2::{Span, TokenStream};
use quote::quote;
use syn::{parse_macro_input, Data, DataEnum, DataStruct, DeriveInput, Fields, Ident};

/// The function that derives the recursive implementation for struct or enum.
#[proc_macro_derive(MsgOnSocket)]
pub fn msg_on_socket_derive(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let impl_for_input = socket_msg_impl(input);
    impl_for_input.into()
}

fn socket_msg_impl(input: DeriveInput) -> TokenStream {
    if !input.generics.params.is_empty() {
        return quote! {
            compile_error!("derive(SocketMsg) does not support generic parameters");
        };
    }
    match input.data {
        Data::Struct(ds) => {
            if is_named_struct(&ds) {
                impl_for_named_struct(input.ident, ds)
            } else {
                impl_for_tuple_struct(input.ident, ds)
            }
        }
        Data::Enum(de) => impl_for_enum(input.ident, de),
        _ => quote! {
            compile_error!("derive(SocketMsg) only support struct and enum");
        },
    }
}

fn is_named_struct(ds: &DataStruct) -> bool {
    match &ds.fields {
        Fields::Named(_f) => true,
        _ => false,
    }
}

/************************** Named Struct Impls ********************************************/
fn impl_for_named_struct(name: Ident, ds: DataStruct) -> TokenStream {
    let fields = get_struct_fields(ds);
    let fields_types = get_types_from_fields_vec(&fields);
    let buffer_sizes_impls = define_buffer_size_for_struct(&fields_types);

    let read_buffer = define_read_buffer_for_struct(&name, &fields);
    let write_buffer = define_write_buffer_for_struct(&name, &fields);
    quote! {
        impl msg_socket::MsgOnSocket for #name {
            #buffer_sizes_impls
            #read_buffer
            #write_buffer
        }
    }
}

fn get_types_from_fields_vec(v: &[(Ident, syn::Type)]) -> Vec<syn::Type> {
    let mut fields_types = Vec::new();
    for (_i, t) in v {
        fields_types.push(t.clone());
    }
    fields_types
}

// Flatten struct fields.
// "myfield : Type" -> \(ident\("myfield"\), Token\(Type\)\)
fn get_struct_fields(ds: DataStruct) -> Vec<(Ident, syn::Type)> {
    let fields = match ds.fields {
        Fields::Named(fields_named) => fields_named.named,
        _ => {
            panic!("Struct must have named fields");
        }
    };
    let mut vec = Vec::new();
    for field in fields {
        let ident = match field.ident {
            Some(ident) => ident,
            None => panic!("Unknown Error."),
        };
        let ty = field.ty;
        vec.push((ident, ty));
    }
    vec
}

fn define_buffer_size_for_struct(field_types: &[syn::Type]) -> TokenStream {
    let (msg_size, max_fd_count) = get_fields_buffer_size_sum(field_types);
    quote! {
        fn msg_size() -> usize {
            #msg_size
        }
        fn max_fd_count() -> usize {
            #max_fd_count
        }
    }
}

fn define_read_buffer_for_struct(_name: &Ident, fields: &[(Ident, syn::Type)]) -> TokenStream {
    let mut read_fields = Vec::new();
    let mut init_fields = Vec::new();
    for f in fields {
        let read_field = read_from_buffer_and_move_offset(&f.0, &f.1);
        read_fields.push(read_field);
        let name = f.0.clone();
        init_fields.push(quote!(#name));
    }
    quote! {
        unsafe fn read_from_buffer(
            buffer: &[u8],
            fds: &[std::os::unix::io::RawFd],
        ) -> msg_socket::MsgResult<(Self, usize)> {
            let mut __offset = 0usize;
            let mut __fd_offset = 0usize;
            #(#read_fields)*
            Ok((
                Self {
                    #(#init_fields),*
                },
                __fd_offset
            ))
        }
    }
}

fn define_write_buffer_for_struct(_name: &Ident, fields: &[(Ident, syn::Type)]) -> TokenStream {
    let mut write_fields = Vec::new();
    for f in fields {
        let write_field = write_to_buffer_and_move_offset(&f.0, &f.1);
        write_fields.push(write_field);
    }
    quote! {
        fn write_to_buffer(
            &self,
            buffer: &mut [u8],
            fds: &mut [std::os::unix::io::RawFd],
        ) -> msg_socket::MsgResult<usize> {
            let mut __offset = 0usize;
            let mut __fd_offset = 0usize;
            #(#write_fields)*
            Ok(__fd_offset)
        }
    }
}

/************************** Enum Impls ********************************************/
fn impl_for_enum(name: Ident, de: DataEnum) -> TokenStream {
    let variants = get_enum_variant_types(&de);
    let buffer_sizes_impls = define_buffer_size_for_enum(&variants);

    let read_buffer = define_read_buffer_for_enum(&name, &de);
    let write_buffer = define_write_buffer_for_enum(&name, &de);
    quote! {
        impl msg_socket::MsgOnSocket for #name {
            #buffer_sizes_impls
            #read_buffer
            #write_buffer
        }
    }
}

fn define_buffer_size_for_enum(variants: &[(Ident, Vec<syn::Type>)]) -> TokenStream {
    let mut variant_buffer_sizes = Vec::new();
    let mut variant_fd_sizes = Vec::new();
    for v in variants {
        let (msg_size_impl, fd_count_impl) = get_fields_buffer_size_sum(&v.1);
        variant_buffer_sizes.push(msg_size_impl);
        variant_fd_sizes.push(fd_count_impl);
    }
    quote! {
        fn msg_size() -> usize {
            // First byte is used for variant.
            [#(#variant_buffer_sizes,)*].iter().max().unwrap().clone() as usize + 1
        }
        fn max_fd_count() -> usize {
            [#(#variant_fd_sizes,)*].iter().max().unwrap().clone() as usize
        }
    }
}

// Flatten enum variants. Return value = \[variant_name, \[types_of_this_variant\]\]
fn get_enum_variant_types(de: &DataEnum) -> Vec<(Ident, Vec<syn::Type>)> {
    let mut variants = Vec::new();
    let de = de.clone();
    for v in de.variants {
        let name = v.ident;
        match v.fields {
            Fields::Unnamed(fields) => {
                let mut vec = Vec::new();
                for field in fields.unnamed {
                    let ty = field.ty;
                    vec.push(ty);
                }
                variants.push((name, vec));
            }
            Fields::Unit => {
                variants.push((name, Vec::new()));
                continue;
            }
            Fields::Named(fields) => {
                let mut vec = Vec::new();
                for field in fields.named {
                    let ty = field.ty;
                    vec.push(ty);
                }
                variants.push((name, vec));
            }
        };
    }
    variants
}

fn define_read_buffer_for_enum(name: &Ident, de: &DataEnum) -> TokenStream {
    let mut match_variants = Vec::new();
    let de = de.clone();
    let mut i = 0u8;
    for v in de.variants {
        let variant_name = v.ident;
        match v.fields {
            Fields::Named(fields) => {
                let mut tmp_names = Vec::new();
                let mut read_tmps = Vec::new();
                for f in fields.named {
                    tmp_names.push(f.ident.clone());
                    let read_tmp = read_from_buffer_and_move_offset(&f.ident.unwrap(), &f.ty);
                    read_tmps.push(read_tmp);
                }
                let v = quote! {
                    #i => {
                        let mut __offset = 1usize;
                        let mut __fd_offset = 0usize;
                        #(#read_tmps)*
                        Ok((#name::#variant_name { #(#tmp_names),* }, __fd_offset))
                    }
                };
                match_variants.push(v);
            }
            Fields::Unnamed(fields) => {
                let mut tmp_names = Vec::new();
                let mut read_tmps = Vec::new();
                let mut j = 0usize;
                for f in fields.unnamed {
                    let tmp_name = format!("enum_variant_tmp{}", j);
                    let tmp_name = Ident::new(&tmp_name, Span::call_site());
                    tmp_names.push(tmp_name.clone());
                    let read_tmp = read_from_buffer_and_move_offset(&tmp_name, &f.ty);
                    read_tmps.push(read_tmp);
                    j += 1;
                }

                let v = quote! {
                    #i => {
                        let mut __offset = 1usize;
                        let mut __fd_offset = 0usize;
                        #(#read_tmps)*
                        Ok((#name::#variant_name( #(#tmp_names),*), __fd_offset))
                    }
                };
                match_variants.push(v);
            }
            Fields::Unit => {
                let v = quote! {
                    #i => Ok((#name::#variant_name, 0)),
                };
                match_variants.push(v);
            }
        }
        i += 1;
    }
    quote! {
        unsafe fn read_from_buffer(
            buffer: &[u8],
            fds: &[std::os::unix::io::RawFd],
        ) -> msg_socket::MsgResult<(Self, usize)> {
            let v = buffer[0];
            match v {
                #(#match_variants)*
                _ => Err(msg_socket::MsgError::InvalidType),
            }
        }
    }
}

fn define_write_buffer_for_enum(name: &Ident, de: &DataEnum) -> TokenStream {
    let mut match_variants = Vec::new();
    let mut i = 0u8;
    let de = de.clone();
    for v in de.variants {
        let variant_name = v.ident;
        match v.fields {
            Fields::Named(fields) => {
                let mut tmp_names = Vec::new();
                let mut write_tmps = Vec::new();
                for f in fields.named {
                    tmp_names.push(f.ident.clone().unwrap());
                    let write_tmp = enum_write_to_buffer_and_move_offset(&f.ident.unwrap(), &f.ty);
                    write_tmps.push(write_tmp);
                }

                let v = quote! {
                    #name::#variant_name { #(#tmp_names),* } => {
                        buffer[0] = #i;
                        let mut __offset = 1usize;
                        let mut __fd_offset = 0usize;
                        #(#write_tmps)*
                        Ok(__fd_offset)
                    }
                };
                match_variants.push(v);
            }
            Fields::Unnamed(fields) => {
                let mut tmp_names = Vec::new();
                let mut write_tmps = Vec::new();
                let mut j = 0usize;
                for f in fields.unnamed {
                    let tmp_name = format!("enum_variant_tmp{}", j);
                    let tmp_name = Ident::new(&tmp_name, Span::call_site());
                    tmp_names.push(tmp_name.clone());
                    let write_tmp = enum_write_to_buffer_and_move_offset(&tmp_name, &f.ty);
                    write_tmps.push(write_tmp);
                    j += 1;
                }

                let v = quote! {
                    #name::#variant_name(#(#tmp_names),*) => {
                        buffer[0] = #i;
                        let mut __offset = 1usize;
                        let mut __fd_offset = 0usize;
                        #(#write_tmps)*
                        Ok(__fd_offset)
                    }
                };
                match_variants.push(v);
            }
            Fields::Unit => {
                let v = quote! {
                    #name::#variant_name => {
                        buffer[0] = #i;
                        Ok(0)
                    }
                };
                match_variants.push(v);
            }
        }
        i += 1;
    }

    quote! {
        fn write_to_buffer(
            &self,
            buffer: &mut [u8],
            fds: &mut [std::os::unix::io::RawFd],
        ) -> msg_socket::MsgResult<usize> {
            match self {
                #(#match_variants)*
            }
        }
    }
}

fn enum_write_to_buffer_and_move_offset(name: &Ident, ty: &syn::Type) -> TokenStream {
    quote! {
        let o = #name.write_to_buffer(&mut buffer[__offset..], &mut fds[__fd_offset..])?;
        __offset += <#ty>::msg_size();
        __fd_offset += o;
    }
}

/************************** Tuple Impls ********************************************/
fn impl_for_tuple_struct(name: Ident, ds: DataStruct) -> TokenStream {
    let types = get_tuple_types(ds);

    let buffer_sizes_impls = define_buffer_size_for_struct(&types);

    let read_buffer = define_read_buffer_for_tuples(&name, &types);
    let write_buffer = define_write_buffer_for_tuples(&name, &types);
    quote! {
        impl msg_socket::MsgOnSocket for #name {
            #buffer_sizes_impls
            #read_buffer
            #write_buffer
        }
    }
}

fn get_tuple_types(ds: DataStruct) -> Vec<syn::Type> {
    let mut types = Vec::new();
    let fields = match ds.fields {
        Fields::Unnamed(fields_unnamed) => fields_unnamed.unnamed,
        _ => {
            panic!("Tuple struct must have unnamed fields.");
        }
    };
    for field in fields {
        let ty = field.ty;
        types.push(ty);
    }
    types
}

fn define_read_buffer_for_tuples(name: &Ident, fields: &[syn::Type]) -> TokenStream {
    let mut read_fields = Vec::new();
    let mut init_fields = Vec::new();
    for i in 0..fields.len() {
        let tmp_name = format!("tuple_tmp{}", i);
        let tmp_name = Ident::new(&tmp_name, Span::call_site());
        let read_field = read_from_buffer_and_move_offset(&tmp_name, &fields[i]);
        read_fields.push(read_field);
        init_fields.push(quote!(#tmp_name));
    }

    quote! {
        unsafe fn read_from_buffer(
            buffer: &[u8],
            fds: &[std::os::unix::io::RawFd],
        ) -> msg_socket::MsgResult<(Self, usize)> {
            let mut __offset = 0usize;
            let mut __fd_offset = 0usize;
            #(#read_fields)*
            Ok((
                #name (
                    #(#init_fields),*
                ),
                __fd_offset
            ))
        }
    }
}

fn define_write_buffer_for_tuples(name: &Ident, fields: &[syn::Type]) -> TokenStream {
    let mut write_fields = Vec::new();
    let mut tmp_names = Vec::new();
    for i in 0..fields.len() {
        let tmp_name = format!("tuple_tmp{}", i);
        let tmp_name = Ident::new(&tmp_name, Span::call_site());
        let write_field = enum_write_to_buffer_and_move_offset(&tmp_name, &fields[i]);
        write_fields.push(write_field);
        tmp_names.push(tmp_name);
    }
    quote! {
        fn write_to_buffer(
            &self,
            buffer: &mut [u8],
            fds: &mut [std::os::unix::io::RawFd],
        ) -> msg_socket::MsgResult<usize> {
            let mut __offset = 0usize;
            let mut __fd_offset = 0usize;
            let #name( #(#tmp_names),* ) = self;
            #(#write_fields)*
            Ok(__fd_offset)
        }
    }
}
/************************** Helpers ********************************************/
fn get_fields_buffer_size_sum(field_types: &[syn::Type]) -> (TokenStream, TokenStream) {
    if field_types.len() > 0 {
        (
            quote! {
                #( <#field_types>::msg_size() as usize )+*
            },
            quote! {
                #( <#field_types>::max_fd_count() as usize )+*
            },
        )
    } else {
        (quote!(0), quote!(0))
    }
}

fn read_from_buffer_and_move_offset(name: &Ident, ty: &syn::Type) -> TokenStream {
    quote! {
        let t = <#ty>::read_from_buffer(&buffer[__offset..], &fds[__fd_offset..])?;
        __offset += <#ty>::msg_size();
        __fd_offset += t.1;
        let #name = t.0;
    }
}

fn write_to_buffer_and_move_offset(name: &Ident, ty: &syn::Type) -> TokenStream {
    quote! {
        let o = self.#name.write_to_buffer(&mut buffer[__offset..], &mut fds[__fd_offset..])?;
        __offset += <#ty>::msg_size();
        __fd_offset += o;
    }
}

#[cfg(test)]
mod tests {
    use crate::socket_msg_impl;
    use quote::quote;
    use syn::{parse_quote, DeriveInput};

    #[test]
    fn end_to_end_struct_test() {
        let input: DeriveInput = parse_quote! {
            struct MyMsg {
                a: u8,
                b: RawFd,
                c: u32,
            }
        };

        let expected = quote! {
            impl msg_socket::MsgOnSocket for MyMsg {
                fn msg_size() -> usize {
                    <u8>::msg_size() as usize
                        + <RawFd>::msg_size() as usize
                        + <u32>::msg_size() as usize
                }
                fn max_fd_count() -> usize {
                    <u8>::max_fd_count() as usize
                        + <RawFd>::max_fd_count() as usize
                        + <u32>::max_fd_count() as usize
                }
                unsafe fn read_from_buffer(
                    buffer: &[u8],
                    fds: &[std::os::unix::io::RawFd],
                ) -> msg_socket::MsgResult<(Self, usize)> {
                    let mut __offset = 0usize;
                    let mut __fd_offset = 0usize;
                    let t = <u8>::read_from_buffer(&buffer[__offset..], &fds[__fd_offset..])?;
                    __offset += <u8>::msg_size();
                    __fd_offset += t.1;
                    let a = t.0;
                    let t = <RawFd>::read_from_buffer(&buffer[__offset..], &fds[__fd_offset..])?;
                    __offset += <RawFd>::msg_size();
                    __fd_offset += t.1;
                    let b = t.0;
                    let t = <u32>::read_from_buffer(&buffer[__offset..], &fds[__fd_offset..])?;
                    __offset += <u32>::msg_size();
                    __fd_offset += t.1;
                    let c = t.0;
                    Ok((Self { a, b, c }, __fd_offset))
                }
                fn write_to_buffer(
                    &self,
                    buffer: &mut [u8],
                    fds: &mut [std::os::unix::io::RawFd],
                ) -> msg_socket::MsgResult<usize> {
                    let mut __offset = 0usize;
                    let mut __fd_offset = 0usize;
                    let o = self.a
                        .write_to_buffer(&mut buffer[__offset..], &mut fds[__fd_offset..])?;
                    __offset += <u8>::msg_size();
                    __fd_offset += o;
                    let o = self.b
                        .write_to_buffer(&mut buffer[__offset..], &mut fds[__fd_offset..])?;
                    __offset += <RawFd>::msg_size();
                    __fd_offset += o;
                    let o = self.c
                        .write_to_buffer(&mut buffer[__offset..], &mut fds[__fd_offset..])?;
                    __offset += <u32>::msg_size();
                    __fd_offset += o;
                    Ok(__fd_offset)
                }
            }
        };

        assert_eq!(socket_msg_impl(input).to_string(), expected.to_string());
    }

    #[test]
    fn end_to_end_tuple_struct_test() {
        let input: DeriveInput = parse_quote! {
            struct MyMsg(u8, u32, File);
        };

        let expected = quote! {
            impl msg_socket::MsgOnSocket for MyMsg {
                fn msg_size() -> usize {
                    <u8>::msg_size() as usize
                        + <u32>::msg_size() as usize
                        + <File>::msg_size() as usize
                }
                fn max_fd_count() -> usize {
                    <u8>::max_fd_count() as usize
                        + <u32>::max_fd_count() as usize
                        + <File>::max_fd_count() as usize
                }
                unsafe fn read_from_buffer(
                    buffer: &[u8],
                    fds: &[std::os::unix::io::RawFd],
                ) -> msg_socket::MsgResult<(Self, usize)> {
                    let mut __offset = 0usize;
                    let mut __fd_offset = 0usize;
                    let t = <u8>::read_from_buffer(&buffer[__offset..], &fds[__fd_offset..])?;
                    __offset += <u8>::msg_size();
                    __fd_offset += t.1;
                    let tuple_tmp0 = t.0;
                    let t = <u32>::read_from_buffer(&buffer[__offset..], &fds[__fd_offset..])?;
                    __offset += <u32>::msg_size();
                    __fd_offset += t.1;
                    let tuple_tmp1 = t.0;
                    let t = <File>::read_from_buffer(&buffer[__offset..], &fds[__fd_offset..])?;
                    __offset += <File>::msg_size();
                    __fd_offset += t.1;
                    let tuple_tmp2 = t.0;
                    Ok((MyMsg(tuple_tmp0, tuple_tmp1, tuple_tmp2), __fd_offset))
                }
                fn write_to_buffer(
                    &self,
                    buffer: &mut [u8],
                    fds: &mut [std::os::unix::io::RawFd],
                ) -> msg_socket::MsgResult<usize> {
                    let mut __offset = 0usize;
                    let mut __fd_offset = 0usize;
                    let MyMsg(tuple_tmp0, tuple_tmp1, tuple_tmp2) = self;
                    let o = tuple_tmp0
                        .write_to_buffer(&mut buffer[__offset..], &mut fds[__fd_offset..])?;
                    __offset += <u8>::msg_size();
                    __fd_offset += o;
                    let o = tuple_tmp1
                        .write_to_buffer(&mut buffer[__offset..], &mut fds[__fd_offset..])?;
                    __offset += <u32>::msg_size();
                    __fd_offset += o;
                    let o = tuple_tmp2
                        .write_to_buffer(&mut buffer[__offset..], &mut fds[__fd_offset..])?;
                    __offset += <File>::msg_size();
                    __fd_offset += o;
                    Ok(__fd_offset)
                }
            }
        };

        assert_eq!(socket_msg_impl(input).to_string(), expected.to_string());
    }

    #[test]
    fn end_to_end_enum_test() {
        let input: DeriveInput = parse_quote! {
            enum MyMsg {
                A(u8),
                B,
                C {
                    f0: u8,
                    f1: RawFd,
                },
            }
        };

        let expected = quote! {
            impl msg_socket::MsgOnSocket for MyMsg {
                fn msg_size() -> usize {
                    [
                        <u8>::msg_size() as usize,
                        0,
                        <u8>::msg_size() as usize + <RawFd>::msg_size() as usize,
                    ].iter()
                        .max().unwrap().clone() as usize+ 1
                }
                fn max_fd_count() -> usize {
                    [
                        <u8>::max_fd_count() as usize,
                        0,
                        <u8>::max_fd_count() as usize + <RawFd>::max_fd_count() as usize,
                    ].iter()
                        .max().unwrap().clone() as usize
                }
                unsafe fn read_from_buffer(
                    buffer: &[u8],
                    fds: &[std::os::unix::io::RawFd],
                ) -> msg_socket::MsgResult<(Self, usize)> {
                    let v = buffer[0];
                    match v {
                        0u8 => {
                            let mut __offset = 1usize;
                            let mut __fd_offset = 0usize;
                            let t =
                                <u8>::read_from_buffer(&buffer[__offset..], &fds[__fd_offset..])?;
                            __offset += <u8>::msg_size();
                            __fd_offset += t.1;
                            let enum_variant_tmp0 = t.0;
                            Ok((MyMsg::A(enum_variant_tmp0), __fd_offset))
                        }
                        1u8 => Ok((MyMsg::B, 0)),
                        2u8 => {
                            let mut __offset = 1usize;
                            let mut __fd_offset = 0usize;
                            let t =
                                <u8>::read_from_buffer(&buffer[__offset..], &fds[__fd_offset..])?;
                            __offset += <u8>::msg_size();
                            __fd_offset += t.1;
                            let f0 = t.0;
                            let t = <RawFd>::read_from_buffer(
                                &buffer[__offset..],
                                &fds[__fd_offset..]
                            )?;
                            __offset += <RawFd>::msg_size();
                            __fd_offset += t.1;
                            let f1 = t.0;
                            Ok((MyMsg::C { f0, f1 }, __fd_offset))
                        }
                        _ => Err(msg_socket::MsgError::InvalidType),
                    }
                }
                fn write_to_buffer(
                    &self,
                    buffer: &mut [u8],
                    fds: &mut [std::os::unix::io::RawFd],
                ) -> msg_socket::MsgResult<usize> {
                    match self {
                        MyMsg::A(enum_variant_tmp0) => {
                            buffer[0] = 0u8;
                            let mut __offset = 1usize;
                            let mut __fd_offset = 0usize;
                            let o = enum_variant_tmp0
                                .write_to_buffer(&mut buffer[__offset..], &mut fds[__fd_offset..])?;
                            __offset += <u8>::msg_size();
                            __fd_offset += o;
                            Ok(__fd_offset)
                        }
                        MyMsg::B => {
                            buffer[0] = 1u8;
                            Ok(0)
                        }
                        MyMsg::C { f0, f1 } => {
                            buffer[0] = 2u8;
                            let mut __offset = 1usize;
                            let mut __fd_offset = 0usize;
                            let o = f0
                                .write_to_buffer(&mut buffer[__offset..], &mut fds[__fd_offset..])?;
                            __offset += <u8>::msg_size();
                            __fd_offset += o;
                            let o = f1
                                .write_to_buffer(&mut buffer[__offset..], &mut fds[__fd_offset..])?;
                            __offset += <RawFd>::msg_size();
                            __fd_offset += o;
                            Ok(__fd_offset)
                        }
                    }
                }
            }

        };

        assert_eq!(socket_msg_impl(input).to_string(), expected.to_string());
    }
}
