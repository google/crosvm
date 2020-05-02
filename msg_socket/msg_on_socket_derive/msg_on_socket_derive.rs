// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#![recursion_limit = "256"]
extern crate proc_macro;

use std::vec::Vec;

use proc_macro2::{Span, TokenStream};
use quote::{format_ident, quote};
use syn::{
    parse_macro_input, Data, DataEnum, DataStruct, DeriveInput, Fields, Ident, Index, Member, Meta,
    NestedMeta, Type,
};

/// The function that derives the recursive implementation for struct or enum.
#[proc_macro_derive(MsgOnSocket, attributes(msg_on_socket))]
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

struct StructField {
    member: Member,
    ty: Type,
    skipped: bool,
}

fn impl_for_named_struct(name: Ident, ds: DataStruct) -> TokenStream {
    let fields = get_struct_fields(ds);
    let uses_fd_impl = define_uses_fd_for_struct(&fields);
    let buffer_sizes_impls = define_buffer_size_for_struct(&fields);

    let read_buffer = define_read_buffer_for_struct(&name, &fields);
    let write_buffer = define_write_buffer_for_struct(&name, &fields);
    quote! {
        impl msg_socket::MsgOnSocket for #name {
            #uses_fd_impl
            #buffer_sizes_impls
            #read_buffer
            #write_buffer
        }
    }
}

// Flatten struct fields.
fn get_struct_fields(ds: DataStruct) -> Vec<StructField> {
    let fields = match ds.fields {
        Fields::Named(fields_named) => fields_named.named,
        _ => {
            panic!("Struct must have named fields");
        }
    };
    let mut vec = Vec::new();
    for field in fields {
        let member = match field.ident {
            Some(ident) => Member::Named(ident),
            None => panic!("Unknown Error."),
        };
        let ty = field.ty;
        let mut skipped = false;
        for attr in field
            .attrs
            .iter()
            .filter(|attr| attr.path.is_ident("msg_on_socket"))
        {
            match attr.parse_meta().unwrap() {
                Meta::List(meta) => {
                    for nested in meta.nested {
                        match nested {
                            NestedMeta::Meta(Meta::Path(ref meta_path))
                                if meta_path.is_ident("skip") =>
                            {
                                skipped = true;
                            }
                            _ => panic!("unrecognized attribute meta `{}`", quote! { #nested }),
                        }
                    }
                }
                _ => panic!("unrecognized attribute `{}`", quote! { #attr }),
            }
        }
        vec.push(StructField {
            member,
            ty,
            skipped,
        });
    }
    vec
}

fn define_uses_fd_for_struct(fields: &[StructField]) -> TokenStream {
    let field_types: Vec<_> = fields
        .iter()
        .filter(|f| !f.skipped)
        .map(|f| &f.ty)
        .collect();

    if field_types.is_empty() {
        return quote!();
    }

    quote! {
        fn uses_fd() -> bool {
            #(<#field_types>::uses_fd())||*
        }
    }
}

fn define_buffer_size_for_struct(fields: &[StructField]) -> TokenStream {
    let (msg_size, fd_count) = get_fields_buffer_size_sum(fields);
    quote! {
        fn msg_size(&self) -> usize {
            #msg_size
        }
        fn fd_count(&self) -> usize {
            #fd_count
        }
    }
}

fn define_read_buffer_for_struct(_name: &Ident, fields: &[StructField]) -> TokenStream {
    let mut read_fields = Vec::new();
    let mut init_fields = Vec::new();
    for field in fields {
        let ident = match &field.member {
            Member::Named(ident) => ident,
            Member::Unnamed(_) => unreachable!(),
        };
        let name = ident.clone();
        if field.skipped {
            let ty = &field.ty;
            init_fields.push(quote! {
                #name: <#ty>::default()
            });
            continue;
        }
        let read_field = read_from_buffer_and_move_offset(&ident, &field.ty);
        read_fields.push(read_field);
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

fn define_write_buffer_for_struct(_name: &Ident, fields: &[StructField]) -> TokenStream {
    let mut write_fields = Vec::new();
    for field in fields {
        if field.skipped {
            continue;
        }
        let ident = match &field.member {
            Member::Named(ident) => ident,
            Member::Unnamed(_) => unreachable!(),
        };
        let write_field = write_to_buffer_and_move_offset(&ident);
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
    let uses_fd_impl = define_uses_fd_for_enum(&de);
    let buffer_sizes_impls = define_buffer_size_for_enum(&name, &de);
    let read_buffer = define_read_buffer_for_enum(&name, &de);
    let write_buffer = define_write_buffer_for_enum(&name, &de);
    quote! {
        impl msg_socket::MsgOnSocket for #name {
            #uses_fd_impl
            #buffer_sizes_impls
            #read_buffer
            #write_buffer
        }
    }
}

fn define_uses_fd_for_enum(de: &DataEnum) -> TokenStream {
    let mut variant_field_types = Vec::new();
    for variant in &de.variants {
        for variant_field_ty in variant.fields.iter().map(|f| &f.ty) {
            variant_field_types.push(variant_field_ty);
        }
    }

    if variant_field_types.len() == 0 {
        return quote!();
    }

    quote! {
        fn uses_fd() -> bool {
            #(<#variant_field_types>::uses_fd())||*
        }
    }
}

fn define_buffer_size_for_enum(name: &Ident, de: &DataEnum) -> TokenStream {
    let mut msg_size_match_variants = Vec::new();
    let mut fd_count_match_variants = Vec::new();

    for variant in &de.variants {
        let variant_name = &variant.ident;
        match &variant.fields {
            Fields::Named(fields) => {
                let mut tmp_names = Vec::new();
                for field in &fields.named {
                    tmp_names.push(field.ident.clone().unwrap());
                }

                let v = quote! {
                    #name::#variant_name { #(#tmp_names),* } => #(#tmp_names.msg_size())+*,
                };
                msg_size_match_variants.push(v);

                let v = quote! {
                    #name::#variant_name { #(#tmp_names),* } => #(#tmp_names.fd_count())+*,
                };
                fd_count_match_variants.push(v);
            }
            Fields::Unnamed(fields) => {
                let mut tmp_names = Vec::new();
                for idx in 0..fields.unnamed.len() {
                    let tmp_name = format!("enum_field{}", idx);
                    let tmp_name = Ident::new(&tmp_name, Span::call_site());
                    tmp_names.push(tmp_name.clone());
                }

                let v = quote! {
                    #name::#variant_name(#(#tmp_names),*) => #(#tmp_names.msg_size())+*,
                };
                msg_size_match_variants.push(v);

                let v = quote! {
                    #name::#variant_name(#(#tmp_names),*) => #(#tmp_names.fd_count())+*,
                };
                fd_count_match_variants.push(v);
            }
            Fields::Unit => {
                let v = quote! {
                    #name::#variant_name => 0,
                };
                msg_size_match_variants.push(v.clone());
                fd_count_match_variants.push(v);
            }
        }
    }

    quote! {
        fn msg_size(&self) -> usize {
            1 + match self {
                #(#msg_size_match_variants)*
            }
        }
        fn fd_count(&self) -> usize {
            match self {
                #(#fd_count_match_variants)*
            }
        }
    }
}

fn define_read_buffer_for_enum(name: &Ident, de: &DataEnum) -> TokenStream {
    let mut match_variants = Vec::new();
    let de = de.clone();
    for (idx, variant) in de.variants.iter().enumerate() {
        let idx = idx as u8;
        let variant_name = &variant.ident;
        match &variant.fields {
            Fields::Named(fields) => {
                let mut tmp_names = Vec::new();
                let mut read_tmps = Vec::new();
                for f in &fields.named {
                    tmp_names.push(f.ident.clone());
                    let read_tmp =
                        read_from_buffer_and_move_offset(f.ident.as_ref().unwrap(), &f.ty);
                    read_tmps.push(read_tmp);
                }
                let v = quote! {
                    #idx => {
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
                for (idx, field) in fields.unnamed.iter().enumerate() {
                    let tmp_name = format_ident!("enum_field{}", idx);
                    tmp_names.push(tmp_name.clone());
                    let read_tmp = read_from_buffer_and_move_offset(&tmp_name, &field.ty);
                    read_tmps.push(read_tmp);
                }

                let v = quote! {
                    #idx => {
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
                    #idx => Ok((#name::#variant_name, 0)),
                };
                match_variants.push(v);
            }
        }
    }
    quote! {
        unsafe fn read_from_buffer(
            buffer: &[u8],
            fds: &[std::os::unix::io::RawFd],
        ) -> msg_socket::MsgResult<(Self, usize)> {
            let v = buffer.get(0).ok_or(msg_socket::MsgError::WrongMsgBufferSize)?;
            match v {
                #(#match_variants)*
                _ => Err(msg_socket::MsgError::InvalidType),
            }
        }
    }
}

fn define_write_buffer_for_enum(name: &Ident, de: &DataEnum) -> TokenStream {
    let mut match_variants = Vec::new();
    let de = de.clone();
    for (idx, variant) in de.variants.iter().enumerate() {
        let idx = idx as u8;
        let variant_name = &variant.ident;
        match &variant.fields {
            Fields::Named(fields) => {
                let mut tmp_names = Vec::new();
                let mut write_tmps = Vec::new();
                for f in &fields.named {
                    tmp_names.push(f.ident.clone().unwrap());
                    let write_tmp =
                        enum_write_to_buffer_and_move_offset(&f.ident.as_ref().unwrap());
                    write_tmps.push(write_tmp);
                }

                let v = quote! {
                    #name::#variant_name { #(#tmp_names),* } => {
                        buffer[0] = #idx;
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
                for idx in 0..fields.unnamed.len() {
                    let tmp_name = format_ident!("enum_field{}", idx);
                    tmp_names.push(tmp_name.clone());
                    let write_tmp = enum_write_to_buffer_and_move_offset(&tmp_name);
                    write_tmps.push(write_tmp);
                }

                let v = quote! {
                    #name::#variant_name(#(#tmp_names),*) => {
                        buffer[0] = #idx;
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
                        buffer[0] = #idx;
                        Ok(0)
                    }
                };
                match_variants.push(v);
            }
        }
    }

    quote! {
        fn write_to_buffer(
            &self,
            buffer: &mut [u8],
            fds: &mut [std::os::unix::io::RawFd],
        ) -> msg_socket::MsgResult<usize> {
            if buffer.is_empty() {
                return Err(msg_socket::MsgError::WrongMsgBufferSize)
            }
            match self {
                #(#match_variants)*
            }
        }
    }
}

fn enum_write_to_buffer_and_move_offset(name: &Ident) -> TokenStream {
    quote! {
        let o = #name.write_to_buffer(&mut buffer[__offset..], &mut fds[__fd_offset..])?;
        __offset += #name.msg_size();
        __fd_offset += o;
    }
}

/************************** Tuple Impls ********************************************/
fn impl_for_tuple_struct(name: Ident, ds: DataStruct) -> TokenStream {
    let fields = get_tuple_fields(ds);

    let uses_fd_impl = define_uses_fd_for_tuples(&fields);
    let buffer_sizes_impls = define_buffer_size_for_struct(&fields);
    let read_buffer = define_read_buffer_for_tuples(&name, &fields);
    let write_buffer = define_write_buffer_for_tuples(&name, &fields);
    quote! {
        impl msg_socket::MsgOnSocket for #name {
            #uses_fd_impl
            #buffer_sizes_impls
            #read_buffer
            #write_buffer
        }
    }
}

fn get_tuple_fields(ds: DataStruct) -> Vec<StructField> {
    let mut field_idents = Vec::new();
    let fields = match ds.fields {
        Fields::Unnamed(fields_unnamed) => fields_unnamed.unnamed,
        _ => {
            panic!("Tuple struct must have unnamed fields.");
        }
    };
    for (idx, field) in fields.iter().enumerate() {
        let member = Member::Unnamed(Index::from(idx));
        let ty = field.ty.clone();
        field_idents.push(StructField {
            member,
            ty,
            skipped: false,
        });
    }
    field_idents
}

fn define_uses_fd_for_tuples(fields: &[StructField]) -> TokenStream {
    if fields.len() == 0 {
        return quote!();
    }

    let field_types = fields.iter().map(|f| &f.ty);
    quote! {
        fn uses_fd() -> bool {
            #(<#field_types>::uses_fd())||*
        }
    }
}

fn define_read_buffer_for_tuples(name: &Ident, fields: &[StructField]) -> TokenStream {
    let mut read_fields = Vec::new();
    let mut init_fields = Vec::new();
    for (idx, field) in fields.iter().enumerate() {
        let tmp_name = format!("tuple_tmp{}", idx);
        let tmp_name = Ident::new(&tmp_name, Span::call_site());
        let read_field = read_from_buffer_and_move_offset(&tmp_name, &field.ty);
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

fn define_write_buffer_for_tuples(name: &Ident, fields: &[StructField]) -> TokenStream {
    let mut write_fields = Vec::new();
    let mut tmp_names = Vec::new();
    for idx in 0..fields.len() {
        let tmp_name = format_ident!("tuple_tmp{}", idx);
        let write_field = enum_write_to_buffer_and_move_offset(&tmp_name);
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
fn get_fields_buffer_size_sum(fields: &[StructField]) -> (TokenStream, TokenStream) {
    let fields: Vec<_> = fields
        .iter()
        .filter(|f| !f.skipped)
        .map(|f| &f.member)
        .collect();
    if fields.len() > 0 {
        (
            quote! {
                #( self.#fields.msg_size() as usize )+*
            },
            quote! {
                #( self.#fields.fd_count() as usize )+*
            },
        )
    } else {
        (quote!(0), quote!(0))
    }
}

fn read_from_buffer_and_move_offset(name: &Ident, ty: &Type) -> TokenStream {
    quote! {
        let t = <#ty>::read_from_buffer(&buffer[__offset..], &fds[__fd_offset..])?;
        __offset += t.0.msg_size();
        __fd_offset += t.1;
        let #name = t.0;
    }
}

fn write_to_buffer_and_move_offset(name: &Ident) -> TokenStream {
    quote! {
        let o = self.#name.write_to_buffer(&mut buffer[__offset..], &mut fds[__fd_offset..])?;
        __offset += self.#name.msg_size();
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
                fn uses_fd() -> bool {
                    <u8>::uses_fd() || <RawFd>::uses_fd() || <u32>::uses_fd()
                }
                fn msg_size(&self) -> usize {
                    self.a.msg_size() as usize
                        + self.b.msg_size() as usize
                        + self.c.msg_size() as usize
                }
                fn fd_count(&self) -> usize {
                    self.a.fd_count() as usize
                        + self.b.fd_count() as usize
                        + self.c.fd_count() as usize
                }
                unsafe fn read_from_buffer(
                    buffer: &[u8],
                    fds: &[std::os::unix::io::RawFd],
                ) -> msg_socket::MsgResult<(Self, usize)> {
                    let mut __offset = 0usize;
                    let mut __fd_offset = 0usize;
                    let t = <u8>::read_from_buffer(&buffer[__offset..], &fds[__fd_offset..])?;
                    __offset += t.0.msg_size();
                    __fd_offset += t.1;
                    let a = t.0;
                    let t = <RawFd>::read_from_buffer(&buffer[__offset..], &fds[__fd_offset..])?;
                    __offset += t.0.msg_size();
                    __fd_offset += t.1;
                    let b = t.0;
                    let t = <u32>::read_from_buffer(&buffer[__offset..], &fds[__fd_offset..])?;
                    __offset += t.0.msg_size();
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
                    let o = self
                        .a
                        .write_to_buffer(&mut buffer[__offset..], &mut fds[__fd_offset..])?;
                    __offset += self.a.msg_size();
                    __fd_offset += o;
                    let o = self
                        .b
                        .write_to_buffer(&mut buffer[__offset..], &mut fds[__fd_offset..])?;
                    __offset += self.b.msg_size();
                    __fd_offset += o;
                    let o = self
                        .c
                        .write_to_buffer(&mut buffer[__offset..], &mut fds[__fd_offset..])?;
                    __offset += self.c.msg_size();
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
                fn uses_fd() -> bool {
                    <u8>::uses_fd() || <u32>::uses_fd() || <File>::uses_fd()
                }
                fn msg_size(&self) -> usize {
                    self.0.msg_size() as usize
                        + self.1.msg_size() as usize + self.2.msg_size() as usize
                }
                fn fd_count(&self) -> usize {
                    self.0.fd_count() as usize
                        + self.1.fd_count() as usize
                        + self.2.fd_count() as usize
                }
                unsafe fn read_from_buffer(
                    buffer: &[u8],
                    fds: &[std::os::unix::io::RawFd],
                ) -> msg_socket::MsgResult<(Self, usize)> {
                    let mut __offset = 0usize;
                    let mut __fd_offset = 0usize;
                    let t = <u8>::read_from_buffer(&buffer[__offset..], &fds[__fd_offset..])?;
                    __offset += t.0.msg_size();
                    __fd_offset += t.1;
                    let tuple_tmp0 = t.0;
                    let t = <u32>::read_from_buffer(&buffer[__offset..], &fds[__fd_offset..])?;
                    __offset += t.0.msg_size();
                    __fd_offset += t.1;
                    let tuple_tmp1 = t.0;
                    let t = <File>::read_from_buffer(&buffer[__offset..], &fds[__fd_offset..])?;
                    __offset += t.0.msg_size();
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
                    let o = tuple_tmp0.write_to_buffer(&mut buffer[__offset..], &mut fds[__fd_offset..])?;
                    __offset += tuple_tmp0.msg_size();
                    __fd_offset += o;
                    let o = tuple_tmp1.write_to_buffer(&mut buffer[__offset..], &mut fds[__fd_offset..])?;
                    __offset += tuple_tmp1.msg_size();
                    __fd_offset += o;
                    let o = tuple_tmp2.write_to_buffer(&mut buffer[__offset..], &mut fds[__fd_offset..])?;
                    __offset += tuple_tmp2.msg_size();
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
                fn uses_fd() -> bool {
                    <u8>::uses_fd() || <u8>::uses_fd() || <RawFd>::uses_fd()
                }
                fn msg_size(&self) -> usize {
                    1 + match self {
                        MyMsg::A(enum_field0) => enum_field0.msg_size(),
                        MyMsg::B => 0,
                        MyMsg::C { f0, f1 } => f0.msg_size() + f1.msg_size(),
                    }
                }
                fn fd_count(&self) -> usize {
                    match self {
                        MyMsg::A(enum_field0) => enum_field0.fd_count(),
                        MyMsg::B => 0,
                        MyMsg::C { f0, f1 } => f0.fd_count() + f1.fd_count(),
                    }
                }
                unsafe fn read_from_buffer(
                    buffer: &[u8],
                    fds: &[std::os::unix::io::RawFd],
                ) -> msg_socket::MsgResult<(Self, usize)> {
                    let v = buffer
                        .get(0)
                        .ok_or(msg_socket::MsgError::WrongMsgBufferSize)?;
                    match v {
                        0u8 => {
                            let mut __offset = 1usize;
                            let mut __fd_offset = 0usize;
                            let t = <u8>::read_from_buffer(&buffer[__offset..], &fds[__fd_offset..])?;
                            __offset += t.0.msg_size();
                            __fd_offset += t.1;
                            let enum_field0 = t.0;
                            Ok((MyMsg::A(enum_field0), __fd_offset))
                        }
                        1u8 => Ok((MyMsg::B, 0)),
                        2u8 => {
                            let mut __offset = 1usize;
                            let mut __fd_offset = 0usize;
                            let t = <u8>::read_from_buffer(&buffer[__offset..], &fds[__fd_offset..])?;
                            __offset += t.0.msg_size();
                            __fd_offset += t.1;
                            let f0 = t.0;
                            let t = <RawFd>::read_from_buffer(&buffer[__offset..], &fds[__fd_offset..])?;
                            __offset += t.0.msg_size();
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
                    if buffer.is_empty() {
                        return Err(msg_socket::MsgError::WrongMsgBufferSize)
                    }
                    match self {
                        MyMsg::A(enum_field0) => {
                            buffer[0] = 0u8;
                            let mut __offset = 1usize;
                            let mut __fd_offset = 0usize;
                            let o = enum_field0
                                .write_to_buffer(&mut buffer[__offset..], &mut fds[__fd_offset..])?;
                            __offset += enum_field0.msg_size();
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
                            let o = f0.write_to_buffer(&mut buffer[__offset..], &mut fds[__fd_offset..])?;
                            __offset += f0.msg_size();
                            __fd_offset += o;
                            let o = f1.write_to_buffer(&mut buffer[__offset..], &mut fds[__fd_offset..])?;
                            __offset += f1.msg_size();
                            __fd_offset += o;
                            Ok(__fd_offset)
                        }
                    }
                }
            }
        };

        assert_eq!(socket_msg_impl(input).to_string(), expected.to_string());
    }

    #[test]
    fn end_to_end_struct_skip_test() {
        let input: DeriveInput = parse_quote! {
            struct MyMsg {
                #[msg_on_socket(skip)]
                a: u8,
            }
        };

        let expected = quote! {
            impl msg_socket::MsgOnSocket for MyMsg {
                fn msg_size(&self) -> usize {
                    0
                }
                fn fd_count(&self) -> usize {
                    0
                }
                unsafe fn read_from_buffer(
                    buffer: &[u8],
                    fds: &[std::os::unix::io::RawFd],
                ) -> msg_socket::MsgResult<(Self, usize)> {
                    let mut __offset = 0usize;
                    let mut __fd_offset = 0usize;
                    Ok((Self { a: <u8>::default() }, __fd_offset))
                }
                fn write_to_buffer(
                    &self,
                    buffer: &mut [u8],
                    fds: &mut [std::os::unix::io::RawFd],
                ) -> msg_socket::MsgResult<usize> {
                    let mut __offset = 0usize;
                    let mut __fd_offset = 0usize;
                    Ok(__fd_offset)
                }
            }

        };

        assert_eq!(socket_msg_impl(input).to_string(), expected.to_string());
    }
}
