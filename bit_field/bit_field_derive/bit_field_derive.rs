// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#![recursion_limit = "256"]
extern crate proc_macro;
extern crate proc_macro2;

#[macro_use]
extern crate quote;

#[cfg_attr(test, macro_use)]
extern crate syn;

use std::string::String;
use std::vec::Vec;

use proc_macro::TokenStream;
use proc_macro2::{Span, TokenNode};
use quote::Tokens;
use syn::{Attribute, Data, DeriveInput, Fields, Ident};

type Result<T> = std::result::Result<T, String>;

/// The function that derives the actual implementation.
#[proc_macro_derive(BitField, attributes(passthrough))]
pub fn bitfield(input: TokenStream) -> TokenStream {
    bitfield_impl(syn::parse(input).unwrap()).into()
}

fn bitfield_impl(ast: DeriveInput) -> Tokens {
    if !ast.generics.params.is_empty() {
        return quote! {
            compile_error!("derive(BitField) does not support generic parameters");
        };
    }

    let name = ast.ident.to_string();
    let struct_name = match get_struct_name(name.as_str()) {
        Some(name) => name,
        None => {
            return quote! {
                compile_error!("Check schema name, it should end with Schema.");
            };
        }
    };

    let ident = Ident::new(struct_name, Span::call_site());
    let test_mod_ident = Ident::new(
        format!("test_{}", struct_name.to_lowercase()).as_str(),
        Span::call_site(),
    );
    // Name of the struct
    let name = quote!(#ident);
    let vis = ast.vis.clone();
    let attrs = match get_attrs(ast.attrs.as_slice()) {
        Ok(attrs) => attrs,
        Err(err_str) => {
            return quote! {
                compile_error!(#err_str);
            };
        }
    };
    // Visibility.
    let vis = quote!(#vis);
    let fields = match get_struct_fields(ast) {
        Ok(f) => f,
        Err(err_str) => {
            return quote! {
                compile_error!(#err_str);
            }
        }
    };
    let struct_def = get_struct_def(&vis, &name, fields.as_slice());
    let bits_impl = get_bits_impl(&name);
    let fields_impl = get_fields_impl(fields.as_slice());
    let tests_impl = get_tests_impl(&name, fields.as_slice());
    let debug_fmt_impl = get_debug_fmt_impl(&name, fields.as_slice());
    quote!(
        #(#attrs)*
        #struct_def
        #bits_impl
        impl #name {
            #(#fields_impl)*
        }

        #debug_fmt_impl
        #[cfg(test)]
        mod #test_mod_ident {
            use super::*;
            #(#tests_impl)*
        }
        )
}

// Generate struct name from schema_name. "MyTypeSchema" -> "MyType".
fn get_struct_name(schema_name: &str) -> Option<&str> {
    let struct_name = schema_name.trim_right_matches("Schema");
    if struct_name.len() + "Schema".len() != schema_name.len() {
        return None;
    }
    if struct_name.len() == 0 {
        return None;
    }
    Some(struct_name)
}

// Unwrap ast to get the named fields. Anything unexpected will be treated as an
// error.
// We only care about field names and types.
// "myfield : BitField3" -> ("myfield", Token(BitField3))
fn get_struct_fields(ast: DeriveInput) -> Result<Vec<(String, Tokens)>> {
    let fields = match ast.data {
        Data::Struct(data_struct) => match data_struct.fields {
            Fields::Named(fields_named) => fields_named.named,
            _ => {
                return Err(format!("Schema must have named fields."));
            }
        },
        _ => {
            return Err(format!("Schema must be a struct."));
        }
    };
    let mut vec = Vec::new();
    for field in fields {
        let ident = match field.ident {
            Some(ident) => ident,
            None => {
                return Err(format!(
                    "Unknown Error. bit_field_derive library might have a bug."
                ))
            }
        };
        let ty = field.ty;
        vec.push((ident.to_string(), quote!(#ty)));
    }

    Ok(vec)
}

// We only support attributes of the form #[passthrough(derive(Clone))].
// Any other attribute will cause undefined behavior.
fn get_attrs(attrs: &[Attribute]) -> Result<Vec<Tokens>> {
    let mut attr_tokens = Vec::new();
    for a in attrs {
        let tts = a.tts.clone();
        for t in tts {
            match t.kind {
                TokenNode::Group(_d, g) => attr_tokens.push(quote!(#[#g])),
                _ => return Err(format!("Unsupported attribute.")),
            }
        }
    }
    Ok(attr_tokens)
}

fn get_struct_def(vis: &Tokens, name: &Tokens, fields: &[(String, Tokens)]) -> Tokens {
    let mut field_types = Vec::new();
    for &(ref _name, ref ty) in fields {
        field_types.push(ty.clone());
    }

    // It will be something like:
    // "(BitField1::FIELD_WIDTH + BitField3::FIELD_WIDTH + BitField4::FIELD_WIDTH) / 8)"
    let data_size_in_bytes = quote!(
            ( #( #field_types::FIELD_WIDTH as usize )+* ) / 8
        );
    quote! (
        #vis struct #name {
            data: [u8; #data_size_in_bytes],
        }
        impl #name {
            pub fn new() -> #name {
                #name { data: [0; #data_size_in_bytes], }
            }
        }
    )
}

// Implement setter and getter for all fields.
fn get_fields_impl(fields: &[(String, Tokens)]) -> Vec<Tokens> {
    let mut impls = Vec::new();
    // This vec keeps track of types before this field, used to generate the offset.
    let mut current_types = vec![quote!(BitField0)];

    for &(ref name, ref ty) in fields {
        // Creating two copies of current types. As they are going to be moved in quote!.
        let ct0 = current_types.clone();
        let ct1 = current_types.clone();
        let getter_ident = Ident::new(format!("get_{}", name).as_str(), Span::call_site());
        let setter_ident = Ident::new(format!("set_{}", name).as_str(), Span::call_site());
        impls.push(quote!(
                pub fn #getter_ident(&self) -> <#ty as BitFieldSpecifier>::DefaultFieldType {
                    let offset = #(#ct0::FIELD_WIDTH as usize)+*;
                    return self.get(offset, #ty::FIELD_WIDTH) as
                        <#ty as BitFieldSpecifier>::DefaultFieldType;
                }

                pub fn #setter_ident(&mut self, val: <#ty as BitFieldSpecifier>::DefaultFieldType) {
                    debug_assert!((val as u64) <= #ty::FIELD_MAX);
                    let offset = #(#ct1::FIELD_WIDTH as usize)+*;
                    return self.set(offset, #ty::FIELD_WIDTH, val as u64);
                }
                ));
        current_types.push(ty.clone());
    }
    impls
}

// Implement setter and getter for all fields.
fn get_debug_fmt_impl(name: &Tokens, fields: &[(String, Tokens)]) -> Tokens {
    // print fields:
    let mut impls = Vec::new();
    for &(ref name, ref _ty) in fields {
        let getter_ident = Ident::new(format!("get_{}", name).as_str(), Span::call_site());
        impls.push(quote!(
                .field(#name, &self.#getter_ident())
                ));
    }

    let name_str = format!("{}", name);
    quote! (
        impl std::fmt::Debug for #name {
            fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.debug_struct(#name_str)
                #(#impls)*
                    .finish()
            }
        }
        )
}

// Implement test.
fn get_tests_impl(struct_name: &Tokens, fields: &[(String, Tokens)]) -> Vec<Tokens> {
    let mut field_types = Vec::new();
    for &(ref _name, ref ty) in fields {
        field_types.push(ty.clone());
    }
    let field_types2 = field_types.clone();
    let mut impls = Vec::new();
    impls.push(quote!(
                #[test]
                fn test_total_size() {
                    let total_size = #(#field_types::FIELD_WIDTH as usize)+*;
                    assert_eq!(total_size % 8, 0);
                }));
    impls.push(quote!(#[test]
    fn test_bits_boundary() {
        let fields_sizes = vec![#(#field_types2::FIELD_WIDTH as usize),*];
        let mut sum = 0usize;
        for s in fields_sizes {
            if sum % 64 == 0 {
                assert!(s <= 64);
            } else {
                if (sum + s) % 64 != 0 {
                    assert_eq!(sum / 64, (sum + s) / 64);
                }
            }
            sum += s;
        }
    }));

    for &(ref name, ref ty) in fields {
        let testname = Ident::new(
            format!("test_{}", name.as_str()).as_str(),
            Span::call_site(),
        );
        let getter_ident = Ident::new(format!("get_{}", name.as_str()).as_str(), Span::call_site());
        let setter_ident = Ident::new(format!("set_{}", name.as_str()).as_str(), Span::call_site());
        impls.push(quote!(
                #[test]
                fn #testname() {
                    let mut a = #struct_name::new();
                    assert_eq!(a.#getter_ident() as u64, 0);
                    a.#setter_ident(#ty::FIELD_MAX as <#ty as BitFieldSpecifier>::DefaultFieldType);
                    assert_eq!(a.#getter_ident() as u64, #ty::FIELD_MAX);
                }
                ));
    }
    impls
}

fn get_bits_impl(name: &Tokens) -> Tokens {
    quote!(
        impl #name {
            #[inline]
            fn check_access(&self, offset: usize, width: u8) {
                debug_assert!(width <= 64);
                debug_assert!(offset / 8 < self.data.len());
                debug_assert!((offset + (width as usize)) <= (self.data.len() * 8));
            }


            #[inline]
            pub fn get_bit(&self, offset: usize) -> bool {
                self.check_access(offset, 1);

                let byte_index = offset / 8;
                let bit_offset = offset % 8;

                let byte = self.data[byte_index];
                let mask = 1 << bit_offset;

                byte & mask == mask
            }

            #[inline]
            pub fn set_bit(&mut self, offset: usize, val: bool) {
                self.check_access(offset, 1);

                let byte_index = offset / 8;
                let bit_offset = offset % 8;

                let byte = &mut self.data[byte_index];
                let mask = 1 << bit_offset;

                if val {
                    *byte |= mask;
                } else {
                    *byte &= !mask;
                }
            }

            #[inline]
            pub fn get(&self, offset: usize, width: u8) -> u64 {
                self.check_access(offset, width);
                let mut val = 0;

                for i in 0..(width as usize) {
                    if self.get_bit(i + offset) {
                        val |= 1 << i;
                    }
                }

                val
            }

            #[inline]
            pub fn set(&mut self, offset: usize, width: u8, val: u64) {
                self.check_access(offset, width);

                for i in 0..(width as usize) {
                    let mask = 1 << i;
                    let val_bit_is_set = val & mask == mask;
                    self.set_bit(i + offset, val_bit_is_set);
                }
            }
        }
        )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn struct_name_parsing_valid() {
        assert_eq!(get_struct_name("MyBitFieldSchema"), Some("MyBitField"));
    }

    #[test]
    fn struct_name_parsing_invalid() {
        assert_eq!(get_struct_name("MyBitFieldS"), None);
    }

    #[test]
    fn end_to_end() {
        let input: DeriveInput = parse_quote! {
            #[passthrough(derive(Clone))]
            struct MyBitFieldSchema {
                a: BitField1,
                b: BitField2,
                c: BitField5,
            }
        };

        let expected = quote! {
            #[derive(Clone)]
            struct MyBitField {
                data: [u8; (BitField1::FIELD_WIDTH as usize
                    + BitField2::FIELD_WIDTH as usize
                    + BitField5::FIELD_WIDTH as usize) / 8],
            }
            impl MyBitField {
                pub fn new() -> MyBitField {
                    MyBitField {
                        data: [0; (BitField1::FIELD_WIDTH as usize
                            + BitField2::FIELD_WIDTH as usize
                            + BitField5::FIELD_WIDTH as usize) / 8],
                    }
                }
            }
            impl MyBitField {
                #[inline]
                fn check_access(&self, offset: usize, width: u8) {
                    debug_assert!(width <= 64);
                    debug_assert!(offset / 8 < self.data.len());
                    debug_assert!((offset + (width as usize)) <= (self.data.len() * 8));
                }
                #[inline]
                pub fn get_bit(&self, offset: usize) -> bool {
                    self.check_access(offset, 1);
                    let byte_index = offset / 8;
                    let bit_offset = offset % 8;
                    let byte = self.data[byte_index];
                    let mask = 1 << bit_offset;
                    byte & mask == mask
                }
                #[inline]
                pub fn set_bit(&mut self, offset: usize, val: bool) {
                    self.check_access(offset, 1);
                    let byte_index = offset / 8;
                    let bit_offset = offset % 8;
                    let byte = &mut self.data[byte_index];
                    let mask = 1 << bit_offset;
                    if val {
                        *byte |= mask;
                    } else {
                        *byte &= !mask;
                    }
                }
                #[inline]
                pub fn get(&self, offset: usize, width: u8) -> u64 {
                    self.check_access(offset, width);
                    let mut val = 0;
                    for i in 0..(width as usize) {
                        if self.get_bit(i + offset) {
                            val |= 1 << i;
                        }
                    }
                    val
                }
                #[inline]
                pub fn set(&mut self, offset: usize, width: u8, val: u64) {
                    self.check_access(offset, width);
                    for i in 0..(width as usize) {
                        let mask = 1 << i;
                        let val_bit_is_set = val & mask == mask;
                        self.set_bit(i + offset, val_bit_is_set);
                    }
                }
            }
            impl MyBitField {
                pub fn get_a(&self) -> <BitField1 as BitFieldSpecifier>::DefaultFieldType {
                    let offset = BitField0::FIELD_WIDTH as usize;
                    return self.get(offset, BitField1::FIELD_WIDTH)
                        as <BitField1 as BitFieldSpecifier>::DefaultFieldType;
                }
                pub fn set_a(&mut self, val: <BitField1 as BitFieldSpecifier>::DefaultFieldType) {
                    debug_assert!((val as u64) <= BitField1::FIELD_MAX);
                    let offset = BitField0::FIELD_WIDTH as usize;
                    return self.set(offset, BitField1::FIELD_WIDTH, val as u64);
                }
                pub fn get_b(&self) -> <BitField2 as BitFieldSpecifier>::DefaultFieldType {
                    let offset = BitField0::FIELD_WIDTH as usize + BitField1::FIELD_WIDTH as usize;
                    return self.get(offset, BitField2::FIELD_WIDTH)
                        as <BitField2 as BitFieldSpecifier>::DefaultFieldType;
                }
                pub fn set_b(&mut self, val: <BitField2 as BitFieldSpecifier>::DefaultFieldType) {
                    debug_assert!((val as u64) <= BitField2::FIELD_MAX);
                    let offset = BitField0::FIELD_WIDTH as usize + BitField1::FIELD_WIDTH as usize;
                    return self.set(offset, BitField2::FIELD_WIDTH, val as u64);
                }
                pub fn get_c(&self) -> <BitField5 as BitFieldSpecifier>::DefaultFieldType {
                    let offset = BitField0::FIELD_WIDTH as usize
                        + BitField1::FIELD_WIDTH as usize
                        + BitField2::FIELD_WIDTH as usize;
                    return self.get(offset, BitField5::FIELD_WIDTH)
                        as <BitField5 as BitFieldSpecifier>::DefaultFieldType;
                }
                pub fn set_c(&mut self, val: <BitField5 as BitFieldSpecifier>::DefaultFieldType) {
                    debug_assert!((val as u64) <= BitField5::FIELD_MAX);
                    let offset = BitField0::FIELD_WIDTH as usize
                        + BitField1::FIELD_WIDTH as usize
                        + BitField2::FIELD_WIDTH as usize;
                    return self.set(offset, BitField5::FIELD_WIDTH, val as u64);
                }
            }

            impl std::fmt::Debug for MyBitField {
                fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                    f.debug_struct("MyBitField")
                        .field("a", &self.get_a())
                        .field("b", &self.get_b())
                        .field("c", &self.get_c())
                        .finish()
                }
            }
            #[cfg(test)]
            mod test_mybitfield {
                use super::*;
                #[test]
                fn test_total_size() {
                    let total_size = BitField1::FIELD_WIDTH as usize
                        + BitField2::FIELD_WIDTH as usize
                        + BitField5::FIELD_WIDTH as usize;
                    assert_eq!(total_size % 8, 0);
                }
                #[test]
                fn test_bits_boundary() {
                    let fields_sizes = vec![
                        BitField1::FIELD_WIDTH as usize,
                        BitField2::FIELD_WIDTH as usize,
                        BitField5::FIELD_WIDTH as usize
                    ];
                    let mut sum = 0usize;
                    for s in fields_sizes {
                        if sum % 64 == 0 {
                            assert!(s <= 64);
                        } else {
                            if (sum + s) % 64 != 0 {
                                assert_eq!(sum / 64, (sum + s) / 64);
                            }
                        }
                        sum += s;
                    }
                }
                #[test]
                fn test_a() {
                    let mut a = MyBitField::new();
                    assert_eq!(a.get_a() as u64, 0);
                    a.set_a(BitField1::FIELD_MAX as
                            <BitField1 as BitFieldSpecifier>::DefaultFieldType);
                    assert_eq!(a.get_a() as u64, BitField1::FIELD_MAX);
                }
                #[test]
                fn test_b() {
                    let mut a = MyBitField::new();
                    assert_eq!(a.get_b() as u64, 0);
                    a.set_b(BitField2::FIELD_MAX as
                            <BitField2 as BitFieldSpecifier>::DefaultFieldType);
                    assert_eq!(a.get_b() as u64, BitField2::FIELD_MAX);
                }
                #[test]
                fn test_c() {
                    let mut a = MyBitField::new();
                    assert_eq!(a.get_c() as u64, 0);
                    a.set_c(BitField5::FIELD_MAX as
                            <BitField5 as BitFieldSpecifier>::DefaultFieldType);
                    assert_eq!(a.get_c() as u64, BitField5::FIELD_MAX);
                }
            }
        };

        assert_eq!(bitfield_impl(input), expected);
    }
}
