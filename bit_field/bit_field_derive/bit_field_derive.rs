// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#![recursion_limit = "256"]

extern crate proc_macro;

use proc_macro2::{Span, TokenStream};
use quote::{quote, quote_spanned};
use syn::parse::{Error, Result};
use syn::{
    parse_macro_input, Attribute, Data, DataEnum, DeriveInput, Fields, FieldsNamed, FieldsUnnamed,
    Ident, Lit, LitInt, Meta, Type, Visibility,
};

/// The function that derives the actual implementation.
#[proc_macro_attribute]
pub fn bitfield(
    _args: proc_macro::TokenStream,
    input: proc_macro::TokenStream,
) -> proc_macro::TokenStream {
    let derive_input = parse_macro_input!(input as DeriveInput);

    let expanded = bitfield_impl(&derive_input).unwrap_or_else(|err| {
        let compile_error = err.to_compile_error();
        quote! {
            #compile_error

            // Include the original input to avoid "use of undeclared type"
            // errors elsewhere.
            #derive_input
        }
    });

    expanded.into()
}

fn bitfield_impl(ast: &DeriveInput) -> Result<TokenStream> {
    if !ast.generics.params.is_empty() {
        return Err(Error::new(
            Span::call_site(),
            "#[bitfield] does not support generic parameters",
        ));
    }

    match &ast.data {
        Data::Struct(data_struct) => match &data_struct.fields {
            Fields::Named(fields_named) => bitfield_struct_impl(ast, fields_named),
            Fields::Unnamed(fields_unnamed) => bitfield_tuple_struct_impl(ast, fields_unnamed),
            Fields::Unit => Err(Error::new(
                Span::call_site(),
                "#[bitfield] does not work with unit struct",
            )),
        },
        Data::Enum(data_enum) => bitfield_enum_impl(ast, data_enum),
        Data::Union(_) => Err(Error::new(
            Span::call_site(),
            "#[bitfield] does not support unions",
        )),
    }
}

fn bitfield_tuple_struct_impl(ast: &DeriveInput, fields: &FieldsUnnamed) -> Result<TokenStream> {
    let mut ast = ast.clone();
    let width = match parse_remove_bits_attr(&mut ast)? {
        Some(w) => w,
        None => {
            return Err(Error::new(
                Span::call_site(),
                "tuple struct field must have bits attribute",
            ));
        }
    };

    let ident = &ast.ident;

    if width.value() > 64 {
        return Err(Error::new(
            Span::call_site(),
            "max width of bitfield field is 64",
        ));
    }

    let bits = width.value() as u8;

    if fields.unnamed.len() != 1 {
        return Err(Error::new(
            Span::call_site(),
            "tuple struct field must have exactly 1 field",
        ));
    }

    let field_type = match &fields.unnamed.first().unwrap().value().ty {
        Type::Path(t) => t,
        _ => {
            return Err(Error::new(
                Span::call_site(),
                "tuple struct field must have primitive field",
            ));
        }
    };
    let span = field_type
        .path
        .segments
        .first()
        .unwrap()
        .value()
        .ident
        .span();

    let from_u64 = quote_spanned! {
        span => val as #field_type
    };

    let into_u64 = quote_spanned! {
        span => val.0 as u64
    };

    let expanded = quote! {
        #ast

        impl bit_field::BitFieldSpecifier for #ident {
            const FIELD_WIDTH: u8 = #bits;
            type SetterType = Self;
            type GetterType = Self;

            #[inline]
            fn from_u64(val: u64) -> Self::GetterType {
                Self(#from_u64)
            }

            #[inline]
            fn into_u64(val: Self::SetterType) -> u64 {
                #into_u64
            }
        }
    };

    Ok(expanded)
}

fn bitfield_enum_impl(ast: &DeriveInput, data: &DataEnum) -> Result<TokenStream> {
    let mut ast = ast.clone();
    let width = parse_remove_bits_attr(&mut ast)?;
    match width {
        None => bitfield_enum_without_width_impl(&ast, data),
        Some(width) => bitfield_enum_with_width_impl(&ast, data, &width),
    }
}

fn bitfield_enum_with_width_impl(
    ast: &DeriveInput,
    data: &DataEnum,
    width: &LitInt,
) -> Result<TokenStream> {
    if width.value() > 64 {
        return Err(Error::new(
            Span::call_site(),
            "max width of bitfield enum is 64",
        ));
    }
    let bits = width.value() as u8;
    let declare_discriminants = get_declare_discriminants_for_enum(bits, ast, data);

    let ident = &ast.ident;
    let type_name = ident.to_string();
    let variants = &data.variants;
    let match_discriminants = variants.iter().map(|variant| {
        let variant = &variant.ident;
        quote! {
            discriminant::#variant => Ok(#ident::#variant),
        }
    });

    let expanded = quote! {
        #ast

        impl bit_field::BitFieldSpecifier for #ident {
            const FIELD_WIDTH: u8 = #bits;
            type SetterType = Self;
            type GetterType = std::result::Result<Self, bit_field::Error>;

            #[inline]
            fn from_u64(val: u64) -> Self::GetterType {
                struct discriminant;
                impl discriminant {
                    #(#declare_discriminants)*
                }
                match val {
                    #(#match_discriminants)*
                    v => Err(bit_field::Error::new(#type_name, v)),
                }
            }

            #[inline]
            fn into_u64(val: Self::SetterType) -> u64 {
                val as u64
            }
        }
    };

    Ok(expanded)
}
// Expand to an impl of BitFieldSpecifier for an enum like:
//
//     #[bitfield]
//     #[derive(Debug, PartialEq)]
//     enum TwoBits {
//         Zero = 0b00,
//         One = 0b01,
//         Two = 0b10,
//         Three = 0b11,
//     }
//
// Such enums may be used as a field of a bitfield struct.
//
//     #[bitfield]
//     struct Struct {
//         prefix: BitField1,
//         two_bits: TwoBits,
//         suffix: BitField5,
//     }
//
fn bitfield_enum_without_width_impl(ast: &DeriveInput, data: &DataEnum) -> Result<TokenStream> {
    let ident = &ast.ident;
    let variants = &data.variants;
    let len = variants.len();
    if len.count_ones() != 1 {
        return Err(Error::new(
            Span::call_site(),
            "#[bitfield] expected a number of variants which is a power of 2 when bits is not \
             specified for the enum",
        ));
    }

    let bits = len.trailing_zeros() as u8;
    let declare_discriminants = get_declare_discriminants_for_enum(bits, ast, data);

    let match_discriminants = variants.iter().map(|variant| {
        let variant = &variant.ident;
        quote! {
            discriminant::#variant => #ident::#variant,
        }
    });

    let expanded = quote! {
        #ast

        impl bit_field::BitFieldSpecifier for #ident {
            const FIELD_WIDTH: u8 = #bits;
            type SetterType = Self;
            type GetterType = Self;

            #[inline]
            fn from_u64(val: u64) -> Self::GetterType {
                struct discriminant;
                impl discriminant {
                    #(#declare_discriminants)*
                }
                match val {
                    #(#match_discriminants)*
                    _ => unreachable!(),
                }
            }

            #[inline]
            fn into_u64(val: Self::SetterType) -> u64 {
                val as u64
            }
        }
    };

    Ok(expanded)
}

fn get_declare_discriminants_for_enum(
    bits: u8,
    ast: &DeriveInput,
    data: &DataEnum,
) -> Vec<TokenStream> {
    let variants = &data.variants;
    let upper_bound = 2u64.pow(bits as u32);
    let ident = &ast.ident;

    variants
        .iter()
        .map(|variant| {
            let variant = &variant.ident;
            let span = variant.span();

            let assertion = quote_spanned! {span=>
                // If IS_IN_BOUNDS is true, this evaluates to 0.
                //
                // If IS_IN_BOUNDS is false, this evaluates to `0 - 1` which
                // triggers a compile error on underflow when referenced below. The
                // error is not beautiful but does carry the span of the problematic
                // enum variant so at least it points to the right line.
                //
                //     error: any use of this value will cause an error
                //       --> bit_field/test.rs:10:5
                //        |
                //     10 |     OutOfBounds = 0b111111,
                //        |     ^^^^^^^^^^^ attempt to subtract with overflow
                //        |
                //
                //     error[E0080]: erroneous constant used
                //      --> bit_field/test.rs:5:1
                //       |
                //     5 | #[bitfield]
                //       | ^^^^^^^^^^^ referenced constant has errors
                //
                const ASSERT: u64 = 0 - !IS_IN_BOUNDS as u64;
            };

            quote! {
                #[allow(non_upper_case_globals)]
                const #variant: u64 = {
                    const IS_IN_BOUNDS: bool = (#ident::#variant as u64) < #upper_bound;

                    #assertion

                    #ident::#variant as u64 + ASSERT
                };
            }
        })
        .collect()
}

fn bitfield_struct_impl(ast: &DeriveInput, fields: &FieldsNamed) -> Result<TokenStream> {
    let name = &ast.ident;
    let vis = &ast.vis;
    let attrs = &ast.attrs;
    let fields = get_struct_fields(fields)?;
    let struct_def = get_struct_def(vis, &name, &fields);
    let bits_impl = get_bits_impl(&name);
    let fields_impl = get_fields_impl(&fields);
    let debug_fmt_impl = get_debug_fmt_impl(&name, &fields);

    let expanded = quote! {
        #(#attrs)*
        #struct_def
        #bits_impl
        impl #name {
            #(#fields_impl)*
        }
        #debug_fmt_impl
    };

    Ok(expanded)
}

struct FieldSpec<'a> {
    ident: &'a Ident,
    ty: &'a Type,
    expected_bits: Option<LitInt>,
}

// Unwrap ast to get the named fields. We only care about field names and types:
// "myfield : BitField3" -> ("myfield", Token(BitField3))
fn get_struct_fields(fields: &FieldsNamed) -> Result<Vec<FieldSpec>> {
    let mut vec = Vec::new();

    for field in &fields.named {
        let ident = field
            .ident
            .as_ref()
            .expect("Fields::Named has named fields");
        let ty = &field.ty;
        let expected_bits = parse_bits_attr(&field.attrs)?;
        vec.push(FieldSpec {
            ident,
            ty,
            expected_bits,
        });
    }

    Ok(vec)
}

// For example: #[bits = 1]
fn parse_bits_attr(attrs: &[Attribute]) -> Result<Option<LitInt>> {
    let mut expected_bits = None;

    for attr in attrs {
        if attr.path.is_ident("doc") {
            continue;
        }
        if let Some(v) = try_parse_bits_attr(attr)? {
            expected_bits = Some(v);
            continue;
        }

        return Err(Error::new_spanned(attr, "unrecognized attribute"));
    }

    Ok(expected_bits)
}

// This function will return None if the attribute is not #[bits = *].
fn try_parse_bits_attr(attr: &Attribute) -> Result<Option<LitInt>> {
    if attr.path.is_ident("bits") {
        if let Meta::NameValue(name_value) = attr.parse_meta()? {
            if let Lit::Int(int) = name_value.lit {
                return Ok(Some(int));
            }
        }
    }
    Ok(None)
}

fn parse_remove_bits_attr(ast: &mut DeriveInput) -> Result<Option<LitInt>> {
    let mut width = None;
    let mut bits_idx = 0;

    for (i, attr) in ast.attrs.iter().enumerate() {
        if let Some(w) = try_parse_bits_attr(attr)? {
            bits_idx = i;
            width = Some(w);
        }
    }

    if width.is_some() {
        ast.attrs.remove(bits_idx);
    }

    Ok(width)
}

fn get_struct_def(vis: &Visibility, name: &Ident, fields: &[FieldSpec]) -> TokenStream {
    let mut field_types = Vec::new();
    for spec in fields {
        field_types.push(spec.ty);
    }

    // `(BitField1::FIELD_WIDTH + BitField3::FIELD_WIDTH + ...)`
    let data_size_in_bits = quote! {
        (
            #(
                <#field_types as ::bit_field::BitFieldSpecifier>::FIELD_WIDTH as usize
            )+*
        )
    };

    quote! {
        #[repr(C)]
        #vis struct #name {
            data: [u8; #data_size_in_bits / 8],
        }

        impl #name {
            pub fn new() -> #name {
                let _: ::bit_field::Check<[u8; #data_size_in_bits % 8]>;

                #name {
                    data: [0; #data_size_in_bits / 8],
                }
            }
        }
    }
}

// Implement setter and getter for all fields.
fn get_fields_impl(fields: &[FieldSpec]) -> Vec<TokenStream> {
    let mut impls = Vec::new();
    // This vec keeps track of types before this field, used to generate the offset.
    let current_types = &mut vec![quote!(::bit_field::BitField0)];

    for spec in fields {
        let ty = spec.ty;
        let getter_ident = Ident::new(format!("get_{}", spec.ident).as_str(), Span::call_site());
        let setter_ident = Ident::new(format!("set_{}", spec.ident).as_str(), Span::call_site());

        // Optional #[bits = N] attribute to provide compile-time checked
        // documentation of how many bits some field covers.
        let check_expected_bits = spec.expected_bits.as_ref().map(|expected_bits| {
            // If expected_bits does not match the actual number of bits in the
            // bit field specifier, this will fail to compile with an error
            // pointing into the #[bits = N] attribute.
            let span = expected_bits.span();
            quote_spanned! {span=>
                #[allow(dead_code)]
                const EXPECTED_BITS: [(); #expected_bits as usize] =
                    [(); <#ty as ::bit_field::BitFieldSpecifier>::FIELD_WIDTH as usize];
            }
        });

        impls.push(quote! {
            pub fn #getter_ident(&self) -> <#ty as ::bit_field::BitFieldSpecifier>::GetterType {
                #check_expected_bits
                let offset = #(<#current_types as ::bit_field::BitFieldSpecifier>::FIELD_WIDTH as usize)+*;
                let val = self.get(offset, <#ty as ::bit_field::BitFieldSpecifier>::FIELD_WIDTH);
                <#ty as ::bit_field::BitFieldSpecifier>::from_u64(val)
            }

            pub fn #setter_ident(&mut self, val: <#ty as ::bit_field::BitFieldSpecifier>::SetterType) {
                let val = <#ty as ::bit_field::BitFieldSpecifier>::into_u64(val);
                debug_assert!(val <= ::bit_field::max::<#ty>());
                let offset = #(<#current_types as ::bit_field::BitFieldSpecifier>::FIELD_WIDTH as usize)+*;
                self.set(offset, <#ty as ::bit_field::BitFieldSpecifier>::FIELD_WIDTH, val)
            }
        });

        current_types.push(quote!(#ty));
    }

    impls
}

// Implement setter and getter for all fields.
fn get_debug_fmt_impl(name: &Ident, fields: &[FieldSpec]) -> TokenStream {
    // print fields:
    let mut impls = Vec::new();
    for spec in fields {
        let field_name = spec.ident.to_string();
        let getter_ident = Ident::new(&format!("get_{}", spec.ident), Span::call_site());
        impls.push(quote! {
            .field(#field_name, &self.#getter_ident())
        });
    }

    let name_str = format!("{}", name);
    quote! {
        impl std::fmt::Debug for #name {
            fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.debug_struct(#name_str)
                #(#impls)*
                    .finish()
            }
        }
    }
}

fn get_bits_impl(name: &Ident) -> TokenStream {
    quote! {
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
    }
}

// Only intended to be used from the bit_field crate. This macro emits the
// marker types bit_field::BitField0 through bit_field::BitField64.
#[proc_macro]
#[doc(hidden)]
pub fn define_bit_field_specifiers(_input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let mut code = TokenStream::new();

    for width in 0u8..=64 {
        let span = Span::call_site();
        let long_name = Ident::new(&format!("BitField{}", width), span);
        let short_name = Ident::new(&format!("B{}", width), span);

        let default_field_type = if width <= 8 {
            quote!(u8)
        } else if width <= 16 {
            quote!(u16)
        } else if width <= 32 {
            quote!(u32)
        } else {
            quote!(u64)
        };

        code.extend(quote! {
            pub struct #long_name;
            pub use self::#long_name as #short_name;

            impl BitFieldSpecifier for #long_name {
                const FIELD_WIDTH: u8 = #width;
                type SetterType = #default_field_type;
                type GetterType = #default_field_type;

                #[inline]
                fn from_u64(val: u64) -> Self::GetterType {
                    val as Self::GetterType
                }

                #[inline]
                fn into_u64(val: Self::SetterType) -> u64 {
                    val as u64
                }
            }
        });
    }

    code.into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use syn::parse_quote;

    #[test]
    fn end_to_end() {
        let input: DeriveInput = parse_quote! {
            #[derive(Clone)]
            struct MyBitField {
                a: BitField1,
                b: BitField2,
                c: BitField5,
            }
        };

        let expected = quote! {
            #[derive(Clone)]
            #[repr(C)]
            struct MyBitField {
                data: [u8; (<BitField1 as ::bit_field::BitFieldSpecifier>::FIELD_WIDTH as usize
                            + <BitField2 as ::bit_field::BitFieldSpecifier>::FIELD_WIDTH as usize
                            + <BitField5 as ::bit_field::BitFieldSpecifier>::FIELD_WIDTH as usize)
                    / 8],
            }
            impl MyBitField {
                pub fn new() -> MyBitField {
                    let _: ::bit_field::Check<[
                        u8;
                        (<BitField1 as ::bit_field::BitFieldSpecifier>::FIELD_WIDTH as usize
                                + <BitField2 as ::bit_field::BitFieldSpecifier>::FIELD_WIDTH as usize
                                + <BitField5 as ::bit_field::BitFieldSpecifier>::FIELD_WIDTH as usize)
                            % 8
                    ]>;

                    MyBitField {
                        data: [0; (<BitField1 as ::bit_field::BitFieldSpecifier>::FIELD_WIDTH as usize
                                   + <BitField2 as ::bit_field::BitFieldSpecifier>::FIELD_WIDTH as usize
                                   + <BitField5 as ::bit_field::BitFieldSpecifier>::FIELD_WIDTH as usize)
                            / 8],
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
                pub fn get_a(&self) -> <BitField1 as ::bit_field::BitFieldSpecifier>::GetterType {
                    let offset = <::bit_field::BitField0 as ::bit_field::BitFieldSpecifier>::FIELD_WIDTH as usize;
                    let val = self.get(offset, <BitField1 as ::bit_field::BitFieldSpecifier>::FIELD_WIDTH);
                    <BitField1 as ::bit_field::BitFieldSpecifier>::from_u64(val)
                }
                pub fn set_a(&mut self, val: <BitField1 as ::bit_field::BitFieldSpecifier>::SetterType) {
                    let val = <BitField1 as ::bit_field::BitFieldSpecifier>::into_u64(val);
                    debug_assert!(val <= ::bit_field::max::<BitField1>());
                    let offset = <::bit_field::BitField0 as ::bit_field::BitFieldSpecifier>::FIELD_WIDTH as usize;
                    self.set(offset, <BitField1 as ::bit_field::BitFieldSpecifier>::FIELD_WIDTH, val)
                }
                pub fn get_b(&self) -> <BitField2 as ::bit_field::BitFieldSpecifier>::GetterType {
                    let offset = <::bit_field::BitField0 as ::bit_field::BitFieldSpecifier>::FIELD_WIDTH as usize
                        + <BitField1 as ::bit_field::BitFieldSpecifier>::FIELD_WIDTH as usize;
                    let val = self.get(offset, <BitField2 as ::bit_field::BitFieldSpecifier>::FIELD_WIDTH);
                    <BitField2 as ::bit_field::BitFieldSpecifier>::from_u64(val)
                }
                pub fn set_b(&mut self, val: <BitField2 as ::bit_field::BitFieldSpecifier>::SetterType) {
                    let val = <BitField2 as ::bit_field::BitFieldSpecifier>::into_u64(val);
                    debug_assert!(val <= ::bit_field::max::<BitField2>());
                    let offset = <::bit_field::BitField0 as ::bit_field::BitFieldSpecifier>::FIELD_WIDTH as usize
                        + <BitField1 as ::bit_field::BitFieldSpecifier>::FIELD_WIDTH as usize;
                    self.set(offset, <BitField2 as ::bit_field::BitFieldSpecifier>::FIELD_WIDTH, val)
                }
                pub fn get_c(&self) -> <BitField5 as ::bit_field::BitFieldSpecifier>::GetterType {
                    let offset = <::bit_field::BitField0 as ::bit_field::BitFieldSpecifier>::FIELD_WIDTH as usize
                        + <BitField1 as ::bit_field::BitFieldSpecifier>::FIELD_WIDTH as usize
                        + <BitField2 as ::bit_field::BitFieldSpecifier>::FIELD_WIDTH as usize;
                    let val = self.get(offset, <BitField5 as ::bit_field::BitFieldSpecifier>::FIELD_WIDTH);
                    <BitField5 as ::bit_field::BitFieldSpecifier>::from_u64(val)
                }
                pub fn set_c(&mut self, val: <BitField5 as ::bit_field::BitFieldSpecifier>::SetterType) {
                    let val = <BitField5 as ::bit_field::BitFieldSpecifier>::into_u64(val);
                    debug_assert!(val <= ::bit_field::max::<BitField5>());
                    let offset = <::bit_field::BitField0 as ::bit_field::BitFieldSpecifier>::FIELD_WIDTH as usize
                        + <BitField1 as ::bit_field::BitFieldSpecifier>::FIELD_WIDTH as usize
                        + <BitField2 as ::bit_field::BitFieldSpecifier>::FIELD_WIDTH as usize;
                    self.set(offset, <BitField5 as ::bit_field::BitFieldSpecifier>::FIELD_WIDTH, val)
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
        };

        assert_eq!(
            bitfield_impl(&input).unwrap().to_string(),
            expected.to_string()
        );
    }
}
