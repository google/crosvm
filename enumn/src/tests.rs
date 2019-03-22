// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use quote::quote;
use syn::{parse_quote, DeriveInput};

#[test]
fn test_repr() {
    let input: DeriveInput = parse_quote! {
        #[repr(u8)]
        enum E {
            A,
            B,
            C,
        }
    };
    let actual = crate::testable_derive(input);
    let expected = quote! {
        #[allow(non_upper_case_globals)]
        impl E {
            pub fn n(value: u8) -> Option<Self> {
                struct discriminant;
                impl discriminant {
                    const A: u8 = E::A as u8;
                    const B: u8 = E::B as u8;
                    const C: u8 = E::C as u8;
                }
                match value {
                    discriminant::A => Some(E::A),
                    discriminant::B => Some(E::B),
                    discriminant::C => Some(E::C),
                    _ => None,
                }
            }
        }
    };
    assert_eq!(actual.to_string(), expected.to_string());
}

#[test]
fn test_no_repr() {
    let input: DeriveInput = parse_quote! {
        enum E {
            A,
            B,
            C,
        }
    };
    let actual = crate::testable_derive(input);
    let expected = quote! {
        #[allow(non_upper_case_globals)]
        impl E {
            pub fn n<REPR: Into<i64>>(value: REPR) -> Option<Self> {
                struct discriminant;
                impl discriminant {
                    const A: i64 = E::A as i64;
                    const B: i64 = E::B as i64;
                    const C: i64 = E::C as i64;
                }
                match <REPR as Into<i64>>::into(value) {
                    discriminant::A => Some(E::A),
                    discriminant::B => Some(E::B),
                    discriminant::C => Some(E::C),
                    _ => None,
                }
            }
        }
    };
    assert_eq!(actual.to_string(), expected.to_string());
}
