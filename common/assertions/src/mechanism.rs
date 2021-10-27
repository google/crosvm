// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::marker::PhantomData;

pub struct True;
pub struct False;

pub trait Expr {
    type Value;
}

impl Expr for [(); 0] {
    type Value = False;
}

impl Expr for [(); 1] {
    type Value = True;
}

// If the macro instantiates this with `T = [(); 1]` then it compiles successfully.
//
// On the other hand if `T = [(); 0]` the user receives an error like the following:
//
//    error[E0271]: type mismatch resolving `<[(); 0] as assertions::Expr>::Value == assertions::True`
//     --> src/main.rs:5:5
//      |
//    5 |     const_assert!(std::mem::size_of::<String>() == 8);
//      |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ expected struct `assertions::True`, found struct `assertions::False`
//
pub struct Assert<T: Expr<Value = True>> {
    marker: PhantomData<T>,
}
