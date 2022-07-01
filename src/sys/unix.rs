// Copyright 2022 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

pub(crate) mod main;
mod panic_hook;

pub(crate) use panic_hook::set_panic_hook;
