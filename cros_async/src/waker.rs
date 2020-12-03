// Copyright 2020 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

/// Wrapper around a usize used as a token to uniquely identify a pending waker.
#[derive(Debug)]
pub(crate) struct WakerToken(pub(crate) usize);
