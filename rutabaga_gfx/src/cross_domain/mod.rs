// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#![cfg(not(target_os = "fuchsia"))]

mod cross_domain;
mod cross_domain_protocol;
mod sys;

pub use cross_domain::CrossDomain;
