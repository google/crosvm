// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::collections::BTreeMap;

use serde::Deserialize;
use serde::Serialize;

#[derive(Serialize, Deserialize)]
pub struct RutabagaSnapshot {
    pub resources: BTreeMap<u32, RutabagaResourceSnapshot>,
}

#[derive(Serialize, Deserialize)]
pub struct RutabagaResourceSnapshot {
    pub resource_id: u32,
    pub width: u32,
    pub height: u32,
}
