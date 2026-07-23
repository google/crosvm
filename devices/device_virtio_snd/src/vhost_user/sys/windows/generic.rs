// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use serde::Deserialize;
use serde::Serialize;

#[derive(Deserialize, Serialize)]
pub struct SndBackendConfig {}

#[derive(Deserialize, Serialize)]
pub struct SndVmmConfig {}
