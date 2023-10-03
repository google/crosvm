// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::fs::File;

/// Device tree overlay file
pub struct DtbOverlay(pub File);
