// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use serde::Deserialize;
use serde::Serialize;

#[derive(Serialize, Deserialize, Debug)]
pub enum GpuSendToService {}

#[derive(Serialize, Deserialize, Debug)]
pub enum ServiceSendToGpu {}

#[derive(Serialize, Deserialize, Debug)]
pub enum GpuSendToMain {}
