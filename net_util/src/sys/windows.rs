// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use base::named_pipes::ReadOverlapped;
use base::named_pipes::WriteOverlapped;
use base::ReadNotifier;

use crate::TapTCommon;

pub trait TapT: TapTCommon + ReadNotifier + ReadOverlapped + WriteOverlapped {}
