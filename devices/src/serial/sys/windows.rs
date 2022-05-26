// Copyright 2022 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use base::named_pipes::PipeConnection;

// TODO(b/234469655): Remove type alias once ReadNotifier is implemented for
// PipeConnection.
pub(crate) type InStreamType = Box<PipeConnection>;
