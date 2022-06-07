// Copyright 2022 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::rc::Rc;

use cros_async::AsyncTube;

use crate::virtio::iommu::{Result, State};

pub(in crate::virtio::iommu) async fn handle_command_tube(
    state: &Rc<RefCell<State>>,
    command_tube: AsyncTube,
) -> Result<()> {
    panic!("IOMMU is not supported on Windows");
}

pub(in crate::virtio::iommu) async fn handle_translate_request(
    state: &Rc<RefCell<State>>,
    request_tube: Option<AsyncTube>,
    response_tubes: Option<BTreeMap<u32, AsyncTube>>,
) -> Result<()> {
    // TODO nkgold (b/222588331): the below implementation assures AsyncTube::send is sync, where it
    //   should be async (as it is on Windows). Once that's fixed there's no reason this function
    //   needs an os-specific implementation.
    panic!("IOMMU is not supported on Windows");
}
