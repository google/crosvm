// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

fn main() {
    cc::Build::new().file("host_cpuid.c").compile("host_cpuid");
}
