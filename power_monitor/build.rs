// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::env;
use std::path::PathBuf;

fn main() {
    let mut input_files = Vec::new();

    if cfg!(feature = "powerd") {
        let power_manager_dir = match env::var("SYSROOT") {
            Ok(dir) => PathBuf::from(dir).join("usr/include/chromeos/dbus/power_manager"),
            // Use local copy of proto file when building upstream
            Err(_) => PathBuf::from("."),
        };

        input_files.push(power_manager_dir.join("power_supply_properties.proto"));
    }

    let mut out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR env does not exist."));
    out_dir.push("protos");

    proto_build_tools::build_protos(&out_dir, &input_files);
}
