// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::path::PathBuf;

pub(crate) mod serial_device;

/// Parses a wayland socket path with optional name parameter (e.g. "PATH[,name=NAME]").
pub fn parse_wayland_sock(value: &str) -> Result<(String, PathBuf), String> {
    let mut components = value.split(',');
    let path = PathBuf::from(match components.next() {
        None => return Err("missing socket path".to_string()),
        Some(c) => c,
    });
    let mut name = "";
    for c in components {
        let mut kv = c.splitn(2, '=');
        let (kind, value) = match (kv.next(), kv.next()) {
            (Some(kind), Some(value)) => (kind, value),
            _ => return Err(format!("option must be of the form `kind=value`: {c}")),
        };
        match kind {
            "name" => name = value,
            _ => return Err(format!("unrecognized option: {kind}")),
        }
    }

    Ok((name.to_string(), path))
}
