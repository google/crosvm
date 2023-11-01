// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! plugin configuration options

use std::path::PathBuf;
use std::str::FromStr;

use serde::Deserialize;
use serde::Serialize;

use crate::crosvm::config::invalid_value_err;

/// A bind mount for directories in the plugin process.
#[derive(Debug, Serialize, Deserialize)]
pub struct BindMount {
    pub src: PathBuf,
    pub dst: PathBuf,
    pub writable: bool,
}

impl FromStr for BindMount {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let components: Vec<&str> = value.split(':').collect();
        if components.is_empty() || components.len() > 3 || components[0].is_empty() {
            return Err(invalid_value_err(
                value,
                "`plugin-mount` should be in a form of: <src>[:[<dst>][:<writable>]]",
            ));
        }

        let src = PathBuf::from(components[0]);
        if src.is_relative() {
            return Err(invalid_value_err(
                components[0],
                "the source path for `plugin-mount` must be absolute",
            ));
        }
        if !src.exists() {
            return Err(invalid_value_err(
                components[0],
                "the source path for `plugin-mount` does not exist",
            ));
        }

        let dst = PathBuf::from(match components.get(1) {
            None | Some(&"") => components[0],
            Some(path) => path,
        });
        if dst.is_relative() {
            return Err(invalid_value_err(
                components[1],
                "the destination path for `plugin-mount` must be absolute",
            ));
        }

        let writable: bool = match components.get(2) {
            None => false,
            Some(s) => s.parse().map_err(|_| {
                invalid_value_err(
                    components[2],
                    "the <writable> component for `plugin-mount` is not valid bool",
                )
            })?,
        };

        Ok(BindMount { src, dst, writable })
    }
}

/// A mapping of linux group IDs for the plugin process.
#[derive(Debug, Deserialize, Serialize)]
pub struct GidMap {
    pub inner: base::Gid,
    pub outer: base::Gid,
    pub count: u32,
}

impl FromStr for GidMap {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let components: Vec<&str> = value.split(':').collect();
        if components.is_empty() || components.len() > 3 || components[0].is_empty() {
            return Err(invalid_value_err(
                value,
                "`plugin-gid-map` must have exactly 3 components: <inner>[:[<outer>][:<count>]]",
            ));
        }

        let inner: base::Gid = components[0].parse().map_err(|_| {
            invalid_value_err(
                components[0],
                "the <inner> component for `plugin-gid-map` is not valid gid",
            )
        })?;

        let outer: base::Gid = match components.get(1) {
            None | Some(&"") => inner,
            Some(s) => s.parse().map_err(|_| {
                invalid_value_err(
                    components[1],
                    "the <outer> component for `plugin-gid-map` is not valid gid",
                )
            })?,
        };

        let count: u32 = match components.get(2) {
            None => 1,
            Some(s) => s.parse().map_err(|_| {
                invalid_value_err(
                    components[2],
                    "the <count> component for `plugin-gid-map` is not valid number",
                )
            })?,
        };

        Ok(GidMap {
            inner,
            outer,
            count,
        })
    }
}

pub fn parse_plugin_mount_option(value: &str) -> Result<BindMount, String> {
    let components: Vec<&str> = value.split(':').collect();
    if components.is_empty() || components.len() > 3 || components[0].is_empty() {
        return Err(invalid_value_err(
            value,
            "`plugin-mount` should be in a form of: <src>[:[<dst>][:<writable>]]",
        ));
    }

    let src = PathBuf::from(components[0]);
    if src.is_relative() {
        return Err(invalid_value_err(
            components[0],
            "the source path for `plugin-mount` must be absolute",
        ));
    }
    if !src.exists() {
        return Err(invalid_value_err(
            components[0],
            "the source path for `plugin-mount` does not exist",
        ));
    }

    let dst = PathBuf::from(match components.get(1) {
        None | Some(&"") => components[0],
        Some(path) => path,
    });
    if dst.is_relative() {
        return Err(invalid_value_err(
            components[1],
            "the destination path for `plugin-mount` must be absolute",
        ));
    }

    let writable: bool = match components.get(2) {
        None => false,
        Some(s) => s.parse().map_err(|_| {
            invalid_value_err(
                components[2],
                "the <writable> component for `plugin-mount` is not valid bool",
            )
        })?,
    };

    Ok(BindMount { src, dst, writable })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_plugin_mount_invalid() {
        "".parse::<BindMount>().expect_err("parse should fail");
        "/dev/null:/dev/null:true:false"
            .parse::<BindMount>()
            .expect_err("parse should fail because too many arguments");

        "null:/dev/null:true"
            .parse::<BindMount>()
            .expect_err("parse should fail because source is not absolute");
        "/dev/null:null:true"
            .parse::<BindMount>()
            .expect_err("parse should fail because source is not absolute");
        "/dev/null:null:blah"
            .parse::<BindMount>()
            .expect_err("parse should fail because flag is not boolean");
    }

    #[test]
    fn parse_plugin_mount_valid() {
        let opt: BindMount = "/dev/null:/dev/zero:true".parse().unwrap();

        assert_eq!(opt.src, PathBuf::from("/dev/null"));
        assert_eq!(opt.dst, PathBuf::from("/dev/zero"));
        assert!(opt.writable);
    }

    #[test]
    fn parse_plugin_mount_valid_shorthand() {
        let opt: BindMount = "/dev/null".parse().unwrap();
        assert_eq!(opt.dst, PathBuf::from("/dev/null"));
        assert!(!opt.writable);

        let opt: BindMount = "/dev/null:/dev/zero".parse().unwrap();
        assert_eq!(opt.dst, PathBuf::from("/dev/zero"));
        assert!(!opt.writable);

        let opt: BindMount = "/dev/null::true".parse().unwrap();
        assert_eq!(opt.dst, PathBuf::from("/dev/null"));
        assert!(opt.writable);
    }

    #[test]
    fn parse_plugin_gid_map_valid() {
        let opt: GidMap = "1:2:3".parse().expect("parse should succeed");
        assert_eq!(opt.inner, 1);
        assert_eq!(opt.outer, 2);
        assert_eq!(opt.count, 3);
    }

    #[test]
    fn parse_plugin_gid_map_valid_shorthand() {
        let opt: GidMap = "1".parse().expect("parse should succeed");
        assert_eq!(opt.inner, 1);
        assert_eq!(opt.outer, 1);
        assert_eq!(opt.count, 1);

        let opt: GidMap = "1:2".parse().expect("parse should succeed");
        assert_eq!(opt.inner, 1);
        assert_eq!(opt.outer, 2);
        assert_eq!(opt.count, 1);

        let opt: GidMap = "1::3".parse().expect("parse should succeed");
        assert_eq!(opt.inner, 1);
        assert_eq!(opt.outer, 1);
        assert_eq!(opt.count, 3);
    }

    #[test]
    fn parse_plugin_gid_map_invalid() {
        "".parse::<GidMap>().expect_err("parse should fail");
        "1:2:3:4"
            .parse::<GidMap>()
            .expect_err("parse should fail because too many arguments");
        "blah:2:3"
            .parse::<GidMap>()
            .expect_err("parse should fail because inner is not a number");
        "1:blah:3"
            .parse::<GidMap>()
            .expect_err("parse should fail because outer is not a number");
        "1:2:blah"
            .parse::<GidMap>()
            .expect_err("parse should fail because count is not a number");
    }
}
