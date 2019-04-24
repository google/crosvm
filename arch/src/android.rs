// Copyright 2019 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::fs::File;
use std::io::BufRead;
use std::io::BufReader;

use crate::fdt::{begin_node, end_node, property_string, Error, Result};

fn parse_fstab_line(line: &str) -> Result<Vec<String>> {
    let vec: Vec<&str> = line.split_whitespace().collect();
    if vec.len() != 5 {
        return Err(Error::FdtFileParseError);
    }
    Ok(vec.iter().map(|s| s.to_string()).collect())
}

/// Creates a flattened device tree containing all of the parameters used
/// by Android.
///
/// # Arguments
///
/// * `fdt` - The DTB to modify. The top-most node should be open.
/// * `android-fstab` - A text file of Android fstab entries to add to the DTB
pub fn create_android_fdt(fdt: &mut Vec<u8>, fstab: File) -> Result<()> {
    let vecs = BufReader::new(fstab)
        .lines()
        .map(|l| parse_fstab_line(&l.map_err(Error::FdtIoError)?))
        .collect::<Result<Vec<Vec<String>>>>()?;
    begin_node(fdt, "firmware")?;
    begin_node(fdt, "android")?;
    property_string(fdt, "compatible", "android,firmware")?;
    begin_node(fdt, "fstab")?;
    property_string(fdt, "compatible", "android,fstab")?;
    for vec in vecs {
        let partition = &vec[1][1..];
        begin_node(fdt, partition)?;
        property_string(fdt, "compatible", &("android,".to_owned() + partition))?;
        property_string(fdt, "dev", &vec[0])?;
        property_string(fdt, "type", &vec[2])?;
        property_string(fdt, "mnt_flags", &vec[3])?;
        property_string(fdt, "fsmgr_flags", &vec[4])?;
        end_node(fdt)?;
    }
    end_node(fdt)?; // fstab
    end_node(fdt)?; // android
    end_node(fdt)?; // firmware
    Ok(())
}
