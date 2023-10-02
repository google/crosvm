// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::fs::File;
use std::io::BufRead;
use std::io::BufReader;

use cros_fdt::Error;
use cros_fdt::Fdt;
use cros_fdt::Result;

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
pub fn create_android_fdt(fdt: &mut Fdt, fstab: File) -> Result<()> {
    let vecs = BufReader::new(fstab)
        .lines()
        .map(|l| parse_fstab_line(&l.map_err(Error::FdtIoError)?))
        .collect::<Result<Vec<Vec<String>>>>()?;
    let firmware_node = fdt.begin_node("firmware")?;
    let android_node = fdt.begin_node("android")?;
    fdt.set_prop("compatible", "android,firmware")?;

    let (dtprop, fstab): (_, Vec<_>) = vecs.into_iter().partition(|x| x[0] == "#dt-vendor");
    let vendor_node = fdt.begin_node("vendor")?;
    for vec in dtprop {
        let content = std::fs::read_to_string(&vec[2]).map_err(Error::FdtIoError)?;
        fdt.set_prop(&vec[1], content)?;
    }
    fdt.end_node(vendor_node)?;
    let fstab_node = fdt.begin_node("fstab")?;
    fdt.set_prop("compatible", "android,fstab")?;
    for vec in fstab {
        let partition = &vec[1][1..];
        let partition_node = fdt.begin_node(partition)?;
        fdt.set_prop("compatible", "android,".to_owned() + partition)?;
        fdt.set_prop("dev", vec[0].as_str())?;
        fdt.set_prop("type", vec[2].as_str())?;
        fdt.set_prop("mnt_flags", vec[3].as_str())?;
        fdt.set_prop("fsmgr_flags", vec[4].as_str())?;
        fdt.end_node(partition_node)?;
    }
    fdt.end_node(fstab_node)?;
    fdt.end_node(android_node)?;
    fdt.end_node(firmware_node)?;
    Ok(())
}
