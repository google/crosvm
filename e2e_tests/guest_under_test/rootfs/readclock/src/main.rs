// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use anyhow::Result;

#[cfg(any(target_os = "linux", target_os = "android"))]
fn main() -> Result<()> {
    use readclock::ClockValues;
    let clocks = ClockValues::now();
    println!("{}", serde_json::to_string(&clocks)?);
    Ok(())
}

// Fallback main function to make the library's serialize / deserialize implementation usable on the e2etest side
// (which may not be Linux environment).
// This workaround is needed due to cargo's dependency limitations.
// c.f. https://github.com/rust-lang/cargo/issues/1982
#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn main() -> Result<()> {
    unimplemented!("This architecture does not support reading CLOCK_MONOTONIC and CLOCK_BOOTTIME")
}
