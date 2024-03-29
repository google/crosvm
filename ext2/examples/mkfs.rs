// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// To allow compiling this file on non-Linux platforms, main logic is
// behind the `linux` module.
#[cfg(target_os = "linux")]
mod linux {
    use std::fs::OpenOptions;
    use std::io::Write;

    use argh::FromArgs;
    use base::MappedRegion;
    use ext2::Ext2;

    #[derive(FromArgs)]
    /// Create ext2 filesystem.
    struct Config {
        /// path to the disk,
        #[argh(option)]
        path: String,
    }

    pub fn main() -> anyhow::Result<()> {
        let cfg: Config = argh::from_env();
        let ext2 = Ext2::new()?;
        println!("Create {}", cfg.path);
        let mem = ext2.write_to_memory()?;
        // SAFETY: `mem` has a valid pointer and its size.
        let buf = unsafe { std::slice::from_raw_parts(mem.as_ptr(), mem.size()) };
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&cfg.path)
            .unwrap();
        file.write_all(buf).unwrap();

        Ok(())
    }
}

fn main() -> anyhow::Result<()> {
    #[cfg(target_os = "linux")]
    linux::main()?;

    #[cfg(not(target_os = "linux"))]
    println!("Not supported on non-Linux platforms");

    Ok(())
}
