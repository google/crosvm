// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// To allow compiling this file on non-Linux platforms, main logic is
// behind the `linux` module.
#[cfg(target_os = "linux")]
mod linux {
    use std::fs::OpenOptions;
    use std::io::Write;
    use std::path::PathBuf;

    use argh::FromArgs;
    use base::MappedRegion;

    #[derive(FromArgs)]
    /// Create ext2 filesystem.
    struct Args {
        /// path to the disk,
        #[argh(option)]
        output: String,

        /// path to the source directory to copy files from,
        #[argh(option)]
        src: Option<String>,

        /// number of blocks for each group
        #[argh(option, default = "1024")]
        blocks_per_group: u32,

        /// number of inodes for each group
        #[argh(option, default = "1024")]
        inodes_per_group: u32,

        /// size of memory region in bytes.
        /// If it's not a multiple of 4096, it will be rounded up to the next multiple of 4096.
        #[argh(option, default = "4194304")]
        size: u32,

        /// if sepecified, create a file systeon on RAM, but do not write to disk.
        #[argh(switch, short = 'j')]
        dry_run: bool,
    }

    pub fn main() -> anyhow::Result<()> {
        let args: Args = argh::from_env();
        let src_dir = args.src.as_ref().map(|s| PathBuf::new().join(s));
        let builder = ext2::Builder {
            blocks_per_group: args.blocks_per_group,
            inodes_per_group: args.inodes_per_group,
            size: args.size,
            root_dir: src_dir,
        };
        let mem = builder.allocate_memory()?.build_mmap_info()?.do_mmap()?;
        if args.dry_run {
            println!("Done!");
            return Ok(());
        }

        // SAFETY: `mem` has a valid pointer and its size.
        let buf = unsafe { std::slice::from_raw_parts(mem.as_ptr(), mem.size()) };
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&args.output)
            .unwrap();

        file.write_all(buf).unwrap();

        println!("{} is written!", args.output);

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
