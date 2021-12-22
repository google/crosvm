// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::fs::OpenOptions;
use std::io::{Read, Write};

use argh::FromArgs;

use base::WriteZeroes;
use disk::{self, QcowFile};

#[derive(FromArgs)]
#[argh(
    subcommand,
    name = "header",
    description = "Show the qcow2 header for a file."
)]
struct HeaderSubCommand {
    #[argh(positional)]
    file_path: String,
}

#[derive(FromArgs)]
#[argh(
    subcommand,
    name = "l1_table",
    description = "Show the L1 table entries for a file."
)]
struct L1TableSubCommand {
    #[argh(positional)]
    file_path: String,
}

#[derive(FromArgs)]
#[argh(
    subcommand,
    name = "l22table",
    description = "Show the L2 table pointed to by the nth L1 entry."
)]
struct L22TableSubCommand {
    #[argh(positional)]
    file_path: String,
    #[argh(positional)]
    l1_index: usize,
}

#[derive(FromArgs)]
#[argh(
    subcommand,
    name = "ref_table",
    description = "Show the refblock table for the file."
)]
struct RefTableSubCommand {
    #[argh(positional)]
    file_path: String,
}

#[derive(FromArgs)]
#[argh(
    subcommand,
    name = "ref_block",
    description = "Show the nth reblock in the file."
)]
struct RefBlockSubCommand {
    #[argh(positional)]
    file_path: String,
    #[argh(positional)]
    table_index: usize,
}

#[derive(FromArgs)]
#[argh(
    subcommand,
    name = "dd",
    description = "Write bytes from the raw source_file to the file."
)]
struct DDSubCommand {
    #[argh(positional)]
    file_path: String,
    #[argh(positional)]
    source_path: String,
    #[argh(positional)]
    count: Option<usize>,
}

#[derive(FromArgs)]
#[argh(
    subcommand,
    name = "convert",
    description = "Convert from src_file to dst_file."
)]
struct ConvertSubCommand {
    #[argh(positional)]
    src_path: String,
    #[argh(positional)]
    dst_path: String,
}

#[derive(FromArgs)]
#[argh(subcommand)]
#[allow(non_camel_case_types)]
enum Command {
    header(HeaderSubCommand),
    l1_table(L1TableSubCommand),
    l22_table(L22TableSubCommand),
    ref_table(RefTableSubCommand),
    ref_block(RefBlockSubCommand),
    dd(DDSubCommand),
    convert(ConvertSubCommand),
}

#[derive(FromArgs)]
#[argh(description = "QCOW2 Utilities")]
struct Options {
    #[argh(subcommand)]
    command: Command,
}

fn main() -> std::result::Result<(), ()> {
    match argh::from_env::<Options>().command {
        Command::header(h) => show_header(&h.file_path),
        Command::l1_table(l) => show_l1_table(&l.file_path),
        Command::l22_table(l) => show_l2_table(&l.file_path, l.l1_index),
        Command::ref_table(r) => show_ref_table(&r.file_path),
        Command::ref_block(r) => show_ref_block(&r.file_path, r.table_index),
        Command::dd(d) => dd(&d.file_path, &d.source_path, d.count),
        Command::convert(c) => convert(&c.src_path, &c.dst_path),
    }
}

fn show_header(file_path: &str) -> std::result::Result<(), ()> {
    let file = match OpenOptions::new().read(true).open(file_path) {
        Ok(f) => f,
        Err(_) => {
            println!("Failed to open {}", file_path);
            return Err(());
        }
    };

    let qcow_file = QcowFile::from(file, disk::MAX_NESTING_DEPTH).map_err(|_| ())?;
    let header = qcow_file.header();

    println!("magic {:x}", header.magic);
    println!("version {:x}", header.version);
    println!("backing_file_offset {:x}", header.backing_file_offset);
    println!("backing_file_size {:x}", header.backing_file_size);
    println!("cluster_bits {:x}", header.cluster_bits);
    println!("size {:x}", header.size);
    println!("crypt_method {:x}", header.crypt_method);
    println!("l1_size {:x}", header.l1_size);
    println!("l1_table_offset {:x}", header.l1_table_offset);
    println!("refcount_table_offset {:x}", header.refcount_table_offset);
    println!(
        "refcount_table_clusters {:x}",
        header.refcount_table_clusters
    );
    println!("nb_snapshots {:x}", header.nb_snapshots);
    println!("snapshots_offset {:x}", header.snapshots_offset);
    println!("incompatible_features {:x}", header.incompatible_features);
    println!("compatible_features {:x}", header.compatible_features);
    println!("autoclear_features {:x}", header.autoclear_features);
    println!("refcount_order {:x}", header.refcount_order);
    println!("header_size {:x}", header.header_size);
    Ok(())
}

fn show_l1_table(file_path: &str) -> std::result::Result<(), ()> {
    let file = match OpenOptions::new().read(true).open(file_path) {
        Ok(f) => f,
        Err(_) => {
            println!("Failed to open {}", file_path);
            return Err(());
        }
    };

    let qcow_file = QcowFile::from(file, disk::MAX_NESTING_DEPTH).map_err(|_| ())?;
    let l1_table = qcow_file.l1_table();

    for (i, l2_offset) in l1_table.iter().enumerate() {
        println!("{}: {:x}", i, l2_offset);
    }

    Ok(())
}

fn show_l2_table(file_path: &str, index: usize) -> std::result::Result<(), ()> {
    let file = match OpenOptions::new().read(true).open(file_path) {
        Ok(f) => f,
        Err(_) => {
            println!("Failed to open {}", file_path);
            return Err(());
        }
    };

    let mut qcow_file = QcowFile::from(file, disk::MAX_NESTING_DEPTH).map_err(|_| ())?;
    let l2_table = qcow_file.l2_table(index).unwrap();

    if let Some(cluster_addrs) = l2_table {
        for (i, addr) in cluster_addrs.iter().enumerate() {
            if i % 16 == 0 {
                print!("\n{:x}:", i);
            }
            print!(" {:x}", addr);
        }
    }

    Ok(())
}

fn show_ref_table(file_path: &str) -> std::result::Result<(), ()> {
    let file = match OpenOptions::new().read(true).open(file_path) {
        Ok(f) => f,
        Err(_) => {
            println!("Failed to open {}", file_path);
            return Err(());
        }
    };

    let qcow_file = QcowFile::from(file, disk::MAX_NESTING_DEPTH).map_err(|_| ())?;
    let ref_table = qcow_file.ref_table();

    for (i, block_offset) in ref_table.iter().enumerate() {
        println!("{}: {:x}", i, block_offset);
    }

    Ok(())
}

fn show_ref_block(file_path: &str, index: usize) -> std::result::Result<(), ()> {
    let file = match OpenOptions::new().read(true).open(file_path) {
        Ok(f) => f,
        Err(_) => {
            println!("Failed to open {}", file_path);
            return Err(());
        }
    };

    let mut qcow_file = QcowFile::from(file, disk::MAX_NESTING_DEPTH).map_err(|_| ())?;
    let ref_table = qcow_file.refcount_block(index).unwrap();

    if let Some(counts) = ref_table {
        for (i, count) in counts.iter().enumerate() {
            if i % 16 == 0 {
                print!("\n{:x}:", i);
            }
            print!(" {:x}", count);
        }
    }

    Ok(())
}

// Transfers from a raw file specifiec in `source_path` to the qcow file specified in `file_path`.
fn dd(file_path: &str, source_path: &str, count: Option<usize>) -> std::result::Result<(), ()> {
    let file = match OpenOptions::new().read(true).write(true).open(file_path) {
        Ok(f) => f,
        Err(_) => {
            println!("Failed to open {}", file_path);
            return Err(());
        }
    };

    let mut qcow_file = QcowFile::from(file, disk::MAX_NESTING_DEPTH).map_err(|_| ())?;

    let mut src_file = match OpenOptions::new().read(true).open(source_path) {
        Ok(f) => f,
        Err(_) => {
            println!("Failed to open {}", file_path);
            return Err(());
        }
    };

    let mut read_count = 0;
    const CHUNK_SIZE: usize = 65536;
    let mut buf = [0; CHUNK_SIZE];
    loop {
        let this_count = if let Some(count) = count {
            std::cmp::min(CHUNK_SIZE, count - read_count)
        } else {
            CHUNK_SIZE
        };
        let nread = src_file.read(&mut buf[..this_count]).map_err(|_| ())?;
        // If this block is all zeros, then use write_zeros so the output file is sparse.
        if buf.iter().all(|b| *b == 0) {
            qcow_file.write_zeroes_all(CHUNK_SIZE).map_err(|_| ())?;
        } else {
            qcow_file.write(&buf).map_err(|_| ())?;
        }
        read_count += nread;
        if nread == 0 || Some(read_count) == count {
            break;
        }
    }

    println!("wrote {} bytes", read_count);

    Ok(())
}

// Reads the file at `src_path` and writes it to `dst_path`.
// The output format is detected based on the `dst_path` file extension.
fn convert(src_path: &str, dst_path: &str) -> std::result::Result<(), ()> {
    let src_file = match OpenOptions::new().read(true).open(src_path) {
        Ok(f) => f,
        Err(_) => {
            println!("Failed to open source file {}", src_path);
            return Err(());
        }
    };

    let dst_file = match OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .open(dst_path)
    {
        Ok(f) => f,
        Err(_) => {
            println!("Failed to open destination file {}", dst_path);
            return Err(());
        }
    };

    let dst_type = if dst_path.ends_with("qcow2") {
        disk::ImageType::Qcow2
    } else {
        disk::ImageType::Raw
    };

    match disk::convert(src_file, dst_file, dst_type, disk::MAX_NESTING_DEPTH) {
        Ok(_) => {
            println!("Converted {} to {}", src_path, dst_path);
            Ok(())
        }
        Err(_) => {
            println!("Failed to copy from {} to {}", src_path, dst_path);
            Err(())
        }
    }
}
