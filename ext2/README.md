# ext2

This crate provides utilities to create ext2 file system on memory or a file.

`examples/mkfs.rs` shows how to use this library. This program is our alternative to `mkfs.ext2`
that create an ext2 file system on a file and useful for debugging this ext2 itself with existing
utilities in `e2fsprogs` such as `fsck` and `dumpe2fs`.

```console
$ cargo run --release --example mkfs -- --path disk.img
Create disk.img
$ dumpe2fs disk.img
dumpe2fs 1.47.0 (5-Feb-2023)
Filesystem volume name:   <none>
Last mounted on:          <not available>
Filesystem UUID:          c6e49d8f-106f-4472-b0e8-6babcc3fa496
Filesystem magic number:  0xEF53
...
```
