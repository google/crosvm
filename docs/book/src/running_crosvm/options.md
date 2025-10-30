# Command line options

Command-line options generally take a set of key-value pairs separated by the comma (`,`) character.
The acceptable key-values for each option can be obtained by passing the `--help` option to a crosvm
command:

```sh
crosvm run --help
...
  -b, --block       parameters for setting up a block device.
                    Valid keys:
                        path=PATH - Path to the disk image. Can be specified
                            without the key as the first argument.
                        ro=BOOL - Whether the block should be read-only.
                            (default: false)
                        root=BOOL - Whether the block device should be mounted
                            as the root filesystem. This will add the required
                            parameters to the kernel command-line. Can only be
                            specified once. (default: false)
                        sparse=BOOL - Indicates whether the disk should support
                            the discard operation. (default: true)
                        block-size=BYTES - Set the reported block size of the
                            disk. (default: 512)
                        id=STRING - Set the block device identifier to an ASCII
                            string, up to 20 characters. (default: no ID)
                        direct=BOOL - Use O_DIRECT mode to bypass page cache.
                            (default: false)
...
```

From this help message, we see that the `--block` or `-b` option accepts the `path`, `ro`, `root`,
`sparse`, `block-size`, `id`, and `direct` keys. Keys which default value is mentioned are optional,
which means only the `path` key must always be specified.

One example invocation of the `--block` option could be:

```sh
--block path=/path/to/bzImage,root=true,block-size=4096
```

Keys taking a boolean parameters can be enabled by specifying their name witout any value, so the
previous option can also be written as

```sh
--block path=/path/to/bzImage,root,block-size=4096
```

Also, the name of the first key can be entirely omitted, which further simplifies our option as:

```sh
--block /path/to/bzImage,root,block-size=4096
```
