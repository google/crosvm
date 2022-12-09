# Command line options and configuration files

It is possible to configure a VM through command-line options and/or a JSON configuration file.

The names and format of configurations options are consistent between both ways of specifying,
however the command-line includes options that are deprecated or unstable, whereas the configuration
file only allows stable options. This section reviews how to use both.

## Command-line options

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

## Configuration files

Configuration files are specified using the `--cfg` argument. Here is an example configuration file
specifying a basic VM with a few devices:

```json
{
    "kernel": "/path/to/bzImage",
    "cpus": {
        "num-cores": 8
    },
    "mem": {
        "size": 2048
    },
    "block": [
        {
            "path": "/path/to/root.img",
            "root": true
        }
    ],
    "serial": [
        {
            "type": "stdout",
            "hardware": "virtio-console",
            "console": true,
            "stdin": true
        }
    ],
    "net": [
        {
            "tap-name": "crosvm_tap"
        }
    ]
}
```

The equivalent command-line options corresponding to this configuration file would be:

```sh
--kernel path/to/bzImage \
--cpus num-cores=8 --mem size=2048 \
--block path=/path/to/root.img,root \
--serial type=stdout,hardware=virtio-console,console,stdin \
--net tap-name=crosvm_tap
```

Or, if we apply the simplification rules discussed in the previous section:

```sh
--kernel /path/to/bzImage \
--cpus 8 --mem 2048 \
--block /path/to/root.img,root \
--serial stdout,hardware=virtio-console,console,stdin \
--net tap-name=crosvm_tap
```

## Combining configuration files and command-line options

One useful use of configuration files is to specify a base configuration that can be augmented or
modified.

Configuration files and other command-line options can be specified together. When this happens, the
command-line parameters will be merged into the initial configuration created by the configuration
file, regardless of their position relative to the `--cfg` argument and even if they come before it.

The effect of command-line arguments redefining items of the configuration file depends on the
nature of said items. If an item can be specified several times (like a block device), then the
command-line arguments will augment the configuration file. For instance, considering this
configuration file `vm.json`:

```json
{
    "kernel": "/path/to/bzImage",
    "block": [
        {
            "path": "/path/to/root.img",
            "root": true
        }
    ]
}
```

And the following crosvm invocation:

```sh
crosvm run --cfg vm.json --block /path/to/home.img
```

Then the created VM will have two block devices, the first one pointing to `root.img` and the second
one to `home.img`.

For options that can be specified only once, like `--kernel`, the one specified on the command-line
will take precedence over the one in the configuration file. For instance, with the same `vm.json`
file and the following command-line:

```sh
crosvm run --cfg vm.json --kernel /path/to/another/bzImage
```

Then the loaded kernel will be `/path/to/another/bzImage`, and the `kernel` option in the
configuration file will become a no-op.
