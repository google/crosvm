# crosvm memory dump tool

A tool to dump memory and processes, useful for diagnosing virtio-blk issues on ARCVM.

## Synopsis

Run from a workstation, against a device under test, like:

```shell
cargo run ${DUT}
```

and the tool will try to collect information via ssh.
