# Crosvm General Purpose Libraries

The crates in this folder are general purpose libraries used by other projects in ChromeOS as well.

To make them accessible independendly of crosvm, each of these crates is excluded from the crosvm
workspace.

## List of libraries

- [cros-fuzz](cros-fuzz/): Support crate for fuzzing rust code in ChromeOS
- [p9](p9): Server implementation of the 9p file system protocol
