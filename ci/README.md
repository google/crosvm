# CrosVM Continuous Integration Builders

This directory contains the toolchain to build docker containers for building
and testing crosvm. They are used by Kokoro during presubmit and on continuous
integration runs, but can also be used locally to run tests in a predictable
environment.

## Overview

- ci/build_environment: Contains tooling for building the dependencies of
  crosvm.
- ci/crosvm_base: Docker image shared by crosvm_builder and
  crosvm_aarch64_builder
- ci/crosvm_builder: A native docker image for building and testing crosvm
- ci/crosvm_aarch64_builder: An x86 docker image to cross-compile for aarch64
  and test with user-space emulation.
- ci/builder: Script to start the crosvm_builder container
- ci/aarch64_builder: Script to start the crosvm_aarch64_builder container

## Running the builder locally

You need to check out crosvm via `repo`, to pull all the required chromiumos
dependencies:

```
$ repo init -u https://chromium.googlesource.com/chromiumos/manifest.git --repo-url https://chromium.googlesource.com/external/repo.git -g crosvm
$ repo sync -j4
$ cd src/platform/crosvm
```

A standard chromiumos checkout following the
[ChromiumOS Developer Guide](https://chromium.googlesource.com/chromiumos/docs/+/master/developer_guide.md#Get-the-Source)
will work too.

To run all crosvm tests using the builder and it's included virtual machine:

```
$ ./ci/builder --vm ./run_tests
$ ./ci/aarch64_builder --vm ./run_tests
```

or start an interactive shell for either of them:

```
$ ./ci/builder [--vm]
$ ./ci/aarch64_builder [--vm]
```

When the builder is started, it will prepare the environment for building and
running tests, this includes building dependencies for crosvm that are provided
by the ChromiumOS checkout.

The environment in both is setup so that `cargo test` or existing scripts like
`bin/smoke_tests` compile for the right target and execute tests correctly
(using qemu-user for aarch64).

The builders allow for incremental builds by storing build artifacts in
`$CARGO_TARGET/ci/crosvm_builder`.

### Using the built-in VM

The builders come with a built-in VM which is automatically started in the
background when run as `./ci/builder --vm`. The enviornment is then set up to
automatically run `cargo test` binaries through the `/workspace/vm/exec_file`
script, which will take care of copying the required .so files and executes the
test binary.

The `./run_tests` script will also make use of the VM for testing.

### Using podman

Podman is a daemon-less docker replacement that runs containers without root
privileges. If podman is installed, it will be automatically used.

For Googlers, see [go/dont-install-docker](http://go/dont-install-docker) for
more details.

Note: Since podman runs with your users permissions, you need to setup access to
devices required by tests. Most notably `/dev/kvm` and `/dev/net/tun`.

### Building and uploading a new version of builders

The docker images for all builders can be built with `make` and uploaded with
`make upload`. Of course you need to have docker push permissions for
`gcr.io/crosvm-packages/` for the upload to work.
