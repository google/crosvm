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

To run the smoke tests suite for both x86 and aarch64 on an x86 machine, just
run:

```
$ cd platform/src/crosvm
$ ./ci/builder bin/smoke_test
$ ./ci/aarch64_builder bin/smoke_test
```

or start an interactive shell for either of them:

```
$ ./ci/builder
$ ./ci/aarch64_builder
```

Note: Tests on aarch64 are a work in progress and may not pass.

When the builder is started, it will prepare the environment for building and
running tests, this includes building dependencies for crosvm that are provided
by the ChromiumOS checkout.

The environment in both is setup so that `cargo test` or existing scripts like
`bin/smoke_tests` compile for the right target and execute tests correctly
(using qemu-user for aarch64).

The builders allow for incremental builds by storing build artifacts in
`$CARGO_TARGET/ci/crosvm_builder`.

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
`registry.gitlab.com/crosvm-ci/crosvm-ci` for the upload to work.
