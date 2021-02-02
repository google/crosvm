# CrosVM Continuous Integration

Crosvm has a complex set of dependencies and requirements on the host machine to
successfully build and run test cases. To allow for consistent testing in our
continuous integration system (kokoro) and reproduction of those tests locally,
we provide docker containers containing the build toolchain and a VM for
testing.

## How to run crosvm tests

### Setting up the source

Since crosvm is part of chromiumos, and uses a couple of it's projects as
dependencies, you need a standard chromiumos checkout as described by the
[ChromiumOS Developer Guide](https://chromium.googlesource.com/chromiumos/docs/+/master/developer_guide.md#Get-the-Source).

To reduce the number of repositories to download, you can use the `-g crosvm`
argument on `repo init`. This will be significantly faster:

In summary:

```
$ repo init -u https://chromium.googlesource.com/chromiumos/manifest.git --repo-url https://chromium.googlesource.com/external/repo.git -g crosvm
$ repo sync -j4
$ cd src/platform/crosvm
```

### Installing Podman (or Docker)

See [Podman Installation](https://podman.io/getting-started/installation) for
instructions on how to install podman.

For Googlers, see [go/dont-install-docker](http://go/dont-install-docker) for
special instructions on how to set up podman.

If you already have docker installed, that will do as well. However podman is
recommended as it will not run containers with root privileges.

### Running all tests

To run all tests, just run:

```
./test_all
```

This will run all tests using the x86 and aarch64 builder containers. What does
this do?

1. It will start `./ci/[aarch64_]builder --vm`.

   The builder will build ChromeOS dependencies from your local repo checkout.
   If you make modifications to these dependencies (e.g. minijail, tpm2, cras)
   these will be included in tests.

   Then it will start a VM for running tests in the background. The VM is
   booting while the next step is running.

2. Then it will call `./run_tests` inside the builder

   The script will pick which tests to execute and where. Simple tests can be
   executed directly, other tests require privileged access to devices and will
   be loaded into the VM to execute.

   Each test will in the end be executed by a call to
   `cargo test -p crate_name`.

Intermediate build data is stored in a scratch directory at `./target/ci/` to
allow for faster subsequent calls (Note: If running with docker, these files
will be owned by root).

### Fast, iterative test runs

For faster iteration time, you can directly invoke some of these steps directly:

To only run x86 tests: `./ci/[aarch64_]builder --vm ./run_tests`.

To run a simple test (e.g. the tempfile crate) that does not need the vm:
`./ci/[aarch64_]builder cargo test -p tempfile`.

Or run a single test (e.g. kvm_sys) inside the vm:
`./ci/[aarch64*]builder --vm cargo test -p kvm_sys`.

Since the VM (especially the fully emulated aarch64 VM) can be slow to boot, you
can start an interactive shell and run commands from there as usual. All cargo
tests will be executed inside the VM, without the need to restart the VM between
test calls.

```
host$ ./ci/aarch64_builder --vm
crosvm-aarch64$ ./run_tests
crosvm-aarch64$ cargo test -p kvm_sys
...
```

### Reproducing Kokoro locally

Kokoro uses the same builders and the same `run_tests` script to run tests.
However, to keep the build stable, it syncs the chromiumos checkout to the fixed
manifest found at `./ci/kokoro/manifest.xml`.

To run tests using the same manifest, as well as the same build process that
Kokoro uses, you can run: `./ci/kokoro/simulate_all`.

## Implementation Overview

Directories:

- ci/build_environment: Contains tooling for building the dependencies of
  crosvm.
- ci/crosvm_aarch64_builder: An x86 docker image to cross-compile for aarch64
  and test with user-space emulation.
- ci/crosvm_base: Docker image shared by crosvm_builder and
  crosvm_aarch64_builder
- ci/crosvm_builder: A native docker image for building and testing crosvm
- ci/crosvm_test_vm: Dockerfile to build the VM included in the builder
  containers.
- ci/kokoro: Configuration files and build scripts used by Kokoro to run crosvm
  tests.

Scripts:

- ci/aarch64_builder: Script to start the crosvm_aarch64_builder container
- ci/builder: Script to start the crosvm_builder container
- ci/run_container.sh: Implementation behind the above scripts.
- test_runner.py: Implementation behind the `./test_all` script.

### Building and uploading a new version of builders

The docker images for all builders can be built with `make` and uploaded with
`make upload`. Of course you need to have docker push permissions for
`gcr.io/crosvm-packages/` for the upload to work.
