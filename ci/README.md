# CrosVM Continuous Integration

Crosvm has a complex set of dependencies and requirements on the host machine to
successfully build and run test cases. To allow for consistent testing in our
continuous integration system (kokoro) and reproduction of those tests locally,
we provide docker containers containing the build toolchain and a VM for
testing.

## Implementation Overview

Directories:

-   ci/build_environment: Contains tooling for building the dependencies of
    crosvm.
-   ci/crosvm_aarch64_builder: An x86 docker image to cross-compile for aarch64
    and test with user-space emulation.
-   ci/crosvm_base: Docker image shared by crosvm_builder and
    crosvm_aarch64_builder
-   ci/crosvm_builder: A native docker image for building and testing crosvm
-   ci/crosvm_test_vm: Dockerfile to build the VM included in the builder
    containers.
-   ci/kokoro: Configuration files and build scripts used by Kokoro to run
    crosvm tests.

Scripts:

-   ci/aarch64_builder: Script to start the crosvm_aarch64_builder container
-   ci/builder: Script to start the crosvm_builder container
-   ci/run_container.sh: Implementation behind the above scripts.
-   test_runner.py: Implementation behind the `./test_all` script.

### Building and uploading a new version of builders

The docker images for all builders can be built with `make` and uploaded with
`make upload`. Of course you need to have docker push permissions for
`gcr.io/crosvm-packages/` for the upload to work.
