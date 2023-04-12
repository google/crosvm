# Experimental Setup on Minimal Container to Build crosvm in chromeOS Tree

This folder contains a setup to build a container that includes initialized cros_sdk and precompiled
dependencies of crosvm to speed up process of develop and test crosvm in the chromeOS tree.
Currently, we aim to produce a fresh cros_container every week (about 20GB in size).

## Usage Instruction

This container need to be built with `docker buildx` for its support of insecure builder (equivalent
to `docker run --privileged` but for build) which is required for `cros_sdk` due to its usage of
multiple linux namespaces and chroot.

Individual commands from the `cloudbuild.yaml` files can be executed locally. Note you need
permission to access crosvm's Google Cloud project to push the container into artifact registry. For
people without access but plan to push the finished container to a container registry, please
substitute `gcr.io/crosvm-infra/crosvm_cros_cloudbuild` with your own container name.

To use it in Cloud Build, run `gcloud builds submit --config=cloudbuild.yaml` in your command line
with this folder as working directory.
