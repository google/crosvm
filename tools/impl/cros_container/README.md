# Experimental Setup on Minimal Container to Build crosvm in chromeOS Tree

This folder contains an **experimental** setup to build a container that includes initialized
cros_sdk and precompiled dependencies of crosvm to speed up process of develop and test crosvm in
chromeOS tree.

Currently, we aim to produce a fresh cros_container every week (about 20GB) and incremental builds
(very rougly estimated to be 2GB each for now). Using this estimation, the container will reach 34GB
at the end of the week, and a weekly fresh container build will return its size back to 20GB.

## Usage Instruction

This container need to be built with `docker buildx` for its support of insecure builder (equivalent
to `docker run --priviliged` but for build) which is required for `cros_sdk` due to its usage of
multiple linux namespaces and chroot.

Individual commands from the `cloudbuild.yaml` files can be executed locally. Note you need
permission to access crosvm's Google Cloud project to push the container into artifact registry. For
people without access but plan to push the finished container to a container registry, please
substitute `gcr.io/crosvm-infra-experimental/crosvm_cros_cloudbuild` with your own container name.

To use it in Cloud Build, run `gcloud builds submit --config=cloudbuild.yaml` in your command line
with either `fresh` or `incremental` as working directory.
