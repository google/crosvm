# Dev Container

This directory contains the dev container used by developers locally as well as the crosvm CI
infrastructure.

The container is split into two, `crosvm_dev` defined by `tools/impl/dev_container/Dockerfile` and
`crosvm_dev_base` defined by `tools/impl/dev_container/Dockerfile.base`.

## crosvm_dev_base

The `Dockerfile.base` image contains a plain debian image with only debian packages from
`tools/deps/install-*-debs` installed. Since we track debian testing, new packages can come with new
problems and that image should not be updated very often.

To make changes to those debian packages, modify the install scripts and uprev the
`tools/impl/dev_container/base_version` file. Then rebuild the container with:

```
make -C tools/impl/dev_container crosvm_dev_base
```

Then proceed below to rebuild the `crosvm_dev` container using the new base image as well and upload
both.

## crosvm_dev

The `Dockerfile` builds the dev container on top of `crosvm_dev_base`, so we are free to uprev
tooling without having to pull in new debian packages.

To make changes to `crosvm_dev`, modify the corresponding install scripts and uprev the
`tools/impl/dev_container/version` file. Then rebuild the container with:

```
make -C tools/impl/dev_container crosvm_dev
```

This will make the image available for testing locally with `tools/dev_container`. You may have to
stop the previous container to pick up the new image `tools/dev_container --stop`.

To upload the new version of the containers run:

```
make -C tools/impl/dev_container upload
```

You need to be a Googler to be able to do so. See go/crosvm/infra for access control and
authenticate via:

```
gcloud auth configure-docker gcr.io
```
