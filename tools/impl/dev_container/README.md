# Dev Container

This directory contains the dev container used by developers locally as well as the crosvm CI
infrastructure.

The container is defined by `tools/impl/dev_container/Dockerfile`, which will primarily run the
`tools/install*` scripts to install all dependencies.

To include new dependencies in the container, modify the corresponding install script and rebuild
the container with:

```
make -C tools/impl/dev_container crosvm_dev
```

This will make the image available for testing locally with `tools/dev_container`. You may have to
stop the previous container to pick up the new image `tools/dev_container --stop`.

To upload the new version of the container, uprev the `version` file and run;

```
make -C tools/impl/dev_container upload
```

You need to be a Googler to be able to do so. See go/crosvm/infra for access control and
authenticate via:

```
gcloud auth configure-docker gcr.io
```
