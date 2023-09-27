# Crosvm End to End Tests

These tests run a crosvm VM on the host to verify end to end behavior. They use a prebuilt guest
kernel and rootfs, which is downloaded from google cloud storage.

The e2e_tests can be executed by:

`$ ./tools/run_tests2 --dut=vm -E 'rdeps(e2e_tests)'`

## Running with locally built kernel/rootfs

If the test needs to run offline, or you want to make changes to the kernel or rootfs, you have to
specify the environment variables `CROSVM_CARGO_TEST_KERNEL_BINARY` and
`CROSVM_CARGO_TEST_ROOTFS_IMAGE` to point to the right files.

The use_local_build.sh script does this for you:

`$ source guest_under_test/use_local_build.sh`

## Uploading prebuilts

Note: Only Googlers with access to the crosvm-testing cloud storage bin can upload prebuilts.

To upload the modified rootfs, you will have to uprev the `PREBUILT_VERSION` variable in:

- `./guest_under_test/PREBUILT_VERSION`

and [request a permission](http://go/crosvm/infra.md?cl=head#access-on-demand-to-upload-artifacts)
to become a member of the `crosvm-policy-uploader` group.

Then run the upload script to build and upload the new prebuilts.

```sh
# Install QEMU-user-static to build aarch64 images
$ sudo apt install binfmt-support qemu-user-static
# Register binfmt_misc entries
$ docker run --rm --privileged multiarch/qemu-user-static --reset -p yes
# Build and upload the new artifacts
$ ./guest_under_test/upload_prebuilts.sh
```

**Never** try to modify an existing prebuilt as the new images may break tests in older versions.
