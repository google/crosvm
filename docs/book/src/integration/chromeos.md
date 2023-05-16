# Crosvm on ChromeOS

A copy of crosvm is included in the ChromeOS source tree at [chromiumos/platform/crosvm], which is
referred to as **downstream** crosvm.

All crosvm development is happening **upstream** at [crosvm/crosvm]. Changes from upstream crosvm
are regularly merged with ChromeOS's downstream crosvm.

## The merge process.

A crosvm bot will regularly generate automated commits that merge upstream crosvm into downstream.
These commits can be found in
[gerrit](https://chromium-review.googlesource.com/q/hashtag:crosvm-merge).

The crosvm team is submitting these merges through the ChromeOS CQ regularly, which happens
**roughly once per week**, but time can vary depending on CQ health.

Googlers can find more information on the merge process at
[go/crosvm/playbook](http://go/crosvm/playbook)

## Building crosvm for ChromeOS

crosvm on ChromeOS is usually built with Portage, so it follows the same general workflow as any
`cros_workon` package. The full package name is `chromeos-base/crosvm`.

The developer guide section on
[Make your Changes](https://chromium.googlesource.com/chromiumos/docs/+/main/developer_guide.md#make-your-changes)
applies to crosvm as well. You can build crosvm with `cros_workon_make`:

```bash
cros_workon --board=${BOARD} start crosvm
cros_workon_make --board=${BOARD} crosvm
```

Deploy it via `cros deploy`:

```bash
cros_workon_make --board=${BOARD} --install crosvm
cros deploy ${IP} crosvm
```

Iterative test runs can be done as well:

```bash
cros_workon_make --board=${BOARD} --test crosvm
```

Warning: `cros_workon_make` patches the local Cargo.toml file. Please do not submit these changes.

### Rebuilding all crosvm dependencies

Crosvm has a lot of rust dependencies that are installed into a registry inside cros_sdk. After a
`repo sync` these can be out of date, causing compilation issues. To make sure all dependencies are
up to date, run:

```bash
emerge-${BOARD} --update --deep -j$(nproc) crosvm
```

## Building crosvm for Linux

`emerge` and `cros_workon_make` workflows can be quite slow to work with, hence a lot of developers
prefer to use standard cargo workflows used upstream.

Just make sure to initialize git submodules (`git submodules update --init`), which is not done by
repo. After that, you can use the workflows as outlined in
[Building Crosvm](../building_crosvm/linux.md) **outside** of cros_sdk.

Note: You can **not** build or test ChromeOS specific features this way.

## Submitting Changes

All changes to crosvm are made upstream, using the same process outlined in
[Contributing](../contributing/index.md). It is recommended to use the
[Building crosvm for Linux](#building-crosvm-for-linux) setup above to run upstream presubmit checks
/ formatting tools / etc when submitting changes.

Code submitted upstream is tested on linux, but not on ChromeOS devices. Changes will only be tested
on the ChromeOS CQ when they go through [the merge process](#the-merge-process).

## Has my change landed in ChromeOS (Googlers only)?

You can use the [crosland](http://crosland/cl) tool to check in which ChromeOS version your changes
have been merged into the [chromiumos/platform/crosvm] repository.

The merge will also contain all `BUG=` references that will notify your bugs about when the change
is submitted.

For more details on the process, please see [go/crosvm-playbook](http://go/crosvm-playbook) (Google
only).

## Cq-Depend

**We cannot support Cq-Depend** to sychronize changes with other ChromeOS repositories. Please try
to make changes in a backwards compatible way to allow them to be submitted independently.

If it cannot be avoided at all, please follow this process:

1. Upload your change to upstream crosvm and get it reviewed. Do not submit it yet.
1. Upload the change to [chromiumos/platform/crosvm] as well.
1. Use Cq-Depend on the ChromeOS changes and submit it via the CQ.
1. After the changes landed in ChromeOS, land them upstream as well.

## Cherry-picking

If you need your changes faster than the usual merge frequency, please follow this process:

1. Upload and submit your change to upstream crosvm.
1. Upload the change to [chromiumos/platform/crosvm] as well.
1. Submit as usual through the CQ.

**Never** submit code just to ChromeOS, as it will cause upstream to diverge and result in merge
conflicts down the road.

[chromiumos/platform/crosvm]: https://chromium.googlesource.com/chromiumos/platform/crosvm
[crosvm/crosvm]: https://chromium.googlesource.com/crosvm/crosvm
