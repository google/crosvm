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

Googlers can find more information on the merge process at [go/crosvm-uprev-playbook].

## Building crosvm for ChromeOS

crosvm on ChromeOS is usually built with Portage, so it follows the same general workflow as any
`cros_workon` package. The full package name is `chromeos-base/crosvm`.

The developer guide section on
[Make your Changes](https://www.chromium.org/chromium-os/developer-library/guides/development/developer-guide/#make-your-changes)
applies to crosvm as well. You can specify the development version to be built with cros_workon, and
build with cros build-packages. Consecutive builds without changes to dependency can be done with
emerge.

```bash
(chroot)$ cros_workon --board=${BOARD} start chromeos-base/crosvm
(chroot or host)$ cros build-packages --board=${BOARD} chromeos-base/crosvm
(chroot)$ emerge-${BOARD} chromeos-base/crosvm -j 10
```

Deploy it via `cros deploy`:

```bash
(chroot)$ cros deploy ${IP} crosvm
```

Iterative test runs can be done as well:

```bash
(chroot)$ FEATURES=test emerge-${BOARD} chromeos-base/crosvm -j 10
```

Warning: Using `cros_workon_make` is possible but patches the local Cargo.toml file and some
configuration files. Please do not submit these changes. Also something makes it rebuild a lot of
the files.

### Rebuilding all crosvm dependencies

Crosvm has a lot of rust dependencies that are installed into a registry inside cros_sdk. After a
`repo sync` these can be out of date, causing compilation issues. To make sure all dependencies are
up to date, run:

```bash
(chroot or host)$ cros build-packages --board=${BOARD} chromeos-base/crosvm
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

For more details on the process, please see [go/crosvm-uprev-playbook] (Googlers only).

## Cq-Depend

**We cannot support Cq-Depend** to sychronize changes with other ChromeOS repositories. Please try
to make changes in a backwards compatible way to allow them to be submitted independently.

If it cannot be avoided at all, please follow this process:

1. Upload your change to upstream crosvm and get it reviewed. Do not submit it yet.
1. Upload the change to [chromiumos/platform/crosvm] as well.
1. Use Cq-Depend on the ChromeOS changes and submit it via the CQ.
1. After the changes landed in ChromeOS, land them upstream as well.

## rutabaga chromeos releases

Upstream crosvm and ChromeOS crosvm will use different versions of rutabaga_gfx crate to guarantee
ChromeOS crosvm stability.

The versions will be API-compatible. This creates two possible scenarios that downstream integrators
should be prepared for.

### upstream rutabaga_gfx update from U.V.W to version X.Y.Z and updating version in ChromeOS downstream

This most commonly happens when upstream crosvm starts using new rutabaga_gfx APIs.

In this case, upstream crosvm will use
[rutabaga_gfx-X.Y.Z](https://crates.io/crates/rutabaga_gfx/0.1.75), while downstream will use
[rutabaga_gfx-X.Y.Z-chromeos](https://crates.io/crates/rutabaga_gfx/0.1.75-chromeos).

The downstream integrator would need to:

1. Uprev to [rutabaga-X.Y.Z in upstream crosvm](https://crrev.com/c/7051742). This will cause a
   merge conflict for downstream.
1. Perform a [downstream merge](https://crrev.com/c/7083089). As part of the merge conflict
   resolution, change rutabaga-U.V.W-chromeos to rutabaga_gfx-X.Y.Z-chromeos. Make another change to
   [CrOS Rust registry](https://crrev.com/c/7085045) to use rutabaga-X.Y.Z-chromeos. Use the
   Cq-Depend mechanism so both the merge commit and CrOS Rust registry change go in at the same
   time.

It is recommended for the upstream update to occur even without downstream CQ testing for ChromeOS.
The reason is rutabaga_gfx-X.Y.Z-chromeos is functionally frozen on a known good version, with _just
enough_ stub API additions to maintain compatibility. The likelihood of breakage under this model is
very small.

### upstream rutabaga_gfx update from U.V.W to version X.Y.Z while keeping the old version in ChromeOS downstream

This most commonly happens when upstream crosvm starts using a new rutabaga_gfx version for
bug-fixes or features, but those bug-fixes/features don't require new APIs.

In this case, a rutabaga_gfx-X.Y-Z-chromeos release will not be available on crates.io.

The downstream integrator would need to:

1. Uprev to rutabaga-X.Y.Z in upstream crosvm. This will cause a merge conflict for downstream.
1. Perform a downstream merge. As part of the merge conflict resolution, keep
   rutabaga-U.V.W-chromeos as the desired version (since it is API compatible with
   rutabaga_gfx-X.Y.Z).

## Cherry-picking

### Cherry-picking without the usual merge process

If you need your changes faster than the usual merge frequency, please follow this process:

1. Upload and submit your change to upstream crosvm.
1. Upload the change to [chromiumos/platform/crosvm] as well.
1. Submit as usual through the CQ.

**Never** submit code just to ChromeOS, as it will cause upstream to diverge and result in merge
conflicts down the road.

### Cherry-picking to release branch

Your change need to be merged into [chromiumos/platform/crosvm] to cherry-pick it to a release
branch. You should follow
[ChromiumOS Merge Workflow](https://www.chromium.org/chromium-os/developer-library/guides/development/work-on-branch/)
to cherry-pick your changes. Since changes are merged from [crosvm/crosvm] to
[chromiumos/platform/crosvm] through [the merge process](#the-merge-process), you can't use gerrit
to cherry-pick your changes but need to use git command locally.

```
$ cd chromiumos/src/platform/crosvm
$ git branch -a | grep remotes/cros/release-R120
  remotes/cros/release-R120-15662.B
$ git checkout -b my-cherry-pick cros/release-R120-15662.B
$ git cherry-pick -x $COMMIT
$ git push cros HEAD:refs/for/release-R120-15662.B
```

`$COMMIT` is the commit hash of the original change you want to cherry-pick not the merge commit.
Note that you push to special gerrit `refs/for/`, not pushing directly to the release branch.

Also note that release branch cherry picks don't get CQ tested at all - they are submitted directly
once you CQ+2 - so it is very important to test locally first.

## Running a Tryjob

For googlers, see go/cdg-site

[chromiumos/platform/crosvm]: https://chromium.googlesource.com/chromiumos/platform/crosvm
[crosvm/crosvm]: https://chromium.googlesource.com/crosvm/crosvm
[go/crosvm-uprev-playbook]: http://go/crosvm-uprev-playbook
