# Crosvm on ChromeOS

Crosvm is included in the ChromeOS source tree at `src/platform/crosvm`.

Since crosvm is developed independently of ChromeOS, submitted code is not directly included in
ChromeOS builds. The main development branch is `main`, which is tested on crosvm's own
infrastructure, running unit and integration tests on linux.

ChromeOS follows the `chromeos` branch, which undergoes testing by the ChromeOS CQ and is merged
with `main` roughtly **once per week** by the crosvm team.

## Has my change landed in ChromeOS (Googlers only)?

You can use the [crosland](http://crosland/cl) tool to check in which ChromeOS version your changes
has been merged into the `chromeos` branch.

The merge will also contain all `BUG=` references that will notify your bugs about when the change
is submitted.

For more details on the process, please see [go/crosvm-playbook](http://go/crosvm-playbook) (Google
only).

## Using repo

The repository at `src/platform/crosvm` is tracking the `chromeos` branch, which is also used by
`repo start`, so you can develop with a CQ-tested foundation.

However, changes are not acceped to the `cros/chromeos` branch, and should be submitted to
`cros/main` instead.

Use `repo upload -D main` to upload changes to the main branch, which works fine in most cases where
gerrit can rebase the commit cleanly. If not, please rebase to `cros/main` manually:

```bash
git branch --set-upstream-to cros/main
git rebase
```

## First time setup / running tools

- All CrosVM `tools` are not expected to work inside the ChromeOS chroot. As such, they must be run
  outside the chroot (but inside the source tree).

- Cloning the ChromeOS source tree will not clone submodules relied upon by the CrosVM build (e.g.
  as used by `tools`). To fix this, run `git submodules update --init` in the `crosvm` root from
  outside the chroot.

## Cq-Depend

**We cannot support Cq-Depend** to sychronize changes with other ChromeOS repositories. Please try
to make changes in a backwards compatible way to allow them to be submitted independently.

If it cannot be avoided at all, please follow the instructions below to manually cherry-pick your
change to the `chromeos` branch.

## Cherry-picking

If you need your changes faster than the usual merge frequency, or need to use Cq-Depend, please
consider cherry-picking your changes to the `chromeos` branch manually.

In order to do so, upload your change to the `main` branch and get a review as usual. Before
submitting the changes to the `main` branch, use the "Cherry-Pick" function in the "..." menu of the
gerrit UI.

The created cherry-pick can be annotated with Cq-Depend if needed and can be submitted through the
CQ like any other ChromeOS change.

Only **after** the cherry-pick is submitted, submit the change to the `main` branch as well.

**Never** submit code to just the `chromeos` branch, as it will cause upstream to diverge and result
in merge conflicts down the road.

## Building for ChromeOS

Crosvm can be built with ChromeOS features using Portage or cargo.

If ChromeOS-specific features are not needed, or you want to run the full test suite of crosvm, the
[Building Crosvm](../building_crosvm.md) workflows can be used from the crosvm repository of
ChromeOS as well.

### Using Portage

crosvm on ChromeOS is usually built with Portage, so it follows the same general workflow as any
`cros_workon` package. The full package name is `chromeos-base/crosvm`.

See the
[Chromium OS developer guide](https://chromium.googlesource.com/chromiumos/docs/+/main/developer_guide.md)
for more on how to build and deploy with Portage.

> NOTE: `cros_workon_make` allows faster, iterative builds, but modifies crosvm's Cargo.toml. Please
> be careful not to commit the changes. Moreover, with the changes cargo will fail to build and
> clippy preupload check will fail.

### Using Cargo

Since development using portage can be slow, it's possible to build crosvm for ChromeOS using cargo
for faster iteration times. To do so, the `Cargo.toml` file needs to be updated to point to
dependencies provided by ChromeOS using `./tools/chromeos/setup_cargo`.
