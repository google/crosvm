# WIP Luci Infrastructure

This directory contains the configuration and build recipes run by our luci infrastructure for CI
and presubmit testing. This is currently a work in progress.

See [Kokoro](../ci/kokoro) configs for the actively used presubmit system.

Note: Luci applies config and recipes changes asynchronously. Do not submit changes to this
directory in the same commit as changes to other crosvm source.

## Recipe Documentation

A few links to relevant documentation needed to write recipes:

- [Recipe Engine](https://chromium.googlesource.com/infra/luci/recipes-py.git/+/HEAD/README.recipes.md)
- [Depot Tools Recipes](https://chromium.googlesource.com/chromium/tools/depot_tools.git/+/HEAD/recipes/README.recipes.md))
- [ChromiumOS Recipes](https://chromium.googlesource.com/chromiumos/infra/recipes.git/+/HEAD/README.recipes.md)

Luci also provides a
[User Guide](https://chromium.googlesource.com/infra/luci/recipes-py/+/master/doc/user_guide.md) and
[Walkthrough](https://chromium.googlesource.com/infra/luci/recipes-py/+/refs/heads/main/doc/walkthrough.md)
for getting started with recipes.
