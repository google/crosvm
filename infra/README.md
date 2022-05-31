# WIP Luci Infrastructure

This directory contains the configuration and build recipes run by our luci infrastructure for CI
and presubmit testing. This is currently a work in progress.

See [Kokoro](../ci/kokoro) configs for the actively used presubmit system.

Note: Luci applies config and recipes changes asynchronously. Do not submit changes to this
directory in the same commit as changes to other crosvm source.

## Recipes

### Recipe Documentation

A few links to relevant documentation needed to write recipes:

- [Recipe Engine](https://chromium.googlesource.com/infra/luci/recipes-py.git/+/HEAD/README.recipes.md)
- [Depot Tools Recipes](https://chromium.googlesource.com/chromium/tools/depot_tools.git/+/HEAD/recipes/README.recipes.md))
- [ChromiumOS Recipes](https://chromium.googlesource.com/chromiumos/infra/recipes.git/+/HEAD/README.recipes.md)

Luci also provides a
[User Guide](https://chromium.googlesource.com/infra/luci/recipes-py/+/master/doc/user_guide.md) and
[Walkthrough](https://chromium.googlesource.com/infra/luci/recipes-py/+/refs/heads/main/doc/walkthrough.md)
for getting started with recipes.

### Running recipe tests

Recipes must have 100% code coverage to have tests pass. Tests can be run with:

```
cd infra && ./recipes.py test run
```

Most tests execute a few example invocations, record the commands that would be executed and compare
them to the json files in `*.expected`. This allows developers to catch unwanted side-effects of
their changes.

To regenerate the expectation files, run:

```
cd infra && ./recipes.py test train
```

Then verify the `git diff` to make sure all changes to outcomes are intentional.

### Testing recipes locally

We try to build our recipes to work well locally, so for example build_linux.py can be invoked in
the recipe engine via:

```
cd infra && ./recipes.py run build_linux
```

When run locally, recipes that check out crosvm, will run against the current HEAD of the main
branch.

The recipe will run in the local `infra/.recipe_deps/recipe_engine/workdir` directory and is
preserved between runs in the same way data is preserved on bots, so incremental builds or the use
of cached files can be tested.

### Testing recipes on a bot (Googlers only)

Note: See internal [crosvm/infra](http://go/crosvm/infra) documentation on access control.

Some things cannot be tested locally and need to be run on one of our build bots. This can be done
with the [led](http://go/luci-how-to-led) tool.

To test changes to an existing recipe, you need to find a previous build that you want to use as a
template and get it's buildbucket id:

![buildbucket id](https://screenshot.googleplex.com/9FuL6PhrvJgZLGs.png)

Then `git commit` your recipe changes locally and run:

```
led get-build $BBID | led edit-recipe-bundle | led launch
```

`get-build` will download and output the job definition, `led edit-recipe-bundle` will upload a
version of your local recipes and update the job definition to use them. The resulting job
definition can then be launched on a bot via `led launch`.
