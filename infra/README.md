# Luci Infrastructure

This directory contains the configuration and build recipes run by our luci infrastructure for CI
and presubmit testing.

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

For writing tests, documentation can be found in the
[Recipe test API](https://chromium.googlesource.com/infra/luci/recipes-py/+/HEAD/recipe_engine/recipe_test_api.py)
and
[Post Process API](https://chromium.googlesource.com/infra/luci/recipes-py/+/HEAD/recipe_engine/post_process.py)

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

Commonly used led commands are:

- `led get-builder $NAME` will download and output the job template for that builder.
- `led get-build $BBID` will download the job definition of a previous build.
- `led edit-recipe-bundle` will update the job to use your local version recipes
- `led edit-cr-cl` will update the job to run on a gerrit change
- `led launch` launches a new job using the input job definition.

Important: Changes to recipes are applied separately from changes to crosvm code.

#### Testing recipe changes on post-submit builders

To test a local recipe change, you can launch a post-submit build using `led`. First `git commit`
your recipe changes locally, then combine the led commands to:

```
led get-builder luci.crosvm.ci:linux_x86_64
 | led-edit-recipe-bundle
 | led launch
```

This will run the `linux_x86_64` builder on the current `main` revision of crosvm using the local
version of recipes.

Important: Changes to crosvm source outside of recipes will not be part of the build.

#### Testing recipe and source changes on pre-submit builders

If we want to test a combination of both recipe and source changes, we can test those on a
pre-submit builder, which patch in a gerrit change to test.

We can specify that gerrit change via `led edit-cr-cl`.

So to test, first `git commit` and `./tools/cl upload` your local changes. Then build a job
definition to run:

```
led get-builder luci.crosvm.try:linux_x86_64
 | led-edit-recipe-bundle
 | led-edit-cr-cl $GERRIT_URL
 | led launch
```

This will launch a presubmit builder using the local version of recipes, and runs it on the gerrit
change at $GERRIT_URL.

#### Testing a new recipe

This is a little tricker, but you can change the recipe name that is launched by `led`. So you can:

```
led get-builder luci.crosvm.ci:linux_x86_64 > job.json
```

Then edit the `job.json` file to use the newly added recipe, and launch the job using the local
version of recipes.

```
cat job.json | led-edit-recipe-bundle | led launch
```
