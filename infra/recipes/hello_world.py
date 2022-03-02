# Enumerates the recipe modules that this recipe uses.
#
# "recipe_engine" is the "repo_name" for the recipes-py repo, and "step"
# is the name of the "step" recipe module within that repo. The
# "recipe_engine/step" module will be the most frequently-used module in your
# recipes as it allows you to run executables within your build.
DEPS = [
    "recipe_engine/step",
]


def RunSteps(api):
    # Creates an 'empty' (i.e. no-op) step in the UI with the name "Hello world".
    api.step.empty("Hello world")


def GenTests(api):
    # Tells the recipe engine to generate an expectation file (JSON simulation
    # output) for this recipe when it is run without any input properties.
    yield api.test("basic")
