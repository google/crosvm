# Copyright 2022 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

from recipe_engine.post_process import Filter

DEPS = [
    "crosvm",
    "recipe_engine/buildbucket",
    "recipe_engine/context",
    "recipe_engine/properties",
    "recipe_engine/step",
]


def RunSteps(api):
    # Note: The recipe does work on linux as well, if the required dependencies have been installed
    # on the host via ./tools/install-deps.
    # This allows the build to be tested via `./recipe.py run build_windows`
    with api.crosvm.host_build_context():
        api.step(
            "Build crosvm tests",
            [
                "vpython3",
                "./tools/run_tests",
                "--verbose",
                "--build-only",
            ],
        )
        api.step(
            "Run crosvm tests",
            [
                "vpython3",
                "./tools/run_tests",
                "--verbose",
            ],
        )
        api.step(
            "Clippy windows crosvm",
            [
                "vpython3",
                "./tools/clippy",
            ],
        )


def GenTests(api):
    filter_steps = Filter("Build crosvm tests", "Run crosvm tests")
    yield (
        api.test(
            "build",
            api.buildbucket.ci_build(project="crosvm/crosvm"),
        )
        + api.post_process(filter_steps)
    )
