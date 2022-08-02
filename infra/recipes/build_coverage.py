# Copyright 2022 The Chromium OS Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
from recipe_engine.post_process import Filter

PYTHON_VERSION_COMPATIBILITY = "PY3"

DEPS = [
    "crosvm",
    "recipe_engine/buildbucket",
    "recipe_engine/context",
    "recipe_engine/cipd",
    "recipe_engine/step",
]


def RunSteps(api):
    with api.crosvm.container_build_context():
        api.crosvm.step_in_container(
            "Run crosvm tests",
            [
                "./tools/run_tests",
                "--verbose",
                "--generate-lcov=coverage.lcov",
            ],
        )
        codecov = api.cipd.ensure_tool("crosvm/codecov/${platform}", "latest")
        sha = api.crosvm.get_git_sha()
        api.step(
            "Uploading to covecov.io",
            [
                "bash",
                api.resource("codecov_wrapper.sh"),
                codecov,
                "--nonZero",  # Enables error codes
                "--slug",
                "google/crosvm",
                "--sha",
                sha,
                "--branch",
                "main",
                "-f",
                "coverage.lcov",
            ],
        )


def GenTests(api):
    filter_steps = Filter("Run crosvm tests", "Uploading to covecov.io")
    yield (
        api.test(
            "generate_coverage",
            api.buildbucket.ci_build(project="crosvm/crosvm"),
        )
        + api.post_process(filter_steps)
    )
