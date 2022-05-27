# Copyright 2022 The Chromium OS Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

from recipe_engine.recipe_api import Property
from recipe_engine.post_process import DropExpectation, StatusFailure, Filter
from PB.recipes.crosvm.build_linux import BuildLinuxProperties

PYTHON_VERSION_COMPATIBILITY = "PY3"

DEPS = [
    "crosvm",
    "recipe_engine/buildbucket",
    "recipe_engine/context",
    "recipe_engine/properties",
    "recipe_engine/step",
]

PROPERTIES = BuildLinuxProperties


def get_test_args(api, test_arch):
    "Returns architecture specific arguments for ./tools/run_tests"
    # TODO(denniskempin): Move this logic into ./tools/presubmit
    if test_arch == "" or test_arch == "x86_64":
        return ["--target=host"]
    elif test_arch == "aarch64":
        return ["--target=vm:aarch64"]
    elif test_arch == "armhf":
        return ["--target=vm:aarch64", "--arch=armhf"]
    else:
        raise api.step.StepFailure("Unknown test_arch " + test_arch)


def RunSteps(api, properties):
    with api.crosvm.build_context():
        api.crosvm.step_in_container(
            "Build crosvm tests",
            [
                "./tools/run_tests",
                "--verbose",
                "--build-only",
            ]
            + get_test_args(api, properties.test_arch),
        )
        api.crosvm.step_in_container(
            "Run crosvm tests",
            [
                "./tools/run_tests",
                "--verbose",
            ]
            + get_test_args(api, properties.test_arch),
        )


def GenTests(api):
    filter_steps = Filter("Build crosvm tests", "Run crosvm tests")
    yield (
        api.test(
            "build_x86_64",
            api.buildbucket.ci_build(project="crosvm/crosvm"),
        )
        + api.properties(BuildLinuxProperties(test_arch="x86_64"))
        + api.post_process(filter_steps)
    )
    yield (
        api.test(
            "build_aarch64",
            api.buildbucket.ci_build(project="crosvm/crosvm"),
        )
        + api.properties(BuildLinuxProperties(test_arch="aarch64"))
        + api.post_process(filter_steps)
    )
    yield (
        api.test(
            "build_armhf",
            api.buildbucket.ci_build(project="crosvm/crosvm"),
        )
        + api.properties(BuildLinuxProperties(test_arch="armhf"))
        + api.post_process(filter_steps)
    )
    yield (
        api.test(
            "build_unknown",
            api.buildbucket.ci_build(project="crosvm/crosvm"),
        )
        + api.properties(BuildLinuxProperties(test_arch="foobar"))
        + api.post_process(StatusFailure)
        + api.post_process(DropExpectation)
    )
