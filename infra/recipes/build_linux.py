# Copyright 2022 The ChromiumOS Authors
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

COVERAGE_FILE = "coverage.lcov"


def get_test_args(api, properties):
    "Returns architecture specific arguments for ./tools/run_tests"
    # TODO(denniskempin): Move this logic into ./tools/presubmit
    test_arch = properties.test_arch
    args = ["--platform=" + test_arch]
    if properties.crosvm_direct:
        args += ["--crosvm-direct"]
    if properties.coverage:
        args += ["--generate-lcov", COVERAGE_FILE]
    return args


def RunSteps(api, properties):
    with api.crosvm.container_build_context():
        api.crosvm.step_in_container(
            "Build crosvm tests",
            [
                "./tools/run_tests",
                "--verbose",
                "--build-only",
            ]
            + get_test_args(api, properties),
        )
        api.crosvm.step_in_container(
            "Run crosvm tests",
            [
                "./tools/run_tests",
                "--verbose",
                "--retry=" + str(properties.retry_tests or 0),
                "--repeat=" + str(properties.repeat_tests or 1),
            ]
            + get_test_args(api, properties),
        )
        if properties.coverage:
            api.crosvm.upload_coverage(COVERAGE_FILE)


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
            "build_x86_64_coverage",
            api.buildbucket.ci_build(project="crosvm/crosvm"),
        )
        + api.properties(BuildLinuxProperties(test_arch="x86_64", coverage=True))
    )
    yield (
        api.test(
            "build_x86_64_direct",
            api.buildbucket.ci_build(project="crosvm/crosvm"),
        )
        + api.properties(BuildLinuxProperties(test_arch="x86_64", crosvm_direct=True))
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
            "build_mingw64",
            api.buildbucket.ci_build(project="crosvm/crosvm"),
        )
        + api.properties(BuildLinuxProperties(test_arch="mingw_64"))
        + api.post_process(filter_steps)
    )
