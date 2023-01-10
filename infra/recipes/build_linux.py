# Copyright 2022 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import json

from recipe_engine.recipe_api import Property
from recipe_engine.post_process import DropExpectation, StatusFailure, Filter
from PB.recipes.crosvm.build_linux import BuildLinuxProperties

PYTHON_VERSION_COMPATIBILITY = "PY3"

DEPS = [
    "crosvm",
    "recipe_engine/buildbucket",
    "recipe_engine/context",
    "recipe_engine/json",
    "recipe_engine/properties",
    "recipe_engine/raw_io",
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
        release_build_result = api.crosvm.step_in_container(
            "Build crosvm releases",
            [
                "./tools/build_release",
                "--json",
                "--platform=" + str(properties.test_arch),
            ],
            stdout=api.raw_io.output_text(name="Obtain release build output", add_output_log=True),
        )

        if release_build_result.stdout and json.loads(
            release_build_result.stdout.strip().splitlines()[-1]
        ):
            binary_sizes = {}
            builder_name = api.buildbucket.builder_name
            release_build_result_dict = json.loads(
                release_build_result.stdout.strip().splitlines()[-1]
            )
            for target_name, binary_path in release_build_result_dict.items():
                binary_size_result = api.crosvm.step_in_container(
                    "Get binary size for {}".format(target_name),
                    [
                        "./tools/infra/binary_size",
                        "--builder-name",
                        builder_name,
                        "--target-name",
                        target_name,
                        "--target-path",
                        binary_path,
                    ],
                    infra_step=True,
                    stdout=api.raw_io.output_text(),
                )
                binary_sizes.update(json.loads(binary_size_result.stdout.strip().splitlines()[-1]))

            api.step("Write binary sizes into output", None, infra_step=True)
            api.step.active_result.presentation.properties["binary_sizes"] = binary_sizes

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
    filter_steps = Filter("Build crosvm releases", "Build crosvm tests", "Run crosvm tests")
    yield (
        api.test(
            "build_x86_64",
            api.buildbucket.ci_build(project="crosvm/crosvm"),
        )
        + api.properties(BuildLinuxProperties(test_arch="x86_64"))
        + api.step_data(
            "Build crosvm releases",
            stdout=api.raw_io.output_text(
                """Using existing container (82e9d24cd4f0).
$ docker exec 82e9d24cd4f0 /tools/entrypoint.sh ./tools/build_release --json --platform=x86_64
{"crosvm": "/scratch/cargo_target/crosvm/x86_64-unknown-linux-gnu/x86_64-unknown-linux-gnu/release/crosvm"}"""
            ),
        )
        + api.step_data(
            "Get binary size for crosvm",
            stdout=api.raw_io.output_text(
                """Using existing container (291baf4496c5).
{"/scratch/cargo_target/crosvm/x86_64-unknown-linux-gnu/x86_64-unknown-linux-gnu/release/crosvm": 22783488}"""
            ),
        )
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
