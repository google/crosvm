# Copyright 2022 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import json

from recipe_engine.recipe_api import Property
from recipe_engine.post_process import DropExpectation, StatusFailure, Filter
from PB.recipes.crosvm.build_linux import BuildLinuxProperties

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


def get_test_args(api, properties):
    "Returns architecture specific arguments for ./tools/run_tests"
    test_arch = properties.test_arch
    args = ["--platform=" + test_arch]
    if test_arch == "x86_64":
        args += ["--dut=host"]
    if test_arch == "aarch64":
        args += ["--dut=vm"]
    if properties.crosvm_direct:
        args += ["--features=direct,all-x86_64"]

    profile = properties.profile or "presubmit"
    args += ["--profile=" + profile]
    return args


def collect_binary_sizes(api, properties):
    release_build_result = api.crosvm.step_in_container(
        "Build crosvm releases",
        [
            "./tools/build_release",
            "--json",
            "--platform=" + str(properties.test_arch),
            "--strip",
        ],
        stdout=api.raw_io.output_text(name="Obtain release build output", add_output_log=True),
    )

    if release_build_result.stdout and json.loads(
        release_build_result.stdout.strip().splitlines()[-1]
    ):
        binary_sizes = {}
        builder_name = api.buildbucket.builder_name
        release_build_result_dict = json.loads(release_build_result.stdout.strip().splitlines()[-1])
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
                    "--base-dir",
                    "/scratch/cargo_target/crosvm",
                    # Only upload binary size in postsubmit
                    *(("--upload",) if properties.profile == "postsubmit" else tuple()),
                    "--builder-name",
                    api.buildbucket.builder_name,
                    "--log-url",
                    api.buildbucket.build_url(),
                    "--build-version",
                    api.buildbucket.gitiles_commit.id,
                ],
                infra_step=True,
                stdout=api.raw_io.output_text(),
            )
            binary_sizes.update(json.loads(binary_size_result.stdout.strip().splitlines()[-1]))

        api.step("Write binary sizes into output", None, infra_step=True)
        api.step.active_result.presentation.properties["binary_sizes"] = binary_sizes


def RunSteps(api, properties):
    with api.crosvm.container_build_context():
        api.crosvm.step_in_container(
            "Build crosvm tests",
            [
                "./tools/run_tests2",
                "--verbose",
                "--no-run",
            ]
            + get_test_args(api, properties),
        )
        api.crosvm.step_in_container(
            "Run crosvm tests",
            [
                "./tools/run_tests2",
                "--verbose",
            ]
            + get_test_args(api, properties),
        )
        api.crosvm.step_in_container(
            "Clippy",
            [
                "./tools/clippy",
                "--verbose",
                "--platform=" + properties.test_arch,
            ],
        )
        with api.step.nest("Collect binary sizes"):
            collect_binary_sizes(api, properties)


def GenTests(api):
    filter_steps = Filter(
        "Build crosvm tests",
        "Run crosvm tests",
        "Clippy",
        "Collect binary sizes.Build crosvm releases",
    )
    yield (
        api.test(
            "build_x86_64",
            api.buildbucket.ci_build(project="crosvm/crosvm"),
        )
        + api.properties(BuildLinuxProperties(test_arch="x86_64"))
        + api.step_data(
            "Collect binary sizes.Build crosvm releases",
            stdout=api.raw_io.output_text(
                """Using existing container (82e9d24cd4f0).
$ docker exec 82e9d24cd4f0 /tools/entrypoint.sh ./tools/build_release --json --platform=x86_64
{"crosvm": "/scratch/cargo_target/crosvm/x86_64-unknown-linux-gnu/x86_64-unknown-linux-gnu/release/crosvm"}"""
            ),
        )
        + api.step_data(
            "Collect binary sizes.Get binary size for crosvm",
            stdout=api.raw_io.output_text(
                """Using existing container (291baf4496c5).
{"/scratch/cargo_target/crosvm/x86_64-unknown-linux-gnu/x86_64-unknown-linux-gnu/release/crosvm": 22783488}"""
            ),
        )
        + api.post_process(filter_steps)
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
