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


def collect_binary_sizes(api, properties):
    release_build_result = api.crosvm.step_in_container(
        "Build crosvm releases",
        [
            "./tools/build_release",
            "--json",
            "--platform=" + str(properties.test_arch),
            "--build-profile",
            "chromeos",
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
        presubmit_group = f"linux_{properties.test_arch}"
        result = api.step(
            "List checks to run",
            [
                "vpython3",
                api.crosvm.source_dir.join("tools/presubmit"),
                "--list-checks",
                presubmit_group,
            ],
            stdout=api.raw_io.output_text(),
        )
        check_list = result.stdout.strip().split("\n")
        for check in check_list:
            with api.context(env={"NEXTEST_PROFILE": properties.profile}):
                api.crosvm.step_in_container(
                    "tools/presubmit %s" % check, ["tools/presubmit", "--no-delta", check]
                )

        with api.step.nest("Collect binary sizes"):
            collect_binary_sizes(api, properties)


def GenTests(api):
    yield (
        api.test(
            "build_x86_64",
            api.buildbucket.ci_build(project="crosvm/crosvm"),
        )
        + api.properties(BuildLinuxProperties(test_arch="x86_64", profile="postsubmit"))
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
        + api.step_data(
            "List checks to run",
            stdout=api.raw_io.output_text("check_a\ncheck_b"),
        )
        + api.post_process(
            Filter("List checks to run")
            .include_re(r"tools/presubmit .*")
            .include_re(r"Collect binary sizes.*")
        )
    )
