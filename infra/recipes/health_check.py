# Copyright 2022 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

from recipe_engine.post_process import Filter

DEPS = [
    "crosvm",
    "recipe_engine/raw_io",
    "recipe_engine/buildbucket",
    "recipe_engine/context",
    "recipe_engine/properties",
    "recipe_engine/step",
]


def RunSteps(api):
    with api.crosvm.container_build_context():
        api.step(
            "Self-test dev-container",
            [
                "vpython3",
                api.crosvm.source_dir / "tools/dev_container",
                "--verbose",
                "--self-test",
            ],
        )
        result = api.step(
            "List checks to run",
            [
                "vpython3",
                api.crosvm.source_dir / "tools/presubmit",
                "--list-checks",
                "health_checks",
            ],
            stdout=api.raw_io.output_text(),
        )
        check_list = result.stdout.strip().split("\n")
        for check in check_list:
            api.crosvm.step_in_container(
                "tools/presubmit %s" % check, ["tools/presubmit", "--no-delta", check]
            )


def GenTests(api):
    yield (
        api.test(
            "basic",
            api.buildbucket.ci_build(project="crosvm/crosvm"),
            # Provide a fake response to --list-checks
            api.step_data(
                "List checks to run",
                stdout=api.raw_io.output_text("check_a\ncheck_b"),
            ),
        )
        + api.post_process(Filter("List checks to run").include_re(r"tools/presubmit .*"))
    )
