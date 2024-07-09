# Copyright 2022 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# Runs tools/presubmit on all checks within a group

import json

from recipe_engine.recipe_api import Property
from recipe_engine.post_process import DropExpectation, StatusFailure, Filter
from PB.recipes.crosvm.presubmit import PresubmitProperties

DEPS = [
    "crosvm",
    "recipe_engine/buildbucket",
    "recipe_engine/context",
    "recipe_engine/json",
    "recipe_engine/properties",
    "recipe_engine/raw_io",
    "recipe_engine/step",
]

PROPERTIES = PresubmitProperties


def RunSteps(api, properties):
    with api.crosvm.container_build_context():
        result = api.step(
            "List checks to run",
            [
                "vpython3",
                api.crosvm.source_dir / "tools/presubmit",
                "--list-checks",
                properties.group_name,
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
        )
        + api.properties(PresubmitProperties(group_name="basic"))
        + api.step_data(
            "List checks to run",
            stdout=api.raw_io.output_text("check_a\ncheck_b"),
        )
        + api.post_process(Filter("List checks to run").include_re(r"tools/presubmit .*"))
    )
