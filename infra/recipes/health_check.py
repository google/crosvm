# Copyright 2022 The Chromium OS Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

from recipe_engine.post_process import Filter

PYTHON_VERSION_COMPATIBILITY = "PY3"

DEPS = [
    "crosvm",
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
                api.crosvm.source_dir.join("tools/dev_container"),
                "--verbose",
                "--self-test",
            ],
        )
        for check in ("python", "misc", "fmt", "clippy"):
            api.crosvm.step_in_container("Checking %s" % check, ["./tools/health-check", check])


def GenTests(api):
    yield (
        api.test(
            "basic",
            api.buildbucket.ci_build(project="crosvm/crosvm"),
        )
        + api.post_process(Filter().include_re(r"Checking.*"))
    )
