# Copyright 2022 The Chromium OS Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

from recipe_engine.post_process import (
    DropExpectation,
    StepCommandContains,
)

PYTHON_VERSION_COMPATIBILITY = "PY3"

DEPS = [
    "crosvm",
    "recipe_engine/buildbucket",
]


def RunSteps(api):
    with api.crosvm.source_context():
        pass


def GenTests(api):
    REPO = "https://chromium.googlesource.com/crosvm/crosvm"
    REVISION = "2d72510e447ab60a9728aeea2362d8be2cbd7789"

    yield (
        api.test(
            "prepare_source_for_try",
            api.buildbucket.try_build(project="crosvm", git_repo=REPO),
        )
        + api.post_process(StepCommandContains, "Prepare source.bot_update", ["--patch_ref"])
        + api.post_process(DropExpectation)
    )
    yield (
        api.test(
            "prepare_source_for_ci",
            api.buildbucket.ci_build(project="crosvm", git_repo=REPO, revision=REVISION),
        )
        + api.post_process(
            StepCommandContains, "Prepare source.bot_update", ["--revision", "crosvm@" + REVISION]
        )
        + api.post_process(DropExpectation)
    )
