# Copyright 2022 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

PYTHON_VERSION_COMPATIBILITY = "PY3"

DEPS = [
    "crosvm",
    "recipe_engine/buildbucket",
]


def RunSteps(api):
    with api.crosvm.source_context():
        api.crosvm.get_git_sha()


def GenTests(api):
    REPO = "https://chromium.googlesource.com/crosvm/crosvm"
    REVISION = "2d72510e447ab60a9728aeea2362d8be2cbd7789"

    yield (
        api.test(
            "prepare_source_for_try",
            api.buildbucket.try_build(project="crosvm", git_repo=REPO),
        )
    )
    yield (
        api.test(
            "prepare_source_for_ci",
            api.buildbucket.ci_build(project="crosvm", git_repo=REPO, revision=REVISION),
        )
    )
    yield (
        api.test(
            "repair_submodules",
            api.buildbucket.ci_build(project="crosvm", git_repo=REPO, revision=REVISION),
            api.step_data(
                "Prepare source.Sync submodules.Init / Update submodules",
                retcode=1,
            ),
        )
    )
