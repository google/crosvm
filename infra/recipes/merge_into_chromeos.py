# Copyright 2022 The Chromium OS Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

from recipe_engine.post_process import Filter

PYTHON_VERSION_COMPATIBILITY = "PY3"

DEPS = [
    "crosvm",
    "recipe_engine/step",
]


def RunSteps(api):
    with api.crosvm.build_context(container=False):
        api.step(
            "Update Merges",
            [
                "vpython3",
                "./tools/chromeos/merge_bot",
                "--verbose",
                "update-merges",
                "--is-bot",
                "HEAD",
            ],
        )
        api.step(
            "Update Dry Runs",
            [
                "vpython3",
                "./tools/chromeos/merge_bot",
                "--verbose",
                "update-dry-runs",
                "--is-bot",
                "HEAD",
            ],
        )


def GenTests(api):
    yield (api.test("basic") + api.post_process(Filter().include_re(r"Update .*")))
