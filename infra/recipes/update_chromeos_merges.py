# Copyright 2022 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

from recipe_engine.post_process import Filter

PYTHON_VERSION_COMPATIBILITY = "PY3"

DEPS = [
    "crosvm",
    "recipe_engine/context",
    "recipe_engine/step",
]


def RunSteps(api):
    with api.crosvm.source_context():
        api.step(
            "Update Merges",
            [
                "vpython3",
                "./tools/chromeos/merge_bot",
                "--verbose",
                "update-merges",
                "--is-bot",
                "origin/main",
            ],
        )


def GenTests(api):
    yield (api.test("basic") + api.post_process(Filter().include_re(r"Update .*")))
