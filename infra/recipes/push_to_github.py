# Copyright 2022 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

from recipe_engine.post_process import Filter

DEPS = [
    "crosvm",
    "recipe_engine/buildbucket",
    "recipe_engine/context",
    "recipe_engine/raw_io",
    "recipe_engine/step",
    "recipe_engine/path",
    "recipe_engine/file",
]


def RunSteps(api):
    with api.crosvm.source_context():
        # Execute push in a bash script so there is no chance of leaking the github token via luci
        # logs.
        api.step("Pushing to github", ["bash", api.resource("push_to_github.sh")])


def GenTests(api):
    yield (api.test("basic") + api.post_process(Filter("Pushing to github")))
