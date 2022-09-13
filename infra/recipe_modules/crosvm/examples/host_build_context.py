# Copyright 2022 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

PYTHON_VERSION_COMPATIBILITY = "PY3"

DEPS = [
    "crosvm",
    "recipe_engine/platform",
    "recipe_engine/step",
]


def RunSteps(api):
    with api.crosvm.host_build_context():
        api.step("Build", ["cargo", "build"])


def GenTests(api):
    yield api.test("basic_linux") + api.platform("linux", 64)
    yield api.test("basic_windows") + api.platform("win", 64)
