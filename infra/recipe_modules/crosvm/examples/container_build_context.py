# Copyright 2022 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

PYTHON_VERSION_COMPATIBILITY = "PY3"

DEPS = [
    "crosvm",
]


def RunSteps(api):
    with api.crosvm.container_build_context():
        api.crosvm.step_in_container("Build", ["cargo", "build"])
        api.crosvm.upload_coverage("coverage.lcov")


def GenTests(api):
    yield api.test("basic")
