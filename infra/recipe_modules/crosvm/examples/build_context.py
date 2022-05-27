# Copyright 2022 The Chromium OS Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

PYTHON_VERSION_COMPATIBILITY = "PY3"

DEPS = [
    "crosvm",
]


def RunSteps(api):
    with api.crosvm.build_context():
        api.crosvm.step_in_container("Foo", ["echo", "success"])


def GenTests(api):
    yield api.test("basic")
