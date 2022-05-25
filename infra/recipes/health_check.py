# Copyright 2022 The Chromium OS Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import re
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
    api.crosvm.prepare_source()
    api.crosvm.prepare_container()
    with api.context(cwd=api.crosvm.source_dir):
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
