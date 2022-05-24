# Copyright 2022 The Chromium OS Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

from PB.recipes.crosvm.build_chromeos import BuildChromeOsProperties

PYTHON_VERSION_COMPATIBILITY = "PY3"

DEPS = [
    "crosvm",
    "recipe_engine/buildbucket",
    "recipe_engine/context",
    "recipe_engine/properties",
    "recipe_engine/step",
    "recipe_engine/path",
    "recipe_engine/file",
]

PROPERTIES = BuildChromeOsProperties

PACKAGE_LIST = [
    "chromeos-base/crosvm",
]


def SetupSource(api, workspace):
    gitilies = api.buildbucket.build.input.gitiles_commit
    upstream_url = "https://chromium.googlesource.com/crosvm/crosvm"
    revision = gitilies.id or "HEAD"

    # Init and sync the ChromeOS checkout
    api.step(
        "Init repo",
        [
            "repo",
            "init",
            "--manifest-url=https://chromium.googlesource.com/chromiumos/manifest",
            "--manifest-branch=stable",
            "--depth=1",
            "--current-branch",
            "--groups=minilayout,crosvm",
        ],
    )
    api.step(
        "Sync repo",
        [
            "repo",
            "sync",
            "--current-branch",
        ],
    )

    # Overwrite crosvm with the upstream revision we need to test
    with api.context(cwd=workspace.join("src/platform/crosvm")):
        api.step("Fetch upstream crosvm", ["git", "fetch", upstream_url])
        api.step("Checkout upstream revision", ["git", "checkout", revision])


def PrepareBuild(api):
    # Uprev crosvm related ebuild files
    api.step(
        "Uprev packages",
        [
            "./chromite/scripts/cros_uprev",
            "--package=%s" % ",".join(PACKAGE_LIST),
            "--overlay-type=public",
        ],
    )
    # Create chroot as a separate step to document the runtime
    api.step("Create SDK chroot", ["cros_sdk", "--create"])


def BuildAndTest(api, board):
    # TODO: We currently build crosvm twice. Once with build_packages, once to run tests.
    api.step(
        "Build packages",
        ["cros_sdk", "build_packages", "--board=%s" % board, "implicit-system"] + PACKAGE_LIST,
    )
    api.step(
        "Run unit tests",
        ["cros_sdk", "cros_run_unit_tests", "--board=%s" % board, "implicit-system"] + PACKAGE_LIST,
    )


def CleanUp(api):
    api.step("Deleting SDK chroot", ["cros_sdk", "--delete"])


def RunSteps(api, properties):
    workspace = api.path["cleanup"].join("workspace")
    api.file.ensure_directory("Ensure workspace exists", workspace)

    with api.context(cwd=workspace):
        try:
            SetupSource(api, workspace)
            PrepareBuild(api)
            BuildAndTest(api, properties.board or "amd64_generic")
        finally:
            CleanUp(api)


def GenTests(api):
    yield api.test("build_default")
