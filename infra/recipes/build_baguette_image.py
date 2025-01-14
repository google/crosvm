# -*- coding: utf-8 -*-
# Copyright 2025 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Recipe for building a Baguette rootfs image."""

import re
import pathlib
from typing import Generator

from PB.recipes.crosvm.build_baguette_image import BuildBaguetteImageProperties
from recipe_engine import post_process
from recipe_engine.recipe_api import RecipeApi
from recipe_engine.recipe_api import StepFailure
from recipe_engine.recipe_test_api import RecipeTestApi
from recipe_engine.recipe_test_api import TestData

DEPS = [
    "recipe_engine/buildbucket",
    "recipe_engine/context",
    "recipe_engine/file",
    "recipe_engine/path",
    "recipe_engine/properties",
    "recipe_engine/step",
    "recipe_engine/time",
    "recipe_engine/raw_io",
    "depot_tools/depot_tools",
    "depot_tools/gclient",
    "depot_tools/bot_update",
    "depot_tools/gsutil",
    "depot_tools/git",
]

PROPERTIES = BuildBaguetteImageProperties

_GCP_PREFIX = "https://storage.googleapis.com"
_PLATFORM2_REPO_URL = "https://chromium.googlesource.com/chromiumos/platform2/"
_BAGUETTE_CODE_PATH = "vm_tools/baguette_image"
_GCP_BUCKET = "cros-containers"
_GCP_BUCKET_PATH = "baguette/images/"

_AMD64_IMAGE_BUILD_PATH = "docker_export/baguette_rootfs_amd64.img.zstd"
_ARM64_IMAGE_BUILD_PATH = "docker_export/baguette_rootfs_arm64.img.zstd"

# image file name should be "baguette_rootfs_<arch>_<build time>_<commit hash>.img.zstd"


def RunSteps(api: RecipeApi, properties: BuildBaguetteImageProperties) -> None:
    with api.context(cwd=api.path.cache_dir, infra_steps=True):
        gclient_config = api.gclient.make_config()
        s = gclient_config.solutions.add()
        s.url = _PLATFORM2_REPO_URL
        s.name = "platform2"
        api.bot_update.ensure_checkout(gclient_config=gclient_config)
    with api.context(cwd=api.path.cache_dir / "platform2" / _BAGUETTE_CODE_PATH):

        api.step("check docker buildx install", ["docker", "buildx"])

        # Version the image.
        version_time = api.time.utcnow().strftime("%Y-%m-%d-%H%M%S")
        result = api.step("Get git hash", ["git", "rev-parse", "HEAD"], stdout=api.raw_io.output())
        commit_hash = result.stdout.strip().decode("utf-8")

        archive_name_amd64 = f"baguette_rootfs_amd64_{version_time}_{commit_hash}.img.zstd"
        archive_name_arm64 = f"baguette_rootfs_arm64_{version_time}_{commit_hash}.img.zstd"
        api.step("build baguette images", ["./src/docker-build.sh"])

        with api.step.nest("upload VM images") as presentation:
            if properties.destination_gs_bucket:
                bucket_name = properties.destination_gs_bucket
            else:
                bucket_name = _GCP_BUCKET
            if properties.destination_gs_path:
                path_name = properties.destination_gs_path
            else:
                path_name = _GCP_BUCKET_PATH

            with api.step.nest("upload amd64 image") as presentation:
                amd64_path_name = str(pathlib.Path(path_name) / archive_name_amd64)
                api.gsutil.upload(_AMD64_IMAGE_BUILD_PATH, bucket_name, amd64_path_name)
                presentation.links["image"] = api.path.join(
                    _GCP_PREFIX, bucket_name, amd64_path_name
                )
            with api.step.nest("upload arm64 image") as presentation:
                arm64_path_name = str(pathlib.Path(path_name) / archive_name_arm64)
                api.gsutil.upload(_ARM64_IMAGE_BUILD_PATH, bucket_name, arm64_path_name)
                presentation.links["image"] = api.path.join(
                    _GCP_PREFIX, bucket_name, arm64_path_name
                )


def GenTests(api: RecipeTestApi) -> Generator[TestData, None, None]:
    good_props = {
        "destination_gs_bucket": "cros-containers-staging",
        "destination_gs_path": "baguette/images/",
    }
    empty_props = {}

    yield api.test(
        "full props",
        api.properties(**good_props),
    )

    yield api.test(
        "no props",
        api.properties(**empty_props),
    )
