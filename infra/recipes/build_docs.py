# Copyright 2022 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

from recipe_engine.post_process import Filter

DEPS = [
    "crosvm",
    "recipe_engine/file",
    "recipe_engine/buildbucket",
    "recipe_engine/context",
    "recipe_engine/step",
    "depot_tools/gsutil",
]

BOOK_URL = "gs://crosvm-dot-dev/book"
DOCS_URL = "gs://crosvm-dot-dev/doc"


def RunSteps(api):
    """
    Builds crosvm mdbook and api docs, then uploads them to GCS.

    This recipe requires ambient luci authentication. To test locally run:
       $ luci-auth context ./infra/recipes.py run build_docs
    """
    with api.crosvm.container_build_context():
        api.crosvm.step_in_container(
            "Build mdbook", ["mdbook", "build", "docs/book/", "--dest-dir", "../target"]
        )
        api.crosvm.step_in_container(
            "Run cargo docs",
            ["./tools/cargo-doc", "--target-dir", "docs/target"],
        )

        # Container generated files are root-owned, we need to make sure they will be readable by
        # gsutil (which has to run outside the container to run with proper authentication).
        api.crosvm.step_in_container(
            "Make docs readable by gsutil",
            ["chmod", "-R", "o+r", "docs/target"],
        )

        api.gsutil(
            ["rsync", "-r", "-d", "./docs/target/html", BOOK_URL],
            name="Upload book",
            multithreaded=True,
        )
        # TODO(b/239255064): Generate the redirect HTML so we can use cleanly mirror here too.
        api.gsutil(
            ["rsync", "-r", "./docs/target/doc", DOCS_URL],
            name="Upload docs",
            multithreaded=True,
        )


def GenTests(api):
    filter_steps = Filter(
        "Build mdbook", "Run cargo docs", "gsutil Upload book", "gsutil Upload docs"
    )
    yield (
        api.test(
            "build_docs",
            api.buildbucket.ci_build(project="crosvm/crosvm"),
        )
        + api.post_process(filter_steps)
    )
