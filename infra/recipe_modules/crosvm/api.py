# Copyright 2022 The Chromium OS Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

from recipe_engine import recipe_api

CROSVM_REPO_URL = "https://chromium.googlesource.com/crosvm/crosvm"


class CrosvmApi(recipe_api.RecipeApi):
    "Crosvm specific functionality shared between recipes."

    @property
    def source_dir(self):
        return self.builder_dir.join("crosvm")

    @property
    def builder_dir(self):
        return self.m.path["cache"].join("builder")

    def prepare_source(self):
        """
        Prepares the local crosvm source for testing in `self.source_dir`

        CI jobs will check out the revision to be tested, try jobs will check out the gerrit
        change to be tested.
        """
        self.m.file.ensure_directory("Ensure builder_dir exists", self.builder_dir)

        with self.m.context(cwd=self.builder_dir):
            gclient_config = self.m.gclient.make_config()
            s = gclient_config.solutions.add()
            s.url = CROSVM_REPO_URL
            s.name = "crosvm"
            gclient_config.got_revision_mapping[s.name] = "got_revision"
            self.m.bot_update.ensure_checkout(gclient_config=gclient_config)

        with self.m.context(cwd=self.source_dir):
            self.m.step("Sync Submodules", ["git", "submodule", "update", "--init"])

    def prepare_container(self):
        with self.m.context(cwd=self.source_dir):
            self.m.step(
                "Stop existing dev containers", ["./tools/dev_container", "--verbose", "--stop"]
            )
            self.m.crosvm.step_in_container("Ensure dev container exists", ["true"])

    def step_in_container(self, step_name, command):
        """
        Runs a luci step inside the crosvm dev container.
        """
        self.m.step(
            step_name,
            [
                "./tools/dev_container",
                "--verbose",
            ]
            + command,
        )
