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

    def __set_git_config(self, prop, value):
        self.m.step(
            "Set git config: %s" % prop,
            ["git", "config", "--global", prop, value],
        )

    def build_context(self, source=True, container=True):
        """
        Prepares everything needed to build crosvm on the revision that needs to be verified.

        This updates the cwd to the crosvm source directory, ensures the revision to be tested
        is checked out and the dev container is ready.

        Usage:
            with api.crosvm.build_context():
                api.crosvm.step_in_container("build crosvm", ["cargo build"])
        """
        self.prepare_git()
        if source:
            self.prepare_source()
        if container:
            self.prepare_container()
        return self.m.context(cwd=self.source_dir)

    def prepare_source(self):
        """
        Prepares the local crosvm source for testing in `self.source_dir`

        CI jobs will check out the revision to be tested, try jobs will check out the gerrit
        change to be tested.
        """
        with self.m.step.nest("Prepare source"):
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
        with self.m.step.nest("Prepare dev_container"):
            with self.m.context(cwd=self.source_dir):
                self.m.step(
                    "Stop existing dev containers",
                    [
                        "vpython3",
                        self.source_dir.join("tools/dev_container"),
                        "--verbose",
                        "--stop",
                    ],
                )
                self.m.crosvm.step_in_container("Ensure dev container exists", ["true"])

    def prepare_git(self):
        with self.m.step.nest("Prepare git"):
            with self.m.context(cwd=self.m.path["start_dir"]):
                name = self.m.git.config_get("user.name")
                email = self.m.git.config_get("user.email")
                if not name or not email:
                    self.__set_git_config("user.name", "Crosvm Bot")
                    self.__set_git_config(
                        "user.email", "crosvm-bot@crosvm-infra.iam.gserviceaccount.com"
                    )

    def step_in_container(self, step_name, command):
        """
        Runs a luci step inside the crosvm dev container.
        """
        self.m.step(
            step_name,
            [
                "vpython3",
                self.source_dir.join("tools/dev_container"),
                "--verbose",
            ]
            + command,
        )
