# Copyright 2022 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import contextlib
from recipe_engine import recipe_api

CROSVM_REPO_URL = "https://chromium.googlesource.com/crosvm/crosvm"


class CrosvmApi(recipe_api.RecipeApi):
    "Crosvm specific functionality shared between recipes."

    @property
    def source_dir(self):
        "Where the crosvm source will be checked out."
        return self.builder_cache.join("crosvm")

    @property
    def rustup_home(self):
        "RUSTUP_HOME is cached between runs."
        return self.builder_cache.join("rustup")

    @property
    def cargo_home(self):
        "CARGO_HOME is cached between runs."
        return self.builder_cache.join("cargo_home")

    @property
    def cargo_target_dir(self):
        "CARGO_TARGET_DIR is cleaned up between runs"
        return self.m.path["cleanup"].join("cargo_target")

    @property
    def local_bin(self):
        "Directory used to install local tools required by the build."
        return self.builder_cache.join("local_bin")

    @property
    def dev_container_cache(self):
        return self.builder_cache.join("dev_container")

    @property
    def builder_cache(self):
        """
        Dedicated cache directory for each builder.

        Luci will try to run each builder on the same bot as previously to keep this cache present.
        """
        return self.m.path["cache"].join("builder")

    def source_context(self):
        """
        Updates the source to the revision to be tested and drops into the source directory.

        Use when no build commands are needed.
        """
        with self.m.context(infra_steps=True):
            self.__prepare_source()
            return self.m.context(cwd=self.source_dir)

    def container_build_context(self):
        """
        Prepares source and system to build crosvm via dev container.

        Usage:
            with api.crosvm.container_build_context():
                api.crosvm.step_in_container("build crosvm", ["cargo build"])
        """
        with self.m.step.nest("Prepare Container Build"):
            with self.m.context(infra_steps=True):
                self.__prepare_source()
                self.__prepare_container()
        env = {
            "CROSVM_CONTAINER_CACHE": str(self.dev_container_cache),
        }
        return self.m.context(cwd=self.source_dir, env=env)

    def cros_container_build_context(self):
        """
        Prepares source and system to build crosvm via cros container.

        Usage:
            with api.crosvm.cros_container_build_context():
                api.crosvm.step_in_container("build crosvm", ["cargo build"], cros=True)
        """
        with self.m.step.nest("Prepare Cros Container Build"):
            with self.m.context(infra_steps=True):
                self.__prepare_source()
            with self.m.context(cwd=self.source_dir):
                self.m.step(
                    "Stop existing cros containers",
                    [
                        "vpython3",
                        self.source_dir.join("tools/dev_container"),
                        "--verbose",
                        "--stop",
                        "--cros",
                    ],
                )
                self.m.step(
                    "Force pull cros_container",
                    [
                        "vpython3",
                        self.source_dir.join("tools/dev_container"),
                        "--pull",
                        "--cros",
                    ],
                )
                self.m.crosvm.step_in_container("Ensure cros container exists", ["true"], cros=True)
        return self.m.context(cwd=self.source_dir)

    def host_build_context(self):
        """
        Prepares source and system to build crosvm directly on the host.

        This will install the required rust version via rustup. However no further dependencies
        are installed.

        Usage:
            with api.crosvm.host_build_context():
                api.step("build crosvm", ["cargo build"])
        """
        with self.m.step.nest("Prepare Host Build"):
            with self.m.context(infra_steps=True):
                self.__prepare_source()
                env = {
                    "RUSTUP_HOME": str(self.rustup_home),
                    "CARGO_HOME": str(self.cargo_home),
                    "CARGO_TARGET_DIR": str(self.cargo_target_dir),
                }
                env_prefixes = {
                    "PATH": [
                        self.cargo_home.join("bin"),
                        self.local_bin,
                    ],
                }
                with self.m.context(env=env, env_prefixes=env_prefixes, cwd=self.source_dir):
                    self.__prepare_rust()
                    self.__prepare_host_depdendencies()

                return self.m.context(env=env, env_prefixes=env_prefixes, cwd=self.source_dir)

    def step_in_container(self, step_name, command, cros=False, **kwargs):
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
            + (["--cros"] if cros else [])
            + command,
            **kwargs
        )

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
            # Use gcloud for authentication, which will make sure we are interacting with gerrit
            # using the Luci configured identity.
            if not self.m.platform.is_win:
                self.__set_git_config("credential.helper", "gcloud.sh")

    def get_git_sha(self):
        result = self.m.step(
            "Get git sha", ["git", "rev-parse", "HEAD"], stdout=self.m.raw_io.output()
        )
        value = result.stdout.strip().decode("utf-8")
        result.presentation.step_text = value
        return value

    def upload_coverage(self, filename):
        with self.m.step.nest("Uploading coverage"):
            codecov = self.m.cipd.ensure_tool("crosvm/codecov/${platform}", "latest")
            sha = self.get_git_sha()
            self.m.step(
                "Uploading to covecov.io",
                [
                    "bash",
                    self.resource("codecov_wrapper.sh"),
                    codecov,
                    "--nonZero",  # Enables error codes
                    "--slug=google/crosvm",
                    "--sha=" + sha,
                    "--branch=main",
                    "-X=search",  # Don't search for coverage files, just upload the file below.
                    "-f",
                    filename,
                ],
            )

    def __prepare_rust(self):
        """
        Prepares the rust toolchain via rustup.

        Installs rustup-init via CIPD, which is then used to install the rust toolchain version
        required by the crosvm sources.

        Note: You want to run this after prepare_source to ensure the correct version is installed.
        """
        with self.m.step.nest("Prepare rust"):
            if not self.m.path.exists(
                self.cargo_home.join("bin/rustup")
            ) and not self.m.path.exists(self.cargo_home.join("bin/rustup.exe")):
                rustup_init = self.m.cipd.ensure_tool("crosvm/rustup-init/${platform}", "latest")
                self.m.step("Install rustup", [rustup_init, "-y", "--default-toolchain", "none"])

            if self.m.platform.is_win:
                self.m.step(
                    "Set rustup default host",
                    ["rustup", "set", "default-host", "x86_64-pc-windows-gnu"],
                )

            # Rustup installs a rustc wrapper that will download and use the version specified by
            # crosvm in the rust-toolchain file.
            self.m.step("Ensure toolchain is installed", ["rustc", "--version"])

    def __prepare_host_depdendencies(self):
        """
        Installs additional dependencies of crosvm host-side builds. This is mainly used for
        builds on windows where the dev container is not available.
        """
        with self.m.step.nest("Prepare host dependencies"):
            self.m.file.ensure_directory("Ensure local_bin exists", self.local_bin)

            ensure_file = self.m.cipd.EnsureFile()
            ensure_file.add_package("crosvm/protoc/${platform}", "latest")
            self.m.cipd.ensure(self.local_bin, ensure_file)

    def __sync_submodules(self):
        with self.m.step.nest("Sync submodules") as sync_step:
            with self.m.context(cwd=self.source_dir):
                try:
                    self.m.step(
                        "Init / Update submodules",
                        ["git", "submodule", "update", "--force", "--init"],
                    )
                except:
                    # Since the repository is cached between builds, the submodules could be left in
                    # a bad state (e.g. after a previous build is cancelled while syncing).
                    # Repair this by re-initializing the submodules.
                    self.m.step(
                        "De-init submodules",
                        ["git", "submodule", "deinit", "--force", "--all"],
                    )
                    self.m.step(
                        "Re-init / Update submodules",
                        ["git", "submodule", "update", "--force", "--init"],
                    )
                    sync_step.step_text = "Repaired submodules."
                    sync_step.status = self.m.step.WARNING

    def __prepare_source(self):
        """
        Prepares the local crosvm source for testing in `self.source_dir`

        CI jobs will check out the revision to be tested, try jobs will check out the gerrit
        change to be tested.
        """
        self.prepare_git()
        with self.m.step.nest("Prepare source"):
            self.m.file.ensure_directory("Ensure builder_cache exists", self.builder_cache)
            with self.m.context(cwd=self.builder_cache):
                gclient_config = self.m.gclient.make_config()
                s = gclient_config.solutions.add()
                s.url = CROSVM_REPO_URL
                s.name = "crosvm"
                gclient_config.got_revision_mapping[s.name] = "got_revision"
                # By default bot_update will soft reset to 'main' after patching in gerrit revisions
                # for try jobs. We do not want to do that as it will prevent us from testing infra
                # jobs like the merge bot, which does not work with a dirty working directory.
                self.m.bot_update.ensure_checkout(
                    gclient_config=gclient_config, gerrit_no_reset=True
                )

                self.__sync_submodules()

                # gclient will use a reference to a cache directory, which won't be available inside
                # the dev container. Repack will make sure all objects are copied into the current
                # repo.
                with self.m.context(cwd=self.source_dir):
                    self.m.step("Repack repository", ["git", "repack", "-a"])

    def __prepare_container(self):
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
                self.m.step(
                    "Force pull dev_container",
                    [
                        "vpython3",
                        self.source_dir.join("tools/dev_container"),
                        "--pull",
                    ],
                )
                self.m.crosvm.step_in_container("Ensure dev container exists", ["true"])

    def __set_git_config(self, prop, value):
        self.m.step(
            "Set git config: %s" % prop,
            ["git", "config", "--global", prop, value],
        )
