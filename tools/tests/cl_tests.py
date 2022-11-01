#!/usr/bin/env python3
# Copyright 2022 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import os
from pathlib import Path
import shutil
import sys
import tempfile
import unittest

sys.path.append(os.path.dirname(sys.path[0]))

from impl.common import CROSVM_ROOT, cmd, quoted, TOOLS_ROOT

git = cmd("git")
cl = cmd(f"{TOOLS_ROOT}/cl")


class ClTests(unittest.TestCase):
    test_root: Path

    def setUp(self):
        self.test_root = Path(tempfile.mkdtemp())
        os.chdir(self.test_root)
        git("clone", CROSVM_ROOT, ".").fg(quiet=True)

        # Set up user name (it's not set up in Luci)
        git("config user.name Nobody").fg(quiet=True)
        git("config user.email nobody@chromium.org").fg(quiet=True)

        # Check out a detached head and delete all branches.
        git("checkout -d HEAD").fg(quiet=True)
        branch_list = git("branch").lines()
        for branch in branch_list:
            if not branch.startswith("*"):
                git("branch -D", branch).fg(quiet=True)

        # Set up the origin for testing uploads and rebases.
        git("remote set-url origin https://chromium.googlesource.com/crosvm/crosvm").fg(quiet=True)
        git("fetch -q origin main").fg(quiet=True)
        git("fetch -q origin chromeos").fg(quiet=True)

    def tearDown(self) -> None:
        shutil.rmtree(self.test_root)

    def create_test_commit(self, message: str, branch: str, upstream: str = "origin/main"):
        git("checkout -b", branch, "--track", upstream).fg(quiet=True)
        with Path("Cargo.toml").open("a") as file:
            file.write("# Foo")
        git("commit -a -m", quoted(message)).fg(quiet=True)
        return git("rev-parse HEAD").stdout()

    def test_cl_upload(self):
        sha = self.create_test_commit("Test Commit", "foo")
        expected = f"""\
Uploading to origin/main:
  {sha} Test Commit

Not running: git push origin HEAD:refs/for/main%"""

        self.assertEqual(cl("upload --dry-run").stdout(), expected)

    def test_cl_status(self):
        self.create_test_commit("Test Commit", "foo")
        expected = """\
Branch foo tracking origin/main
  NOT_UPLOADED Test Commit"""

        self.assertEqual(cl("status").stdout(), expected)

    def test_cl_rebase(self):
        self.create_test_commit("Test Commit", "foo", "origin/chromeos")
        cl("rebase").fg()

        # Expect foo-upstream to be tracking `main` and have the same commit
        self.assertEqual(git("rev-parse --abbrev-ref foo-upstream@{u}").stdout(), "origin/main")
        self.assertEqual(
            git("log -1 --format=%s foo").stdout(),
            git("log -1 --format=%s foo-upstream").stdout(),
        )

    def test_cl_rebase_with_existing_branch(self):
        previous_sha = self.create_test_commit("Previous commit", "foo-upstream ")
        self.create_test_commit("Test Commit", "foo", "origin/chromeos")
        message = cl("rebase").stdout()

        # `cl rebase` will overwrite the branch, but we should print the previous sha in case
        # the user needs to recover it.
        self.assertIn(previous_sha, message)

        # Expect foo-upstream to be tracking `main` and have the same commit. The previous commit
        # would be dropped.
        self.assertEqual(git("rev-parse --abbrev-ref foo-upstream@{u}").stdout(), "origin/main")
        self.assertEqual(
            git("log -1 --format=%s foo").stdout(),
            git("log -1 --format=%s foo-upstream").stdout(),
        )

    def test_prune(self):
        self.create_test_commit("Test Commit", "foo")
        git("branch foo-no-commit origin/main").fg()
        cl("prune --force").fg()

        # `foo` has unsubmitted commits, it should still be there.
        self.assertTrue(git("rev-parse foo").success())

        # `foo-no-commit` has no commits, it should have been pruned.
        self.assertFalse(git("rev-parse foo-no-commit").success())


if __name__ == "__main__":
    unittest.main()
