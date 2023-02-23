#!/usr/bin/env python3
# Copyright 2023 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""
Run first before executing any python developer tool to ensure the environment is set up correctly.
"""

import sys
from typing import List


def ensure_packages_exist(*packages: str):
    """
    Exits if one of the listed packages does not exist.

    TODO(b/270708102): Automate venv installation of the packages
    """
    missing_packages: List[str] = []

    for package in packages:
        try:
            __import__(package)
        except ImportError:
            missing_packages.append(package)

    if missing_packages:
        debian_packages = [f"python3-{p}" for p in missing_packages]
        package_list = " ".join(debian_packages)
        print("Missing python dependencies. Please re-run ./tools/install-deps")
        print(f"Or `sudo apt install {package_list}`")
        sys.exit(1)


# Note: These packages need to be provided as CIPD packages for vpython in Luci CI.
# See tools/.vpython3 for how to add them.
ensure_packages_exist("argh", "rich")
