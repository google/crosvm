# Copyright 2022 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# The lists/dictionaries in this file let vendors build/link custom libraries

# paths are relative to platform/crosvm dir
DLLS = []

VS_PROJECTS_FROM_CMAKE = {
    # Format of this dictionary is:
    # "dll_path": { "src": "source_code_path", "cmake_flags": "flags", "cmake_flags_for_features": {"feature": "flags"}}
}

WINDOWS_BUILDABLE_DLLS = {
    # Format of this dictionary is:
    # dll_path: (proj_path/sln_path, build_flags)
}

BINARIES = [
    # List of binaries to include.
]
