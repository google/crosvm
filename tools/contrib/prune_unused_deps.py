# Copyright 2026 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""
A tool to automatically detect and remove unused dependencies across the crosvm workspace.

This script leverages `cargo check` with the `unused-crate-dependencies` rustc lint to identify
dependencies that are declared in a `Cargo.toml` but not used in the corresponding crate's source
code.

Note that the `unused-crate-dependencies` lint is a nightly-only feature. Since crosvm
uses the stable toolchain by default, we cannot enable this lint globally in `Cargo.toml` or
`.cargo/config.toml`. Thus, this script explicitly invokes `cargo +nightly check` to run the
analysis on demand.

Because some dependencies are only used on specific platforms (e.g., Windows) or when specific
features are enabled, the script performs a safety check:
If the dependency name appears anywhere in the crate's `.rs` files, it will NOT automatically remove
the dependency, and will instead flag it for manual review (as it may need to be `optional = true`
or moved to a target-specific dependency block).
"""

import subprocess
import json
import re
import os
from pathlib import Path


def get_workspace_packages():
    """
    Retrieves a dictionary mapping crate names to their manifest (Cargo.toml) and source directories.
    Uses `cargo metadata` to get accurate paths for all packages in the workspace.
    """
    result = subprocess.run(
        ["cargo", "metadata", "--format-version", "1", "--no-deps"],
        capture_output=True,
        text=True,
        check=True,
    )
    metadata = json.loads(result.stdout)
    packages = {}
    for pkg in metadata["packages"]:
        manifest_path = Path(pkg["manifest_path"])
        # rustc emits crate names with underscores, so we normalize hyphens to underscores.
        packages[pkg["name"].replace("-", "_")] = {
            "manifest": manifest_path,
            "src_dir": manifest_path.parent,
        }
    return packages


def get_unused_dependencies():
    """
    Cleans the cargo cache and runs a fresh `cargo check` across the workspace with the
    `unused-crate-dependencies` lint enabled.

    Returns a dictionary mapping crate names to a set of unused dependency names.
    """
    print("Running cargo clean to invalidate cache...")
    subprocess.run(["cargo", "clean"])

    print("Running cargo check to collect unused dependencies... (This will take a moment)")
    env = os.environ.copy()
    # Enforce the lint to get warnings for unused crate dependencies.
    env["RUSTFLAGS"] = "-W unused-crate-dependencies"

    # Note: The `unused-crate-dependencies` lint requires a nightly toolchain.
    # Therefore, we explicitly use `cargo +nightly check`.
    # We omit `--all-features` because conflicting features in a large workspace
    # like crosvm can cause the check to crash prematurely before emitting all warnings.
    result = subprocess.run(
        ["cargo", "+nightly", "check", "--workspace"], env=env, capture_output=True, text=True
    )

    unused_deps = {}
    # Regex to match the specific rustc warning format.
    pattern = re.compile(r"warning: extern crate `([^`]+)` is unused in crate `([^`]+)`")

    for line in result.stderr.splitlines():
        match = pattern.search(line)
        if match:
            dep_name = match.group(1)
            crate_name = match.group(2)
            # Ignore self-referential warnings (e.g., a binary not using its own library crate)
            if dep_name.replace("-", "_") == crate_name.replace("-", "_"):
                continue
            unused_deps.setdefault(crate_name, set()).add(dep_name)

    return unused_deps


def is_dep_used_in_source(src_dir: Path, dep_name: str) -> bool:
    """
    Performs a simple text-based search in the crate's Rust source files to check if
    the dependency is mentioned.

    This serves as a safety net to prevent deleting dependencies that are only used behind
    `#[cfg(...)]` blocks that are inactive during the default `cargo check`.
    """
    # Allow matching both underscore and hyphen variations (e.g., async_task vs async-task)
    dep_pattern = dep_name.replace("_", "[-_]")
    pattern = re.compile(rf"\b{dep_pattern}\b")

    for filepath in src_dir.rglob("*.rs"):
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                if pattern.search(f.read()):
                    return True
        except Exception:
            pass
    return False


def remove_dep_from_cargo_toml(manifest_path: Path, dep_name: str) -> bool:
    """
    Removes a dependency declaration from the specified Cargo.toml.
    Returns True if a line was actually removed, False otherwise.
    """
    with open(manifest_path, "r", encoding="utf-8") as f:
        lines = f.readlines()

    new_lines = []
    # Match lines starting with the dependency name (handling both - and _ variations)
    dep_pattern_str = dep_name.replace("_", "[-_]")
    dep_pattern = re.compile(rf"^\s*{dep_pattern_str}\s*=")
    removed = False

    for line in lines:
        if dep_pattern.match(line):
            removed = True
            continue
        new_lines.append(line)

    # Only write back if a line was actually removed
    if removed:
        with open(manifest_path, "w", encoding="utf-8") as f:
            f.writelines(new_lines)
    return removed


def main():
    packages = get_workspace_packages()
    unused_deps = get_unused_dependencies()

    manual_review_needed = []
    auto_fixed = []

    for crate_name, deps in unused_deps.items():
        if crate_name not in packages:
            continue

        pkg_info = packages[crate_name]
        manifest_path = pkg_info["manifest"]
        src_dir = pkg_info["src_dir"]

        for dep in deps:
            # Safety check: Does the dependency name appear anywhere in the source code?
            if is_dep_used_in_source(src_dir, dep):
                manual_review_needed.append((crate_name, dep, manifest_path))
            else:
                auto_fixed.append((crate_name, dep, manifest_path))

    print("\n" + "=" * 60)
    print(" [AUTO-FIX] REMOVING UNUSED DEPENDENCIES")
    print("=" * 60)
    for crate, dep, manifest in auto_fixed:
        if remove_dep_from_cargo_toml(manifest, dep):
            print(f" - Removed '{dep}' from {crate}")

    print("\n" + "=" * 60)
    print(" MANUAL REVIEW REQUIRED (Used in code, maybe feature/OS specific)")
    print("=" * 60)
    for crate, dep, _ in manual_review_needed:
        print(f" - {crate}: {dep}")


if __name__ == "__main__":
    main()
