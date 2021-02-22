#!/usr/bin/env python3
# Copyright 2021 The Chromium OS Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
#
# Test runner for crosvm:
# - Selects which tests to run based on local environment
# - Can run some tests single-threaded
# - Can run some tests using the VM provided by the builders.
# - Can generate junit xml files for integration with sponge
#
# The crates and feature to test are configured in ./run_tests

from typing import Iterable, List, Dict, Set, Optional, Union
import argparse
import enum
import os
import platform
import subprocess
import sys
import re
import xml.etree.ElementTree as ET
import pathlib

# Print debug info. Overriden by -v or -vv
VERBOSE = False
VERY_VERBOSE = False

# Runs tests using the exec_file wrapper, which will run the test inside the
# builders built-in VM.
VM_TEST_RUNNER = (
    os.path.abspath("./ci/vm_tools/exec_binary_in_vm") + " --no-sync"
)

# Runs tests using QEMU user-space emulation.
QEMU_TEST_RUNNER = (
    "qemu-aarch64-static -E LD_LIBRARY_PATH=/workspace/scratch/lib"
)

# Kill a test after 5 minutes to prevent frozen tests from running too long.
TEST_TIMEOUT_SECS = 300


class Requirements(enum.Enum):
    # Test can only be built for aarch64.
    AARCH64 = "aarch64"

    # Test can only be built for x86_64.
    X86_64 = "x86_64"

    # Requires ChromeOS build environment.
    CROS_BUILD = "cros_build"

    # Test is disabled explicitly.
    DISABLED = "disabled"

    # Test needs to be executed with expanded privileges for device access and
    # will be run inside a VM.
    PRIVILEGED = "privileged"

    # Test needs to run single-threaded
    SINGLE_THREADED = "single_threaded"

    # Separate workspaces that have dev-dependencies cannot be built from the
    # crosvm workspace and need to be built separately.
    # Note: Separate workspaces are built with no features enabled.
    SEPARATE_WORKSPACE = "separate_workspace"

    # Build, but do not run.
    DO_NOT_RUN = "do_not_run"


BUILD_TIME_REQUIREMENTS = [
    Requirements.AARCH64,
    Requirements.X86_64,
    Requirements.CROS_BUILD,
    Requirements.DISABLED,
]


class CrateInfo(object):
    """Informaton about whether a crate can be built or run on this host."""

    def __init__(
        self,
        name: str,
        requirements: Set[Requirements],
        capabilities: Set[Requirements],
    ):
        self.name = name
        self.requirements = requirements
        self.single_threaded = Requirements.SINGLE_THREADED in requirements
        self.needs_privilege = Requirements.PRIVILEGED in requirements

        build_reqs = requirements.intersection(BUILD_TIME_REQUIREMENTS)
        self.can_build = all(req in capabilities for req in build_reqs)

        self.can_run = (
            self.can_build
            and (
                not self.needs_privilege
                or Requirements.PRIVILEGED in capabilities
            )
            and not Requirements.DO_NOT_RUN in self.requirements
        )

    def __repr__(self):
        return f"{self.name} {self.requirements}"


def target_arch():
    """Returns architecture cargo is set up to build for."""
    if "CARGO_BUILD_TARGET" in os.environ:
        target = os.environ["CARGO_BUILD_TARGET"]
        return target.split("-")[0]
    else:
        return platform.machine()


def get_test_runner_env(use_vm: bool):
    """Sets the target.*.runner cargo setting to use the correct test runner."""
    env = os.environ.copy()
    key = f"CARGO_TARGET_{target_arch().upper()}_UNKNOWN_LINUX_GNU_RUNNER"
    if use_vm:
        env[key] = VM_TEST_RUNNER
    else:
        if target_arch() == "aarch64":
            env[key] = QEMU_TEST_RUNNER
        else:
            if key in env:
                del env[key]
    return env


class TestResult(enum.Enum):
    PASS = "Pass"
    FAIL = "Fail"
    SKIP = "Skip"
    UNKNOWN = "Unknown"


class CrateResults(object):
    """Container for results of a single cargo test call."""

    def __init__(self, crate_name: str, success: bool, cargo_test_log: str):
        self.crate_name = crate_name
        self.success = success
        self.cargo_test_log = cargo_test_log

        # Parse "test test_name... ok|ignored|FAILED" messages from cargo log.
        test_regex = re.compile(r"^test ([\w\/_\-\.:() ]+) \.\.\. (\w+)$")
        self.tests: Dict[str, TestResult] = {}
        for line in cargo_test_log.split(os.linesep):
            match = test_regex.match(line)
            if match:
                name = match.group(1)
                result = match.group(2)
                if result == "ok":
                    self.tests[name] = TestResult.PASS
                elif result == "ignored":
                    self.tests[name] = TestResult.SKIP
                elif result == "FAILED":
                    self.tests[name] = TestResult.FAIL
                else:
                    self.tests[name] = TestResult.UNKNOWN

    def total(self):
        return len(self.tests)

    def count(self, result: TestResult):
        return sum(r == result for r in self.tests.values())

    def to_junit(self):
        testsuite = ET.Element(
            "testsuite",
            {
                "name": self.crate_name,
                "tests": str(self.total()),
                "failures": str(self.count(TestResult.FAIL)),
            },
        )
        for (test, result) in self.tests.items():
            testcase = ET.SubElement(
                testsuite, "testcase", {"name": f"{self.crate_name} - ${test}"}
            )
            if result == TestResult.SKIP:
                ET.SubElement(
                    testcase, "skipped", {"message": "Disabled in rust code."}
                )
            else:
                testcase.set("status", "run")
                if result == TestResult.FAIL:
                    failure = ET.SubElement(
                        testcase, "failure", {"message": "Test failed."}
                    )
                    failure.text = self.cargo_test_log

        return testsuite


class RunResults(object):
    """Container for results of the whole test run."""

    def __init__(self, crate_results: Iterable[CrateResults]):
        self.crate_results = list(crate_results)
        self.success: bool = (
            len(self.crate_results) > 0 and self.count(TestResult.FAIL) == 0
        )

    def total(self):
        return sum(r.total() for r in self.crate_results)

    def count(self, result: TestResult):
        return sum(r.count(result) for r in self.crate_results)

    def to_junit(self):
        testsuites = ET.Element("testsuites", {"name": "Cargo Tests"})
        for crate_result in self.crate_results:
            testsuites.append(crate_result.to_junit())
        return testsuites


def results_summary(results: Union[RunResults, CrateResults]):
    """Returns a concise 'N passed, M failed' summary of `results`"""
    num_pass = results.count(TestResult.PASS)
    num_skip = results.count(TestResult.SKIP)
    num_fail = results.count(TestResult.FAIL)
    msg: List[str] = []
    if num_pass:
        msg.append(f"{num_pass} passed")
    if num_skip:
        msg.append(f"{num_skip} skipped")
    if num_fail:
        msg.append(f"{num_fail} failed")
    return ", ".join(msg)


def cargo_build_process(
    cwd: str = ".", crates: List[CrateInfo] = [], features: Set[str] = set()
):
    """Builds the main crosvm crate."""
    cmd = [
        "cargo",
        "build",
        "--color=never",
        "--no-default-features",
        "--features",
        ",".join(features),
    ]

    for crate in sorted(crate.name for crate in crates):
        cmd += ["-p", crate]

    if VERY_VERBOSE:
        print("CMD", " ".join(cmd))

    process = subprocess.run(
        cmd,
        cwd=cwd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    if process.returncode != 0 or VERBOSE:
        print()
        print(process.stdout)
    return process


def cargo_test_process(
    cwd: str,
    crates: List[CrateInfo] = [],
    features: Set[str] = set(),
    run: bool = True,
    single_threaded: bool = False,
    use_vm: bool = False,
    timeout: Optional[int] = None,
):
    """Creates the subprocess to run `cargo test`."""
    cmd = ["cargo", "test", "--color=never"]
    if not run:
        cmd += ["--no-run"]
    if features:
        cmd += ["--no-default-features", "--features", ",".join(features)]

    # Skip doc tests as these cannot be run in the VM.
    if use_vm:
        cmd += ["--bins", "--tests"]

    for crate in sorted(crate.name for crate in crates):
        cmd += ["-p", crate]

    cmd += ["--", "--color=never"]
    if single_threaded:
        cmd += ["--test-threads=1"]
    env = get_test_runner_env(use_vm)

    if VERY_VERBOSE:
        print("ENV", env)
        print("CMD", " ".join(cmd))

    process = subprocess.run(
        cmd,
        cwd=cwd,
        env=env,
        timeout=timeout,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    if process.returncode != 0 or VERBOSE:
        print()
        print(process.stdout)
    return process


def cargo_build_tests(crates: List[CrateInfo], features: Set[str]):
    """Runs cargo test --no-run to build all listed `crates`."""
    separate_workspace_crates = [
        crate
        for crate in crates
        if Requirements.SEPARATE_WORKSPACE in crate.requirements
    ]
    workspace_crates = [
        crate
        for crate in crates
        if Requirements.SEPARATE_WORKSPACE not in crate.requirements
    ]

    print(
        "Building workspace: ",
        ", ".join(crate.name for crate in workspace_crates),
    )
    build_process = cargo_build_process(
        cwd=".", crates=workspace_crates, features=features
    )
    if build_process.returncode != 0:
        return False
    test_process = cargo_test_process(
        cwd=".", crates=workspace_crates, features=features, run=False
    )
    if test_process.returncode != 0:
        return False

    for crate in separate_workspace_crates:
        print("Building crate:", crate.name)
        build_process = cargo_build_process(cwd=crate.name)
        if build_process.returncode != 0:
            return False
        test_process = cargo_test_process(cwd=crate.name, run=False)
        if test_process.returncode != 0:
            return False
    return True


def cargo_test(
    crates: List[CrateInfo],
    features: Set[str],
    single_threaded: bool = False,
    use_vm: bool = False,
) -> Iterable[CrateResults]:
    """Runs cargo test for all listed `crates`."""
    for crate in crates:
        msg = ["Testing crate", crate.name]
        if use_vm:
            msg.append("in vm")
        if single_threaded:
            msg.append("(single-threaded)")
        if Requirements.SEPARATE_WORKSPACE in crate.requirements:
            msg.append("(separate workspace)")
        sys.stdout.write(f"{' '.join(msg)}... ")
        sys.stdout.flush()

        if Requirements.SEPARATE_WORKSPACE in crate.requirements:
            process = cargo_test_process(
                cwd=crate.name,
                run=True,
                single_threaded=single_threaded,
                use_vm=use_vm,
                timeout=TEST_TIMEOUT_SECS,
            )
        else:
            process = cargo_test_process(
                cwd=".",
                crates=[crate],
                features=features,
                run=True,
                single_threaded=single_threaded,
                use_vm=use_vm,
                timeout=TEST_TIMEOUT_SECS,
            )
        results = CrateResults(
            crate.name, process.returncode == 0, process.stdout
        )
        print(results_summary(results))
        yield results


def execute_batched_by_parallelism(
    crates: List[CrateInfo], features: Set[str], use_vm: bool
) -> Iterable[CrateResults]:
    """Batches tests by single-threaded and parallel, then executes them."""
    run_single = [crate for crate in crates if crate.single_threaded]
    yield from cargo_test(
        run_single, features, single_threaded=True, use_vm=use_vm
    )

    run_parallel = [crate for crate in crates if not crate.single_threaded]
    yield from cargo_test(run_parallel, features, use_vm=use_vm)


def execute_batched_by_privilege(
    crates: List[CrateInfo], features: Set[str], use_vm: bool
) -> Iterable[CrateResults]:
    """
    Batches tests by whether or not a test needs privileged access to run.

    Non-privileged tests are run first. Privileged tests are executed in
    a VM if use_vm is set.
    """
    build_crates = [crate for crate in crates if crate.can_build]
    if not cargo_build_tests(build_crates, features):
        return []

    simple_crates = [
        crate for crate in crates if crate.can_run and not crate.needs_privilege
    ]
    yield from execute_batched_by_parallelism(
        simple_crates, features, use_vm=False
    )

    privileged_crates = [
        crate for crate in crates if crate.can_run and crate.needs_privilege
    ]
    if privileged_crates:
        if use_vm:
            subprocess.run("./ci/vm_tools/sync_deps", check=True)
            yield from execute_batched_by_parallelism(
                privileged_crates, features, use_vm=True
            )
        else:
            yield from execute_batched_by_parallelism(
                privileged_crates, features, use_vm=False
            )


def results_report(
    feature_requirements: Dict[str, List[Requirements]],
    crates: List[CrateInfo],
    features: Set[str],
    run_results: RunResults,
):
    """Prints a summary report of all test results."""
    print()

    if len(run_results.crate_results) == 0:
        print("Could not build tests.")
        return

    crates_not_built = [crate.name for crate in crates if not crate.can_build]
    print(f"Crates not built: {', '.join(crates_not_built)}")

    crates_not_run = [
        crate.name for crate in crates if crate.can_build and not crate.can_run
    ]
    print(f"Crates not tested: {', '.join(crates_not_run)}")

    disabled_features: Set[str] = set(feature_requirements.keys()).difference(
        features
    )
    print(f"Disabled features: {', '.join(disabled_features)}")

    print()
    if not run_results.success:
        for crate_results in run_results.crate_results:
            if crate_results.success:
                continue
            print(f"Test failures in {crate_results.crate_name}:")
            for (test, result) in crate_results.tests.items():
                if result == TestResult.FAIL:
                    print(f"  {test}")
        print()
        print("Some tests failed:", results_summary(run_results))
    else:
        print("All tests passed:", results_summary(run_results))


def execute_tests(
    crate_requirements: Dict[str, List[Requirements]],
    feature_requirements: Dict[str, List[Requirements]],
    capabilities: Set[Requirements],
    use_vm: bool,
    junit_file: Optional[str] = None,
):
    print("Capabilities:", ", ".join(cap.value for cap in capabilities))

    # Select all features where capabilities meet the requirements
    features = set(
        feature
        for (feature, requirements) in feature_requirements.items()
        if all(r in capabilities for r in requirements)
    )

    # Disable sandboxing for tests until our builders are set up to run with
    # sandboxing.
    features.add("default-no-sandbox")
    print("Features:", ", ".join(features))

    crates = [
        CrateInfo(crate, set(requirements), capabilities)
        for (crate, requirements) in crate_requirements.items()
    ]
    run_results = RunResults(
        execute_batched_by_privilege(crates, features, use_vm)
    )

    if junit_file:
        pathlib.Path(junit_file).parent.mkdir(parents=True, exist_ok=True)
        ET.ElementTree(run_results.to_junit()).write(junit_file)

    results_report(feature_requirements, crates, features, run_results)
    if not run_results.success:
        exit(-1)


DESCRIPTION = """\
Runs tests for crosvm based on the capabilities of the local host.

This script can be run directly on a worksation to run a limited number of tests
that can be built and run on a standard debian system.

It can also be run via the CI builder: `./ci/builder --vm ./run_tests`. This
will build all tests and runs tests that require special privileges inside the
virtual machine provided by the builder.
"""


def main(
    crate_requirements: Dict[str, List[Requirements]],
    feature_requirements: Dict[str, List[Requirements]],
):
    parser = argparse.ArgumentParser(description=DESCRIPTION)
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        default=False,
        help="Print all test output.",
    )
    parser.add_argument(
        "--very-verbose",
        "-vv",
        action="store_true",
        default=False,
        help="Print debug information and commands executed.",
    )
    parser.add_argument(
        "--run-privileged",
        action="store_true",
        default=False,
        help="Enable tests that requires privileged access to the system.",
    )
    parser.add_argument(
        "--cros-build",
        action="store_true",
        default=False,
        help=(
            "Enables tests that require a ChromeOS build environment. "
            "Can also be set by CROSVM_CROS_BUILD"
        ),
    )
    parser.add_argument(
        "--use-vm",
        action="store_true",
        default=False,
        help=(
            "Enables privileged tests to run in a VM. "
            "Can also be set by CROSVM_USE_VM"
        ),
    )
    parser.add_argument(
        "--require-all",
        action="store_true",
        default=False,
        help="Requires all tests to run, fail if tests would be disabled.",
    )
    parser.add_argument(
        "--junit-file",
        default=None,
        help="Path to file where to store junit xml results",
    )
    args = parser.parse_args()

    global VERBOSE, VERY_VERBOSE
    VERBOSE = args.verbose or args.very_verbose  # type: ignore
    VERY_VERBOSE = args.very_verbose  # type: ignore

    use_vm = os.environ.get("CROSVM_USE_VM") != None or args.use_vm
    cros_build = os.environ.get("CROSVM_CROS_BUILD") != None or args.cros_build

    capabilities = set()
    if target_arch() == "aarch64":
        capabilities.add(Requirements.AARCH64)
    elif target_arch() == "x86_64":
        capabilities.add(Requirements.X86_64)

    if cros_build:
        capabilities.add(Requirements.CROS_BUILD)

    if use_vm:
        if not os.path.exists("/workspace/vm"):
            print("--use-vm can only be used within the ./ci/builder's.")
            exit(1)
        capabilities.add(Requirements.PRIVILEGED)

    if args.run_privileged:
        capabilities.add(Requirements.PRIVILEGED)

    if args.require_all and not Requirements.PRIVILEGED in capabilities:
        print("--require-all needs to be run with --use-vm or --run-privileged")
        exit(1)

    execute_tests(
        crate_requirements,
        feature_requirements,
        capabilities,
        use_vm,
        args.junit_file,
    )
