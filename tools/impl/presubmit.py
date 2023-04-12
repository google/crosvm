#!/usr/bin/env python3
# Copyright 2022 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import os
import subprocess
import sys
import traceback
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime, timedelta
from fnmatch import fnmatch
from pathlib import Path
from time import sleep
from typing import Callable, List, NamedTuple, Optional, Union

from impl.common import (
    Command,
    all_tracked_files,
    cmd,
    console,
    rich,
    strip_ansi_escape_sequences,
    verbose,
)

git = cmd("git")


@dataclass
class CheckContext(object):
    "Information passed to each check when it's called."

    # Whether or not --fix was set and checks should attempt to fix problems they encounter.
    fix: bool

    # Use rust nightly version for rust checks
    nightly_fmt: bool

    # All files that this check should cover (e.g. all python files on a python check).
    all_files: List[Path]

    # Those files of all_files that were modified locally.
    modified_files: List[Path]

    # Files that do not exist upstream and have been added locally.
    new_files: List[Path]


class Check(NamedTuple):
    "Metadata for each check, definining on which files it should run."

    # Function to call for this check
    check_function: Callable[[CheckContext], Union[Command, None, List[Command]]]

    custom_name: Optional[str] = None

    # List of globs that this check should be triggered on
    files: List[str] = []

    python_tools: bool = False

    # List of globs to exclude from this check
    exclude: List[str] = []

    # Whether or not this check can fix issues.
    can_fix: bool = False

    # Which groups this check belongs to.
    groups: List[str] = []

    # Priority tasks usually take lonkger and are started first, and will show preliminary output.
    priority: bool = False

    @property
    def name(self):
        if self.custom_name:
            return self.custom_name
        name = self.check_function.__name__
        if name.startswith("check_"):
            return name[len("check_") :]
        return name

    @property
    def doc(self):
        if self.check_function.__doc__:
            return self.check_function.__doc__.strip()
        else:
            return None


class Group(NamedTuple):
    "Metadata for a group of checks"

    name: str

    doc: str

    checks: List[str]


def list_file_diff():
    """
    Lists files there were modified compared to the upstream branch.

    Falls back to all files tracked by git if there is no upstream branch.
    """
    upstream = git("rev-parse @{u}").stdout(check=False)
    if upstream:
        for line in git("diff --name-status", upstream).lines():
            parts = line.split("\t", 1)
            file = Path(parts[1].strip())
            if file.is_file():
                yield (parts[0].strip(), file)
    else:
        print("WARNING: Not tracking a branch. Checking all files.")
        for file in all_tracked_files():
            yield ("M", file)


def should_run_check_on_file(check: Check, file: Path):
    "Returns true if `file` should be run on `check`."

    # Skip third_party except vmm_vhost.
    if str(file).startswith("third_party") and not str(file).startswith("third_party/vmm_vhost"):
        return False

    # Skip excluded files
    for glob in check.exclude:
        if fnmatch(str(file), glob):
            return False

    # Match python tools (no file-extension, but with a python shebang line)
    if check.python_tools:
        if fnmatch(str(file), "tools/*") and file.suffix == "" and file.is_file():
            if file.open(errors="ignore").read(32).startswith("#!/usr/bin/env python3"):
                return True

    # If no constraint is specified, match all files.
    if not check.files and not check.python_tools:
        return True

    # Otherwise, match only those specified by `files`.
    for glob in check.files:
        if fnmatch(str(file), glob):
            return True

    return False


class Task(object):
    """
    Represents a task that needs to be executed to perform a `Check`.

    The task can be executed via `Task.execute`, which will update the state variables with
    status and progress information.

    This information can then be rendered from a separate thread via `Task.status_widget()`
    """

    def __init__(self, title: str, commands: List[Command], priority: bool):
        "Display title."
        self.title = title
        "Commands to execute."
        self.commands = commands
        "Task is a priority check."
        self.priority = priority
        "List of log lines (stdout+stderr) produced by the task."
        self.log_lines: List[str] = []
        "Task was compleded, but may or not have been successful."
        self.done = False
        "True if the task completed successfully."
        self.success = False
        "Time the task was started."
        self.start_time = datetime.min
        "Duration the task took to execute. Only filled after completion."
        self.duration = timedelta.max
        "Spinner object for status_widget UI."
        self.spinner = rich.spinner.Spinner("point", title)

    def status_widget(self):
        "Returns a rich console object showing the currrent status of the task."
        duration = self.duration if self.done else datetime.now() - self.start_time
        title = f"[{duration.total_seconds():6.2f}s] [bold]{self.title}[/bold]"

        if self.done:
            status: str = "[green]OK [/green]" if self.success else "[red]ERR[/red]"
            title_widget = rich.text.Text.from_markup(f"{status} {title}")
        else:
            self.spinner.text = rich.text.Text.from_markup(title)
            title_widget = self.spinner

        if not self.priority:
            return title_widget

        last_lines = [
            self.log_lines[-3] if len(self.log_lines) >= 3 else "",
            self.log_lines[-2] if len(self.log_lines) >= 2 else "",
            self.log_lines[-1] if len(self.log_lines) >= 1 else "",
        ]

        return rich.console.Group(
            *(
                # Print last log lines without it's original colors
                rich.text.Text(
                    "│ " + strip_ansi_escape_sequences(log_line),
                    style="light_slate_grey",
                    overflow="ellipsis",
                    no_wrap=True,
                )
                for log_line in last_lines
            ),
            rich.text.Text("└ ", end="", style="light_slate_grey"),
            title_widget,
            rich.text.Text(),
        )

    def execute(self):
        "Execute the task while updating the status variables."
        try:
            self.start_time = datetime.now()
            success = True
            for command in self.commands:
                if verbose():
                    self.log_lines.append(f"$ {command}")
                process = command.popen(stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
                assert process.stdout
                for line in iter(process.stdout.readline, ""):
                    self.log_lines.append(line.strip())
                if process.wait() != 0:
                    success = False
            self.duration = datetime.now() - self.start_time
            self.success = success
            self.done = True
        except Exception:
            self.log_lines.append(traceback.format_exc())


def print_logs(tasks: List[Task]):
    "Prints logs of all failed or unfinished tasks."
    for task in tasks:
        if not task.done:
            print()
            console.rule(f"{task.title} did not finish", style="yellow")
            for line in task.log_lines:
                print(line)
            if not task.log_lines:
                print(f"{task.title} did not output any logs")
    for task in tasks:
        if task.done and not task.success:
            console.rule(f"{task.title} failed", style="red")
            for line in task.log_lines:
                print(line)
            if not task.log_lines:
                print(f"{task.title} did not output any logs")


def print_summary(tasks: List[Task]):
    "Prints a summary of all task results."
    console.rule("Summary")
    tasks.sort(key=lambda t: t.duration)
    for task in tasks:
        title = f"[{task.duration.total_seconds():6.2f}s] [bold]{task.title}[/bold]"
        status: str = "[green]OK [/green]" if task.success else "[red]ERR[/red]"
        console.print(f"{status} {title}")


def execute_tasks_parallel(tasks: List[Task]):
    "Executes the list of tasks in parallel, while rendering live status updates."
    with ThreadPoolExecutor() as executor:
        try:
            # Since tasks are executed in subprocesses, we can use a thread pool to parallelize
            # despite the GIL.
            task_futures = [executor.submit(lambda: t.execute()) for t in tasks]

            # Render task updates while they are executing in the background.
            with rich.live.Live(refresh_per_second=30) as live:
                while True:
                    live.update(
                        rich.console.Group(
                            *(t.status_widget() for t in tasks),
                            rich.text.Text(),
                            rich.text.Text.from_markup(
                                "[green]Tip:[/green] Press CTRL-C to abort execution and see all logs."
                            ),
                        )
                    )
                    if all(future.done() for future in task_futures):
                        break
                    sleep(0.1)
        except KeyboardInterrupt:
            print_logs(tasks)
            # Force exit to skip waiting for the executor to shutdown. This will kill all
            # running subprocesses.
            os._exit(1)  # type: ignore

    # Render error logs and summary after execution
    print_logs(tasks)
    print_summary(tasks)

    if any(not t.success for t in tasks):
        raise Exception("Some checks failed")


def execute_tasks_serial(tasks: List[Task]):
    "Executes the list of tasks one-by-one"
    for task in tasks:
        console.rule(task.title)
        for command in task.commands:
            command.fg()
        console.print()


def generate_plan(
    checks_list: List[Check],
    fix: bool,
    run_on_all_files: bool,
    nightly_fmt: bool,
):
    "Generates a list of `Task`s to execute the checks provided in `checks_list`"
    all_files = [*all_tracked_files()]
    file_diff = [*list_file_diff()]
    new_files = [f for (s, f) in file_diff if s == "A"]
    if run_on_all_files:
        modified_files = all_files
    else:
        modified_files = [f for (s, f) in file_diff if s in ("M", "A")]

    tasks: List[Task] = []
    unsupported_checks: List[str] = []
    for check in checks_list:
        if fix and not check.can_fix:
            continue
        context = CheckContext(
            fix=fix,
            nightly_fmt=nightly_fmt,
            all_files=[f for f in all_files if should_run_check_on_file(check, f)],
            modified_files=[f for f in modified_files if should_run_check_on_file(check, f)],
            new_files=[f for f in new_files if should_run_check_on_file(check, f)],
        )
        if context.modified_files:
            commands = check.check_function(context)
            if commands is None:
                unsupported_checks.append(check.name)
                continue
            if not isinstance(commands, list):
                commands = [commands]
            title = f"fixing {check.name}" if fix else check.name
            tasks.append(Task(title, commands, check.priority))

    if unsupported_checks:
        console.print("[yellow]Warning:[/yellow] The following checks cannot be run:")
        for unsupported_check in unsupported_checks:
            console.print(f" - {unsupported_check}")
        console.print()
        console.print("[green]Tip:[/green] Use the dev container to run presubmits:")
        console.print()
        console.print(
            f"  [blue] $ tools/dev_container tools/presubmit {' '.join(sys.argv[1:])}[/blue]"
        )
        console.print()

    if not os.access("/dev/kvm", os.W_OK):
        console.print("[yellow]Warning:[/yellow] Cannot access KVM. Integration tests are not run.")

    # Sort so that priority tasks are launched (and rendered) first
    tasks.sort(key=lambda t: (t.priority, t.title), reverse=True)
    return tasks


def run_checks(
    checks_list: List[Check],
    fix: bool,
    run_on_all_files: bool,
    nightly_fmt: bool,
    parallel: bool,
):
    """
    Runs all checks in checks_list.

    Arguments:
        fix: Run fixes instead of checks on `Check`s that support it.
        run_on_all_files: Do not use git delta, but run on all files.
        nightly_fmt: Use nightly version of rust tooling.
        parallel: Run tasks in parallel.
    """
    tasks = generate_plan(checks_list, fix, run_on_all_files, nightly_fmt)
    if len(tasks) == 1:
        parallel = False

    if parallel:
        execute_tasks_parallel(list(tasks))
    else:
        execute_tasks_serial(list(tasks))
