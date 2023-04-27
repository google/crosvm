#!/usr/bin/env python3
# Copyright 2023 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""
Implements styles for `Command.fg(style=)` that use `rich` terminal UI features.
"""

import subprocess
from typing import List

from .util import ensure_packages_exist

ensure_packages_exist("rich")
import rich
import rich.console
import rich.live
import rich.spinner
import rich.text


class Styles(object):
    "A collection of methods that can be passed to `Command.fg(style=)`"

    @staticmethod
    def live_truncated(num_lines: int = 8):
        "Prints only the last `num_lines` of output while the program is running and successful."

        def output(process: "subprocess.Popen[str]"):
            assert process.stdout
            spinner = rich.spinner.Spinner("dots")
            lines: List[rich.text.Text] = []
            stdout: List[str] = []
            with rich.live.Live(refresh_per_second=30, transient=True) as live:
                for line in iter(process.stdout.readline, ""):
                    stdout.append(line.strip())
                    lines.append(rich.text.Text.from_ansi(line.strip(), no_wrap=True))
                    while len(lines) > num_lines:
                        lines.pop(0)
                    live.update(rich.console.Group(rich.text.Text("…"), *lines, spinner))
            if process.wait() == 0:
                console.print(rich.console.Group(rich.text.Text("…"), *lines))
            else:
                for line in stdout:
                    print(line)

        return output

    @staticmethod
    def quiet_with_progress(title: str):
        "Prints only the last `num_lines` of output while the program is running and successful."

        def output(process: "subprocess.Popen[str]"):
            assert process.stdout
            with rich.live.Live(
                rich.spinner.Spinner("dots", title), refresh_per_second=30, transient=True
            ):
                stdout = process.stdout.read()

            if process.wait() == 0:
                console.print(f"[green]OK[/green] {title}")
            else:
                print(stdout)
                console.print(f"[red]ERR[/red] {title}")

        return output


console = rich.console.Console()
