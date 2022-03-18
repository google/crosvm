#!/usr/bin/env python3
# Copyright 2022 The Chromium OS Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""
Provides helpers for writing shell-like scripts in Python.

It provides tools to execute commands with similar flexibility to shell scripts and simplifies
command line arguments using `argh` and provides common flags (e.g. -v and -vv) for all of
our command line tools.

Refer to the scripts in ./tools for example usage.
"""
from __future__ import annotations

import argparse
import contextlib
import csv
import os
import re
import shutil
import subprocess
import sys
import traceback
from io import StringIO
from multiprocessing.pool import ThreadPool
from pathlib import Path
from subprocess import DEVNULL, PIPE, STDOUT  # type: ignore
from typing import Any, Callable, Iterable, NamedTuple, Optional, TypeVar, Union

try:
    import argh  # type: ignore
except ImportError as e:
    print("Missing module:", e)
    print("(Re-)Run ./tools/install-deps to install the required dependencies.")
    sys.exit(1)

"Root directory of crosvm"
CROSVM_ROOT = Path(__file__).parent.parent.parent.resolve()

"Cargo.toml file of crosvm"
CROSVM_TOML = CROSVM_ROOT / "Cargo.toml"

# Ensure that we really found the crosvm root directory
assert 'name = "crosvm"' in CROSVM_TOML.read_text()


PathLike = Union[Path, str]


class CommandResult(NamedTuple):
    """Results of a command execution as returned by Command.run()"""

    stdout: str
    stderr: str
    returncode: int


class Command(object):
    """
    Simplified subprocess handling for shell-like scripts.

    ## Arguments

    Arguments are provided as a list similar to subprocess.run():

    >>> Command('cargo', 'build', '--workspace')
    Command('cargo', 'build', '--workspace')

    In contrast to subprocess.run, all strings are split by whitespaces similar to bash:

    >>> Command('cargo build --workspace', '--features foo')
    Command('cargo', 'build', '--workspace', '--features', 'foo')

    In contrast to bash, globs are *not* evaluated, but can easily be provided using Path:

    >>> Command('ls -l', *Path('.').glob('*.toml'))
    Command('ls', '-l', ...)

    None or False are ignored to make it easy to include conditional arguments:

    >>> all = False
    >>> Command('cargo build', '--workspace' if all else None)
    Command('cargo', 'build')

    Commands can be nested, similar to $() subshells in bash. The sub-commands will be executed
    right away and their output will undergo the usual splitting:

    >>> Command('printf "(%s)"', Command('echo foo bar')).stdout()
    '(foo)(bar)'

    Arguments can be explicitly quoted to prevent splitting, it applies to both sub-commands
    as well as strings:

    >>> Command('printf "(%s)"', quoted(Command('echo foo bar'))).stdout()
    '(foo bar)'

    Commands can also be piped into one another:

    >>> wc = Command('wc')
    >>> Command('echo "abcd"').pipe(wc('-c')).stdout()
    '5'

    ## Executing

    Once built, commands can be executed using `Command.fg()`, to run the command in the
    foreground, visible to the user, or `Command.stdout()` to capture the stdout.

    By default, any non-zero exit code will trigger an Exception and stderr is always directed to
    the user.

    More complex use-cases are supported with the `Command.run()` or `Command.stream()` methods.
    A Command instance can also be passed to the subprocess.run() for any use-cases unsupported by
    this API.
    """

    def __init__(self, *args: Any, stdin_cmd: Optional[Command] = None):
        self.args = Command.__parse_cmd(args)
        self.stdin_cmd = stdin_cmd
        if len(self.args) > 0:
            executable = self.args[0]
            path = shutil.which(executable)
            if not path:
                raise ValueError(f'Required program "{executable}" cannot be found in PATH.')
            elif very_verbose():
                print(f"Using {executable}: {path}")
            self.executable = Path(path)

    ### High level execution API

    def fg(
        self,
        quiet: bool = False,
        check: bool = True,
    ) -> int:
        """
        Runs a program in the foreground with output streamed to the user.

        >>> Command('true').fg()
        0

        Non-zero exit codes will trigger an Exception
        >>> Command('false').fg()
        Traceback (most recent call last):
        ...
        subprocess.CalledProcessError: Command 'false' returned non-zero exit status 1.

        But can be disabled:

        >>> Command('false').fg(check=False)
        1

        Arguments:
            quiet: Do not show stdout unless the program failed.
            check: Raise an exception if the program returned an error code.

        Returns: The return code of the program.
        """
        self.__debug_print()
        if quiet:
            result = subprocess.run(
                self.args,
                stdout=PIPE,
                stderr=STDOUT,
                stdin=self.__stdin_stream(),
                text=True,
            )
        else:
            result = subprocess.run(
                self.args,
                stdin=self.__stdin_stream(),
            )

        if result.returncode != 0:
            if quiet and result.stdout:
                print(result.stdout)
            if check:
                raise subprocess.CalledProcessError(result.returncode, str(self), result.stdout)
        return result.returncode

    def stdout(self):
        """
        Runs a program and returns stdout. Stderr is still directed to the user.
        """
        return self.run(stderr=None).stdout.strip()

    def write_to(self, filename: Path):
        """
        Writes all program output (stdout and stderr) to the provided file.
        """
        with open(filename, "w") as file:
            file.write(self.run(stderr=STDOUT).stdout)

    def append_to(self, filename: Path):
        """
        Appends all program output (stdout and stderr) to the provided file.
        """
        with open(filename, "a") as file:
            file.write(self.run(stderr=STDOUT).stdout)

    def pipe(self, *args: Any):
        """
        Pipes the output of this command into another process.

        The target can either be another Command or the argument list to build a new command.
        """
        if len(args) == 1 and isinstance(args[0], Command):
            cmd = Command(stdin_cmd=self)
            cmd.args = args[0].args
            return cmd
        else:
            return Command(*args, stdin_cmd=self)

    ### Lower level execution API

    def run(self, check: bool = True, stderr: Optional[int] = PIPE) -> CommandResult:
        """
        Runs a program with stdout, stderr and error code returned.

        >>> Command('echo', 'Foo').run()
        CommandResult(stdout='Foo\\n', stderr='', returncode=0)

        Non-zero exit codes will trigger an Exception by default.

        Arguments:
            check: Raise an exception if the program returned an error code.

        Returns: CommandResult(stdout, stderr, returncode)
        """
        self.__debug_print()
        result = subprocess.run(
            self.args,
            stdout=subprocess.PIPE,
            stderr=stderr,
            stdin=self.__stdin_stream(),
            check=check,
            text=True,
        )
        return CommandResult(result.stdout, result.stderr, result.returncode)

    def stream(self, stderr: Optional[int] = PIPE) -> subprocess.Popen[str]:
        """
        Runs a program and returns the Popen object of the running process.
        """
        self.__debug_print()
        return subprocess.Popen(
            self.args,
            stdout=subprocess.PIPE,
            stderr=stderr,
            stdin=self.__stdin_stream(),
            text=True,
        )

    def foreach(self, arguments: Iterable[Any], batch_size: int = 1):
        """
        Yields a new command for each entry in `arguments`.

        The argument is appended to each command and is intended to be used in
        conjunction with `parallel()` to execute a command on a list of arguments in
        parallel.

        >>> parallel(*cmd('echo').foreach((1, 2, 3))).stdout()
        ['1', '2', '3']

        Arguments can also be batched by setting batch_size > 1, which will append multiple
        arguments to each command.

        >>> parallel(*cmd('echo').foreach((1, 2, 3), batch_size=2)).stdout()
        ['1 2', '3']

        """
        for batch in batched(arguments, batch_size):
            yield self(*batch)

    def __call__(self, *args: Any):
        """Returns a new Command with added arguments.

        >>> cargo = Command('cargo')
        >>> cargo('clippy')
        Command('cargo', 'clippy')
        """
        cmd = Command()
        cmd.args = [*self.args, *Command.__parse_cmd(args)]
        return cmd

    def __iter__(self):
        """Allows a `Command` to be treated like a list of arguments for subprocess.run()."""
        return iter(self.args)

    def __str__(self):
        def fmt_arg(arg: str):
            # Quote arguments containing spaces.
            if re.search(r"\s", arg):
                return f'"{arg}"'
            return arg

        stdin = ""
        if self.stdin_cmd:
            stdin = str(self.stdin_cmd) + " | "
        return stdin + " ".join(fmt_arg(a) for a in self.args)

    def __repr__(self):
        stdin = ""
        if self.stdin_cmd:
            stdin = ", stdin_cmd=" + repr(self.stdin_cmd)
        return f"Command({', '.join(repr(a) for a in self.args)}{stdin})"

    ### Private utilities

    def __stdin_stream(self):
        if self.stdin_cmd:
            return self.stdin_cmd.stream().stdout
        return None

    def __debug_print(self):
        if verbose():
            print("$", repr(self) if very_verbose() else str(self))

    @staticmethod
    def __shell_like_split(value: str):
        """Splits a string by spaces, accounting for escape characters and quoting."""
        # Re-use csv parses to split by spaces and new lines, while accounting for quoting.
        for line in csv.reader(StringIO(value), delimiter=" ", quotechar='"'):
            for arg in line:
                if arg:
                    yield arg

    @staticmethod
    def __parse_cmd(args: Iterable[Any]) -> list[str]:
        """Parses command line arguments for Command."""
        res = [parsed for arg in args for parsed in Command.__parse_cmd_args(arg)]
        return res

    @staticmethod
    def __parse_cmd_args(arg: Any) -> list[str]:
        """Parses a mixed type command line argument into a list of strings."""
        if isinstance(arg, Path):
            return [str(arg)]
        elif isinstance(arg, QuotedString):
            return [arg.value]
        elif isinstance(arg, Command):
            return [*Command.__shell_like_split(arg.stdout())]
        elif arg is None or arg is False:
            return []
        else:
            return [*Command.__shell_like_split(str(arg))]


class ParallelCommands(object):
    """
    Allows commands to be run in parallel.

    >>> parallel(cmd('true'), cmd('false')).fg(check=False)
    [0, 1]

    >>> parallel(cmd('echo a'), cmd('echo b')).stdout()
    ['a', 'b']
    """

    def __init__(self, *commands: Command):
        self.commands = commands

    def fg(self, quiet: bool = True, check: bool = True):
        with ThreadPool(os.cpu_count()) as pool:
            return pool.map(lambda command: command.fg(quiet=quiet, check=check), self.commands)

    def stdout(self):
        with ThreadPool(os.cpu_count()) as pool:
            return pool.map(lambda command: command.stdout(), self.commands)


@contextlib.contextmanager
def cwd_context(path: PathLike):
    """Context for temporarily changing the cwd.

    >>> with cwd('/tmp'):
    ...     os.getcwd()
    '/tmp'

    """
    cwd = os.getcwd()
    try:
        chdir(path)
        yield
    finally:
        chdir(cwd)


def chdir(path: PathLike):
    if very_verbose():
        print("cd", path)
    os.chdir(path)


class QuotedString(object):
    """
    Prevents the provided string from being split.

    Commands will be executed and their stdout is quoted.
    """

    def __init__(self, value: Any):
        if isinstance(value, Command):
            self.value = value.stdout()
        else:
            self.value = str(value)

    def __str__(self):
        return f'"{self.value}"'


T = TypeVar("T")


def batched(source: Iterable[T], batch_size: int) -> Iterable[list[T]]:
    """
    Returns an iterator over batches of elements from source_list.

    >>> list(batched([1, 2, 3, 4, 5], batch_size=2))
    [[1, 2], [3, 4], [5]]
    """
    source_list = list(source)
    for index in range(0, len(source_list), batch_size):
        yield source_list[index : min(index + batch_size, len(source_list))]


# Shorthands
quoted = QuotedString
cmd = Command
cwd = cwd_context
parallel = ParallelCommands


def run_main(main_fn: Callable[..., Any]):
    """
    Runs the main function using argh to translate command line arguments into function arguments.
    """
    try:
        # Add global verbose arguments
        parser = argparse.ArgumentParser()
        __add_verbose_args(parser)

        # Register main method as argh command
        argh.set_default_command(parser, main_fn)  # type: ignore

        # Call main method
        argh.dispatch(parser)  # type: ignore
    except Exception as e:
        if verbose():
            traceback.print_exc()
        else:
            print(e)
        sys.exit(1)


def verbose():
    return very_verbose() or "-v" in sys.argv or "--verbose" in sys.argv


def very_verbose():
    return "-vv" in sys.argv or "--very-verbose" in sys.argv


def __add_verbose_args(parser: argparse.ArgumentParser):
    # This just serves as documentation to argparse. The verbose variables are directly
    # parsed from argv above to ensure they are accessible early.
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        default=False,
        help="Print debug output",
    )
    parser.add_argument(
        "--very-verbose",
        "-vv",
        action="store_true",
        default=False,
        help="Print more debug output",
    )


if __name__ == "__main__":
    import doctest

    doctest.testmod(optionflags=doctest.ELLIPSIS)
