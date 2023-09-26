#!/usr/bin/env python3
# Copyright 2023 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""
Provides helpers for writing shell-like scripts in Python.

It provides tools to execute commands with similar flexibility as shell scripts.
"""

import contextlib
import json
import os
import re
import shlex
import subprocess
import sys
from copy import deepcopy
from math import ceil
from multiprocessing.pool import ThreadPool
from pathlib import Path
from subprocess import DEVNULL, PIPE, STDOUT  # type: ignore
from typing import (
    Any,
    Callable,
    Dict,
    Iterable,
    List,
    NamedTuple,
    Optional,
    TypeVar,
    Union,
)
from .util import verbose, very_verbose, color_enabled

PathLike = Union[Path, str]


# Regex that matches ANSI escape sequences
ANSI_ESCAPE = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")


class CommandResult(NamedTuple):
    """Results of a command execution as returned by Command.run()"""

    stdout: str
    stderr: str
    returncode: int


class Command(object):
    """
    Simplified subprocess handling for shell-like scripts.

    ## Example Usage

    To run a program on behalf of the user:

    >> cmd("cargo build").fg()

    This will run the program with stdio passed to the user. Developer tools usually run a set of
    actions on behalf of the user. These should be executed with fg().

    To make calls in the background to gather information use success/stdout/lines:

    >> cmd("git branch").lines()
    >> cmd("git rev-parse foo").success()

    These will capture all program output. Try to avoid using these to run mutating commands,
    as they will remain hidden to the user even when using --verbose.

    ## Arguments

    Arguments are provided as a list similar to subprocess.run():

    >>> Command('cargo', 'build', '--workspace')
    Command('cargo', 'build', '--workspace')

    In contrast to subprocess.run, all strings are split by whitespaces similar to bash:

    >>> Command('cargo build --workspace', '--features foo')
    Command('cargo', 'build', '--workspace', '--features', 'foo')

    In contrast to bash, globs are *not* evaluated, but can easily be provided using Path:

    >>> Command('ls -l', *Path(CROSVM_ROOT).glob('*.toml'))
    Command('ls', '-l', ...)

    None or False are ignored to make it easy to include conditional arguments:

    >>> all = False
    >>> Command('cargo build', '--workspace' if all else None)
    Command('cargo', 'build')

    ## Nesting

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

    ## Verbosity

    The --verbose flag is intended for users and will show all command lines executed in the
    foreground with fg(), it'll also include output of programs run with fg(quiet=True). Commands
    executed in the background are not shown.

    For script developers, the --very-verbose flag will print full details and output of all
    executed command lines, including those run hidden from the user.
    """

    def __init__(
        self,
        *args: Any,
        stdin_cmd: Optional["Command"] = None,
        env_vars: Dict[str, str] = {},
        cwd: Optional[Path] = None,
    ):
        self.args = Command.__parse_cmd(args)
        self.stdin_cmd = stdin_cmd
        self.env_vars = env_vars
        self.cwd = cwd

    ### Builder API to construct commands

    def with_args(self, *args: Any):
        """Returns a new Command with added arguments.

        >>> cargo = Command('cargo')
        >>> cargo.with_args('clippy')
        Command('cargo', 'clippy')
        """
        cmd = deepcopy(self)
        cmd.args = [*self.args, *Command.__parse_cmd(args)]
        return cmd

    def with_cwd(self, cwd: Optional[Path]):
        """Changes the working directory the command is executed in.

        >>> cargo = Command('pwd')
        >>> cargo.with_cwd('/tmp').stdout()
        '/tmp'
        """
        cmd = deepcopy(self)
        cmd.cwd = cwd
        return cmd

    def __call__(self, *args: Any):
        """Shorthand for Command.with_args"""
        return self.with_args(*args)

    def with_env(self, key: str, value: Optional[str]):
        """
        Returns a command with an added env variable.

        The variable is removed if value is None.
        """
        return self.with_envs({key: value})

    def with_envs(self, envs: Union[Dict[str, Optional[str]], Dict[str, str]]):
        """
        Returns a command with an added env variable.

        The variable is removed if value is None.
        """
        cmd = deepcopy(self)
        for key, value in envs.items():
            if value is not None:
                cmd.env_vars[key] = value
            else:
                if key in cmd.env_vars:
                    del cmd.env_vars[key]
        return cmd

    def with_path_env(self, new_path: str):
        """Returns a command with a path added to the PATH variable."""
        path_var = self.env_vars.get("PATH", os.environ.get("PATH", ""))
        return self.with_env("PATH", f"{path_var}:{new_path}")

    def with_color_arg(
        self,
        always: Optional[str] = None,
        never: Optional[str] = None,
    ):
        """Returns a command with an argument added to pass through enabled/disabled colors."""
        new_cmd = self
        if color_enabled():
            if always:
                new_cmd = new_cmd(always)
        else:
            if never:
                new_cmd = new_cmd(never)
        return new_cmd

    def with_color_env(self, var_name: str):
        """Returns a command with an env var added to pass through enabled/disabled colors."""
        return self.with_env(var_name, "1" if color_enabled() else "0")

    def with_color_flag(self, flag: str = "--color"):
        """Returns a command with an added --color=always/never/auto flag."""
        return self.with_color_arg(always=f"{flag}=always", never=f"{flag}=never")

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

    def pipe(self, *args: Any):
        """
        Pipes the output of this command into another process.

        The target can either be another Command or the argument list to build a new command.
        """
        if len(args) == 1 and isinstance(args[0], Command):
            cmd = Command(stdin_cmd=self)
            cmd.args = args[0].args
            cmd.env_vars = self.env_vars.copy()
            return cmd
        else:
            return Command(*args, stdin_cmd=self, env_vars=self.env_vars)

    ### Executing programs in the foreground

    def run_foreground(
        self,
        quiet: bool = False,
        check: bool = True,
        dry_run: bool = False,
        style: Optional[Callable[["subprocess.Popen[str]"], None]] = None,
    ):
        """
        Runs a program in the foreground with output streamed to the user.

        >>> Command('true').fg()
        0

        Non-zero exit codes will trigger an Exception

        >>> Command('false').fg()
        Traceback (most recent call last):
        ...
        subprocess.CalledProcessError...

        But can be disabled:

        >>> Command('false').fg(check=False)
        1

        Output can be hidden by setting quiet=True:

        >>> Command("echo foo").fg(quiet=True)
        0

        This will hide the programs stdout and stderr unless the program fails.

        More sophisticated means of outputting stdout/err are available via `Styles`:

        >>> Command("echo foo").fg(style=Styles.live_truncated())
        …
        foo
        0

        Will output the results of the command but truncate output after a few lines. See `Styles`
        for more options.

        Arguments:
            quiet: Do not show stdout/stderr unless the program failed.
            check: Raise an exception if the program returned an error code.
            style: A function to present the output of the program. See `Styles`

        Returns: The return code of the program.
        """
        if dry_run:
            print(f"Not running: {self}")
            return 0

        if quiet:

            def quiet_style(process: "subprocess.Popen[str]"):
                "Won't print anything unless the command failed."
                assert process.stdout
                stdout = process.stdout.read()
                if process.wait() != 0:
                    print(stdout, end="")

            style = quiet_style

        if verbose():
            print(f"$ {self}")

        if style is None or verbose():
            return self.__run(stdout=None, stderr=None, check=check).returncode
        else:
            process = self.popen(stdout=PIPE, stderr=STDOUT)
            style(process)
            returncode = process.wait()
            if returncode != 0 and check:
                assert process.stdout
                raise subprocess.CalledProcessError(returncode, process.args)
            return returncode

    def fg(
        self,
        quiet: bool = False,
        check: bool = True,
        dry_run: bool = False,
        style: Optional[Callable[["subprocess.Popen[str]"], None]] = None,
    ):
        """
        Shorthand for Command.run_foreground()
        """
        return self.run_foreground(quiet, check, dry_run, style)

    def write_to(self, filename: Path):
        """
        Writes stdout to the provided file.
        """
        if verbose():
            print(f"$ {self} > {filename}")
        with open(filename, "w") as file:
            file.write(self.__run(stdout=PIPE, stderr=PIPE).stdout)

    def append_to(self, filename: Path):
        """
        Appends stdout to the provided file.
        """
        if verbose():
            print(f"$ {self} >> {filename}")
        with open(filename, "a") as file:
            file.write(self.__run(stdout=PIPE, stderr=PIPE).stdout)

    ### API for executing commands hidden from the user

    def success(self):
        """
        Returns True if the program succeeded (i.e. returned 0).

        The program will not be visible to the user unless --very-verbose is specified.
        """
        if very_verbose():
            print(f"$ {self}")
        return self.__run(stdout=PIPE, stderr=PIPE, check=False).returncode == 0

    def stdout(self, check: bool = True, stderr: int = PIPE):
        """
        Runs a program and returns stdout.

        The program will not be visible to the user unless --very-verbose is specified.
        """
        if very_verbose():
            print(f"$ {self}")
        return self.__run(stdout=PIPE, stderr=stderr, check=check).stdout.strip()

    def json(self, check: bool = True) -> Any:
        """
        Runs a program and returns stdout parsed as json.

        The program will not be visible to the user unless --very-verbose is specified.
        """
        stdout = self.stdout(check=check)
        if stdout:
            return json.loads(stdout)
        else:
            return None

    def lines(self, check: bool = True, stderr: int = PIPE):
        """
        Runs a program and returns stdout line by line.

        The program will not be visible to the user unless --very-verbose is specified.
        """
        return self.stdout(check=check, stderr=stderr).splitlines()

    ### Utilities

    def __str__(self):
        stdin = ""
        if self.stdin_cmd:
            stdin = str(self.stdin_cmd) + " | "
        return stdin + shlex.join(self.args)

    def __repr__(self):
        stdin = ""
        if self.stdin_cmd:
            stdin = ", stdin_cmd=" + repr(self.stdin_cmd)
        return f"Command({', '.join(repr(a) for a in self.args)}{stdin})"

    ### Private implementation details

    def __run(
        self,
        stdout: Optional[int],
        stderr: Optional[int],
        check: bool = True,
    ) -> CommandResult:
        "Run this command in subprocess.run()"
        if very_verbose():
            print(f"cwd: {Path().resolve()}")
            for k, v in self.env_vars.items():
                print(f"env: {k}={v}")
        result = subprocess.run(
            self.args,
            cwd=self.cwd,
            stdout=stdout,
            stderr=stderr,
            stdin=self.__stdin_stream(),
            env={**os.environ, **self.env_vars},
            check=check,
            text=True,
        )
        if very_verbose():
            if result.stdout:
                for line in result.stdout.splitlines():
                    print("stdout:", line)
            if result.stderr:
                for line in result.stderr.splitlines():
                    print("stderr:", line)
            print("returncode:", result.returncode)
        if check and result.returncode != 0:
            raise subprocess.CalledProcessError(result.returncode, str(self), result.stdout)
        return CommandResult(result.stdout, result.stderr, result.returncode)

    def __stdin_stream(self):
        if self.stdin_cmd:
            return self.stdin_cmd.popen(stdout=PIPE, stderr=PIPE).stdout
        return None

    def popen(self, **kwargs: Any) -> "subprocess.Popen[str]":
        """
        Runs a program and returns the Popen object of the running process.
        """
        return subprocess.Popen(
            self.args,
            cwd=self.cwd,
            stdin=self.__stdin_stream(),
            env={**os.environ, **self.env_vars},
            text=True,
            **kwargs,
        )

    @staticmethod
    def __parse_cmd(args: Iterable[Any]) -> List[str]:
        """Parses command line arguments for Command."""
        res = [parsed for arg in args for parsed in Command.__parse_cmd_args(arg)]
        return res

    @staticmethod
    def __parse_cmd_args(arg: Any) -> List[str]:
        """Parses a mixed type command line argument into a list of strings."""

        def escape_backslash_if_necessary(input: str) -> str:
            if os.name == "nt":
                return input.replace("\\", "\\\\")
            else:
                return input

        if isinstance(arg, Path):
            return [escape_backslash_if_necessary(str(arg))]
        elif isinstance(arg, QuotedString):
            return [arg.value]
        elif isinstance(arg, Command):
            return [*shlex.split(escape_backslash_if_necessary(arg.stdout()))]
        elif arg is None or arg is False:
            return []
        else:
            return [*shlex.split(escape_backslash_if_necessary(str(arg)))]


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

    def fg(self, quiet: bool = False, check: bool = True):
        with ThreadPool(1 if very_verbose() else os.cpu_count()) as pool:
            return pool.map(lambda command: command.fg(quiet=quiet, check=check), self.commands)

    def stdout(self):
        with ThreadPool(1 if very_verbose() else os.cpu_count()) as pool:
            return pool.map(lambda command: command.stdout(), self.commands)

    def success(self):
        results = self.fg(check=False, quiet=True)
        return all(result == 0 for result in results)


class Remote(object):
    """
    Wrapper around the cmd() API and allow execution of commands via SSH."
    """

    def __init__(self, host: str, opts: Dict[str, str]):
        self.host = host
        ssh_opts = [f"-o{k}={v}" for k, v in opts.items()]
        self.ssh_cmd = cmd("ssh", host, "-T", *ssh_opts)
        self.scp_cmd = cmd("scp", *ssh_opts)

    def ssh(self, cmd: Command, remote_cwd: Optional[Path] = None):
        # Use huponexit to ensure the process is killed if the connection is lost.
        # Use shlex to properly quote the command.
        wrapped_cmd = f"bash -O huponexit -c {shlex.quote(str(cmd))}"
        if remote_cwd is not None:
            wrapped_cmd = f"cd {remote_cwd} && {wrapped_cmd}"
        # The whole command to pass it to SSH for remote execution.
        return self.ssh_cmd.with_args(quoted(wrapped_cmd))

    def scp(self, sources: List[Path], target: str, quiet: bool = False):
        return self.scp_cmd.with_args(*sources, f"{self.host}:{target}").fg(quiet=quiet)


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


def batched(source: Iterable[T], max_batch_size: int) -> Iterable[List[T]]:
    """
    Returns an iterator over batches of elements from source_list.

    >>> list(batched([1, 2, 3, 4, 5], 2))
    [[1, 2], [3, 4], [5]]
    """
    source_list = list(source)
    # Calculate batch size that spreads elements evenly across all batches
    batch_count = ceil(len(source_list) / max_batch_size)
    batch_size = ceil(len(source_list) / batch_count)
    for index in range(0, len(source_list), batch_size):
        yield source_list[index : min(index + batch_size, len(source_list))]


# Shorthands
quoted = QuotedString
cmd = Command
cwd = cwd_context
parallel = ParallelCommands


if __name__ == "__main__":
    import doctest

    (failures, num_tests) = doctest.testmod(optionflags=doctest.ELLIPSIS)
    sys.exit(1 if failures > 0 else 0)
