#!/usr/bin/env python3
# Copyright 2022 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""
Provides helpers for writing shell-like scripts in Python.

It provides tools to execute commands with similar flexibility to shell scripts and simplifies
command line arguments using `argh` and provides common flags (e.g. -v and -vv) for all of
our command line tools.

Refer to the scripts in ./tools for example usage.
"""
import functools
import json
import sys
import subprocess


def ensure_package_exists(package: str):
    """Installs the specified package via pip if it does not exist."""
    try:
        __import__(package)
    except ImportError:
        print(
            f"Missing the python package {package}. Do you want to install? [y/N] ",
            end="",
            flush=True,
        )
        response = sys.stdin.readline()
        if response[:1].lower() == "y":
            subprocess.check_call([sys.executable, "-m", "pip", "install", "--user", package])
        else:
            sys.exit(1)


ensure_package_exists("argh")

from io import StringIO
from math import ceil
from multiprocessing.pool import ThreadPool
from pathlib import Path
from subprocess import DEVNULL, PIPE, STDOUT  # type: ignore
from tempfile import gettempdir
from typing import Any, Callable, Dict, Iterable, List, NamedTuple, Optional, TypeVar, Union, cast
import argh  # type: ignore
import argparse
import contextlib
import csv
import getpass
import os
import re
import shutil
import traceback

# File where to store http headers for gcloud authentication
AUTH_HEADERS_FILE = Path(gettempdir()) / f"crosvm_gcloud_auth_headers_{getpass.getuser()}"

PathLike = Union[Path, str]


def find_crosvm_root():
    "Walk up from CWD until we find the crosvm root dir."
    path = Path("").resolve()
    while True:
        if (path / "tools/impl/common.py").is_file():
            return path
        if path.parent:
            path = path.parent
        else:
            raise Exception("Cannot find crosvm root dir.")


"Root directory of crosvm derived from CWD."
CROSVM_ROOT = find_crosvm_root()

"Cargo.toml file of crosvm"
CROSVM_TOML = CROSVM_ROOT / "Cargo.toml"

"""
Root directory of crosvm devtools.

May be different from `CROSVM_ROOT/tools`, which is allows you to run the crosvm dev
tools from this directory on another crosvm repo.

Use this if you want to call crosvm dev tools, which will use the scripts relative
to this file.
"""
TOOLS_ROOT = Path(__file__).parent.parent.resolve()

"Url of crosvm's gerrit review host"
GERRIT_URL = "https://chromium-review.googlesource.com"

# Ensure that we really found the crosvm root directory
assert 'name = "crosvm"' in CROSVM_TOML.read_text()


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

    >>> Command('ls -l', *Path('.').glob('*.toml'))
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
    ):
        self.args = Command.__parse_cmd(args)
        self.stdin_cmd = stdin_cmd
        self.env_vars = env_vars

    ### Builder API to construct commands

    def with_args(self, *args: Any):
        """Returns a new Command with added arguments.

        >>> cargo = Command('cargo')
        >>> cargo.with_args('clippy')
        Command('cargo', 'clippy')
        """
        cmd = Command()
        cmd.args = [*self.args, *Command.__parse_cmd(args)]
        cmd.env_vars = self.env_vars
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
        cmd = Command()
        cmd.args = self.args
        cmd.env_vars = self.env_vars
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
        cmd = Command()
        cmd.args = self.args
        cmd.env_vars = {**self.env_vars, "PATH": f"{path_var}:{new_path}"}
        return cmd

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

    def run_foreground(self, quiet: bool = False, check: bool = True, dry_run: bool = False):
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

        Output can be hidden by setting quiet=True:

        >>> Command("echo foo").fg(quiet=True)
        0

        This will hide the programs stdout and stderr unless the program fails.

        Arguments:
            quiet: Do not show stdout/stderr unless the program failed.
            check: Raise an exception if the program returned an error code.

        Returns: The return code of the program.
        """
        if dry_run:
            print(f"Not running: {self}")
            return 0

        if verbose():
            print(f"$ {self}")
        if quiet:
            result = self.__run(stdout=PIPE, stderr=STDOUT, check=False)
        else:
            result = self.__run(stdout=None, stderr=None, check=False)

        # If stdout was capured, print it if the program failed (or verbose is enabled).
        # Skip this if very_verbose is enabled since __run will print captured output already.
        if result.stdout and (verbose() or result.returncode != 0) and not very_verbose():
            print(result.stdout)

        if result.returncode != 0:
            if check:
                raise subprocess.CalledProcessError(result.returncode, str(self), result.stdout)
        return result.returncode

    def fg(self, quiet: bool = False, check: bool = True, dry_run: bool = False):
        """
        Shorthand for Command.run_foreground()
        """
        return self.run_foreground(quiet, check, dry_run)

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

    def stdout(self, check: bool = True):
        """
        Runs a program and returns stdout.

        The program will not be visible to the user unless --very-verbose is specified.
        """
        if very_verbose():
            print(f"$ {self}")
        return self.__run(stdout=PIPE, stderr=PIPE, check=check).stdout.strip()

    def lines(self, check: bool = True):
        """
        Runs a program and returns stdout line by line.

        The program will not be visible to the user unless --very-verbose is specified.
        """
        return self.stdout(check=check).splitlines()

    ### Utilities

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
            return self.stdin_cmd.__popen().stdout
        return None

    def __popen(self, stderr: Optional[int] = PIPE) -> "subprocess.Popen[str]":
        """
        Runs a program and returns the Popen object of the running process.
        """
        return subprocess.Popen(
            self.args,
            stdout=subprocess.PIPE,
            stderr=stderr,
            stdin=self.__stdin_stream(),
            env={**os.environ, **self.env_vars},
            text=True,
        )

    @staticmethod
    def __shell_like_split(value: str):
        """Splits a string by spaces, accounting for escape characters and quoting."""
        # Re-use csv parses to split by spaces and new lines, while accounting for quoting.
        for line in csv.reader(StringIO(value), delimiter=" ", quotechar='"'):
            for arg in line:
                if arg:
                    yield arg

    @staticmethod
    def __parse_cmd(args: Iterable[Any]) -> List[str]:
        """Parses command line arguments for Command."""
        res = [parsed for arg in args for parsed in Command.__parse_cmd_args(arg)]
        return res

    @staticmethod
    def __parse_cmd_args(arg: Any) -> List[str]:
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

    def fg(self, quiet: bool = False, check: bool = True):
        with ThreadPool(1 if very_verbose() else os.cpu_count()) as pool:
            return pool.map(lambda command: command.fg(quiet=quiet, check=check), self.commands)

    def stdout(self):
        with ThreadPool(1 if very_verbose() else os.cpu_count()) as pool:
            return pool.map(lambda command: command.stdout(), self.commands)

    def success(self):
        results = self.fg(check=False, quiet=True)
        return all(result == 0 for result in results)


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


def run_main(main_fn: Callable[..., Any]):
    run_commands(default_fn=main_fn)


def run_commands(
    *functions: Callable[..., Any],
    default_fn: Optional[Callable[..., Any]] = None,
    usage: Optional[str] = None,
):
    """
    Allow the user to call the provided functions with command line arguments translated to
    function arguments via argh: https://pythonhosted.org/argh
    """
    try:
        parser = argparse.ArgumentParser(usage=usage)
        add_common_args(parser)

        # Add provided commands to parser. Do not use sub-commands if we just got one function.
        if functions:
            argh.add_commands(parser, functions)  # type: ignore
        if default_fn:
            argh.set_default_command(parser, default_fn)  # type: ignore

        # Call main method
        argh.dispatch(parser)  # type: ignore
    except Exception as e:
        if verbose():
            traceback.print_exc()
        else:
            print(e)
        sys.exit(1)


@functools.lru_cache(None)
def parse_common_args():
    """
    Parse args common to all scripts

    These args are parsed separately of the run_main/run_commands method so we can access
    verbose/etc before the commands arguments are parsed.
    """
    parser = argparse.ArgumentParser()
    add_common_args(parser)
    return parser.parse_known_args()[0]


def add_common_args(parser: argparse.ArgumentParser):
    "These args are added to all commands."
    parser.add_argument(
        "--color",
        default="auto",
        choices=("always", "never", "auto"),
        help="Force enable or disable colors. Defaults to automatic detection.",
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        default=False,
        help="Print more details about the commands this script is running.",
    )
    parser.add_argument(
        "--very-verbose",
        "-vv",
        action="store_true",
        default=False,
        help="Print more debug output",
    )


def verbose():
    return very_verbose() or parse_common_args().verbose


def very_verbose():
    return parse_common_args().very_verbose


def color_enabled():
    color_arg = parse_common_args().color
    if color_arg == "never":
        return False
    if color_arg == "always":
        return True
    return sys.stdout.isatty()


def all_tracked_files():
    for line in cmd("git ls-files").lines():
        file = Path(line)
        if file.is_file():
            yield file


def find_source_files(extension: str, ignore: List[str] = []):
    for file in all_tracked_files():
        if file.suffix != f".{extension}":
            continue
        if file.is_relative_to("third_party"):
            continue
        if str(file) in ignore:
            continue
        yield file


def find_scripts(path: Path, shebang: str):
    for file in path.glob("*"):
        if file.is_file() and file.open(errors="ignore").read(512).startswith(f"#!{shebang}"):
            yield file


def confirm(message: str, default: bool = False):
    print(message, "[y/N]" if default == False else "[Y/n]", end=" ", flush=True)
    response = sys.stdin.readline().strip()
    if response in ("y", "Y"):
        return True
    if response in ("n", "N"):
        return False
    return default


def get_cookie_file():
    path = cmd("git config http.cookiefile").stdout(check=False)
    return Path(path) if path else None


def get_gcloud_access_token():
    if not shutil.which("gcloud"):
        return None
    return cmd("gcloud auth print-access-token").stdout(check=False)


@functools.lru_cache(maxsize=None)
def curl_with_git_auth():
    """
    Returns a curl `Command` instance set up to use the same HTTP credentials as git.

    This currently supports two methods:
    - git cookies (the default)
    - gcloud

    Most developers will use git cookies, which are passed to curl.

    glloud for authorization can be enabled in git via `git config credential.helper gcloud.sh`.
    If enabled in git, this command will also return a curl command using a gloud access token.
    """
    helper = cmd("git config credential.helper").stdout(check=False)

    if not helper:
        cookie_file = get_cookie_file()
        if not cookie_file or not cookie_file.is_file():
            raise Exception("git http cookiefile is not available.")
        return cmd("curl --cookie", cookie_file)

    if helper.endswith("gcloud.sh"):
        token = get_gcloud_access_token()
        if not token:
            raise Exception("Cannot get gcloud access token.")
        # Write token to a header file so it will not appear in logs or error messages.
        AUTH_HEADERS_FILE.write_text(f"Authorization: Bearer {token}")
        return cmd(f"curl -H @{AUTH_HEADERS_FILE}")

    raise Exception(f"Unsupported git credentials.helper: {helper}")


def strip_xssi(response: str):
    # See https://gerrit-review.googlesource.com/Documentation/rest-api.html#output
    assert response.startswith(")]}'\n")
    return response[5:]


def gerrit_api_get(path: str):
    response = cmd(f"curl --silent --fail {GERRIT_URL}/{path}").stdout()
    return json.loads(strip_xssi(response))


def gerrit_api_post(path: str, body: Any):
    response = curl_with_git_auth()(
        "--silent --fail",
        "-X POST",
        "-H",
        quoted("Content-Type: application/json"),
        "-d",
        quoted(json.dumps(body)),
        f"{GERRIT_URL}/a/{path}",
    ).stdout()
    if very_verbose():
        print("Response:", response)
    return json.loads(strip_xssi(response))


class GerritChange(object):
    """
    Class to interact with the gerrit /changes/ API.

    For information on the data format returned by the API, see:
    https://gerrit-review.googlesource.com/Documentation/rest-api-changes.html#change-info
    """

    id: str
    _data: Any

    def __init__(self, data: Any):
        self._data = data
        self.id = data["id"]

    @functools.cached_property
    def _details(self) -> Any:
        return gerrit_api_get(f"changes/{self.id}/detail")

    @functools.cached_property
    def _messages(self) -> List[Any]:
        return gerrit_api_get(f"changes/{self.id}/messages")

    @property
    def status(self):
        return cast(str, self._data["status"])

    def get_votes(self, label_name: str) -> List[int]:
        "Returns the list of votes on `label_name`"
        label_info = self._details.get("labels", {}).get(label_name)
        votes = label_info.get("all", [])
        return [cast(int, v.get("value")) for v in votes]

    def get_messages_by(self, email: str) -> List[str]:
        "Returns all messages posted by the user with the specified `email`."
        return [m["message"] for m in self._messages if m["author"].get("email") == email]

    def review(self, message: str, labels: Dict[str, int]):
        "Post review `message` and set the specified review `labels`"
        print("Posting on", self, ":", message, labels)
        gerrit_api_post(
            f"changes/{self.id}/revisions/current/review",
            {"message": message, "labels": labels},
        )

    def abandon(self, message: str):
        print("Abandoning", self, ":", message)
        gerrit_api_post(f"changes/{self.id}/abandon", {"message": message})

    @classmethod
    def query(cls, *queries: str):
        "Returns a list of gerrit changes matching the provided list of queries."
        return [cls(c) for c in gerrit_api_get(f"changes/?q={'+'.join(queries)}")]

    def short_url(self):
        return f"http://crrev.com/c/{self._data['_number']}"

    def __str__(self):
        return self.short_url()

    def pretty_info(self):
        return f"{self} - {self._data['subject']}"


def is_cros_repo():
    "Returns true if the crosvm repo is a symlink or worktree to a CrOS repo checkout."
    dot_git = CROSVM_ROOT / ".git"
    if not dot_git.is_symlink() and dot_git.is_dir():
        return False
    return (cros_repo_root() / ".repo").exists()


def cros_repo_root():
    "Root directory of the CrOS repo checkout."
    return (CROSVM_ROOT / "../../..").resolve()


if __name__ == "__main__":
    import doctest

    doctest.testmod(optionflags=doctest.ELLIPSIS)
