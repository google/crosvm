#!/usr/bin/env python3
# Copyright 2023 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""
Provides a framework for command line interfaces based on argh.

It automatically adds common arguments, such as -v, -vv and --color to provide consistent
behavior.
"""

import argparse
import sys
import traceback
from typing import (
    Any,
    Callable,
    Optional,
)

from .util import (
    add_common_args,
    parse_common_args,
    print_timing_info,
    record_time,
    verbose,
    ensure_packages_exist,
)

ensure_packages_exist("argh")
import argh  # type: ignore

# Hack: argh does not support type annotations. This prevents type errors.
argh: Any  # type: ignore


def run_main(main_fn: Callable[..., Any], usage: Optional[str] = None):
    run_commands(default_fn=main_fn, usage=usage)


def run_commands(
    *functions: Callable[..., Any],
    default_fn: Optional[Callable[..., Any]] = None,
    usage: Optional[str] = None,
):
    """
    Allow the user to call the provided functions with command line arguments translated to
    function arguments via argh: https://pythonhosted.org/argh
    """
    exit_code = 0
    try:
        parser = argparse.ArgumentParser(
            description=usage,
            # Docstrings are used as the description in argparse, preserve their formatting.
            formatter_class=argparse.RawDescriptionHelpFormatter,
            # Do not allow implied abbreviations. Abbreviations should be manually specified.
            allow_abbrev=False,
        )
        add_common_args(parser)

        # Add provided commands to parser. Do not use sub-commands if we just got one function.
        if functions:
            argh.add_commands(parser, functions)  # type: ignore
        if default_fn:
            argh.set_default_command(parser, default_fn)  # type: ignore

        with record_time("Total Time"):
            # Call main method
            argh.dispatch(parser)  # type: ignore

    except Exception as e:
        if verbose():
            traceback.print_exc()
        else:
            print(e)
        exit_code = 1

    if parse_common_args().timing_info:
        print_timing_info()

    sys.exit(exit_code)


if __name__ == "__main__":
    import doctest

    (failures, num_tests) = doctest.testmod(optionflags=doctest.ELLIPSIS)
    sys.exit(1 if failures > 0 else 0)
