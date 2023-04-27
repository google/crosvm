#!/usr/bin/env python3
# Copyright 2023 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""
Provides helpers for accessing gerrit and listing files under version control.
"""

import functools
import getpass
import json
import shutil
import sys
from pathlib import Path
from tempfile import gettempdir
from typing import (
    Any,
    Dict,
    List,
    cast,
)

from .command import quoted, cmd
from .util import very_verbose

# File where to store http headers for gcloud authentication
AUTH_HEADERS_FILE = Path(gettempdir()) / f"crosvm_gcloud_auth_headers_{getpass.getuser()}"

"Url of crosvm's gerrit review host"
GERRIT_URL = "https://chromium-review.googlesource.com"


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
        # File where to store http headers for gcloud authentication
        AUTH_HEADERS_FILE = Path(gettempdir()) / f"crosvm_gcloud_auth_headers_{getpass.getuser()}"

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


if __name__ == "__main__":
    import doctest

    (failures, num_tests) = doctest.testmod(optionflags=doctest.ELLIPSIS)
    sys.exit(1 if failures > 0 else 0)
