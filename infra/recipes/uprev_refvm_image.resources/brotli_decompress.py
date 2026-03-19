# Copyright 2026 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Decompresses a Brotli-compressed file."""

import brotli
import sys


def main():
    if len(sys.argv) != 3:
        print("Usage: brotli_decompress.py <input> <output>")
        sys.exit(1)
    input_file = sys.argv[1]
    output_file = sys.argv[2]

    with open(input_file, "rb") as f:
        compressed_data = f.read()

    decompressed_data = brotli.decompress(compressed_data)

    with open(output_file, "wb") as f:
        f.write(decompressed_data)


if __name__ == "__main__":
    main()
