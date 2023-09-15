# Copyright 2023 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import json
import matplotlib.pyplot as plt
import argparse

parser = argparse.ArgumentParser()
parser.add_argument("input_json", help="create histogram from input_json")
args = parser.parse_args()

with open(args.input_json) as f:
    data = json.load(f)
for key in data.keys():
    plt.hist(data[key], bins=len(data[key]))
    plt.title(key)
    plt.xlabel("latency")
    plt.ylabel("number of requests")
    plt.show(block=True)
