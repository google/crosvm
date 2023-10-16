#!/usr/bin/env python3

# Copyright 2023 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

from collections import defaultdict
import argparse
import subprocess
import os
import json
import pandas as pd
import plotly
import plotly.graph_objects as go
import plotly.express as px


class BalloonRecord:
    def __init__(self, rec):
        byte_to_gb = 1024.0**3
        self.total = rec["balloon_stats"]["stats"]["total_memory"] / byte_to_gb
        self.free = rec["balloon_stats"]["stats"]["free_memory"] / byte_to_gb
        self.disk_caches = rec["balloon_stats"]["stats"]["disk_caches"] / byte_to_gb
        self.avail = rec["balloon_stats"]["stats"]["available_memory"] / byte_to_gb

        self.shared_memory = (rec["balloon_stats"]["stats"]["shared_memory"] or 0.0) / byte_to_gb
        self.unevictable_memory = (
            rec["balloon_stats"]["stats"]["unevictable_memory"] or 0.0
        ) / byte_to_gb
        self.balloon_actual = (rec["balloon_stats"]["balloon_actual"] or 0.0) / byte_to_gb


class Records:
    def __init__(self) -> None:
        self.data = []

    def add(self, timestamp, name, mem_usage) -> None:
        self.data.append({"boot time (sec)": timestamp, "process": name, "PSS (GB)": mem_usage})


def memstat_plot(data, args) -> str:
    names = set()
    for rec in data:
        for p in rec["stats"]:
            names.add(p["name"])

    recs = Records()
    ballon_sizes = [[], []]

    total_memory_size = BalloonRecord(data[-1]).total
    for rec in data:
        timestamp = int(rec["timestamp"])

        balloon = None
        if rec["balloon_stats"]:
            balloon = BalloonRecord(rec)

        # Dict: name -> (dict: field -> value)
        # Example: { "crosvm": {"Pss": 100, "Rss": 120, ...}, "virtio-blk": ... }
        proc_to_smaps = {name: defaultdict(int) for name in names}

        # Summarize multiple processes using the same name such as multiple virtiofs devices.
        for p in rec["stats"]:
            name = p["name"]
            for key in p["smaps"]:
                val = p["smaps"][key]
                # Convert the value from KB to GB.
                proc_to_smaps[name][key] += val / (1024.0**2)

        for p in rec["stats"]:
            name = p["name"]
            smaps = proc_to_smaps[name]

            if name != "crosvm":
                # TODO: We may want to track VmPTE too.
                # https://chromium-review.googlesource.com/c/crosvm/crosvm/+/4712086/comment/9e08afd5_2fd05550/
                recs.add(timestamp, name, smaps["Private_Dirty"])
                continue

            assert name == "crosvm"
            if not balloon:
                recs.add(timestamp, "crosvm (guest disk caches)", 0)
                recs.add(timestamp, "crosvm (guest shared memory)", 0)
                recs.add(timestamp, "crosvm (guest unevictable)", 0)
                recs.add(timestamp, "crosvm (guest used)", 0)

                recs.add(timestamp, "crosvm (host)", smaps["Rss"])

                ballon_sizes[0].append(timestamp)
                ballon_sizes[1].append(total_memory_size)

                continue

            recs.add(timestamp, "crosvm (guest disk caches)", balloon.disk_caches)
            recs.add(timestamp, "crosvm (guest shared memory)", balloon.shared_memory)
            recs.add(timestamp, "crosvm (guest unevictable)", balloon.unevictable_memory)

            # (guest used) = (guest total = host's RSS) - (free + balloon_actual + disk caches + shared memory)
            guest_used = (
                balloon.total
                - balloon.free
                - balloon.balloon_actual
                - balloon.disk_caches
                - balloon.shared_memory
                - balloon.unevictable_memory
            )
            assert guest_used >= 0
            if guest_used > proc_to_smaps["crosvm"]["Rss"]:
                print(
                    "WARNING: guest_used > crosvm RSS: {} > {}".format(
                        guest_used, proc_to_smaps["crosvm"]["Rss"]
                    )
                )

            recs.add(timestamp, "crosvm (guest used)", guest_used)
            crosvm_host = (
                proc_to_smaps["crosvm"]["Rss"]
                - guest_used
                - balloon.disk_caches
                - balloon.shared_memory
                - balloon.unevictable_memory
            )
            if crosvm_host < 0:
                print("WARNING: crosvm (host) < 0: {}".format(crosvm_host))
            recs.add(timestamp, "crosvm (host)", crosvm_host)

            ballon_sizes[0].append(timestamp)
            ballon_sizes[1].append(balloon.total - balloon.balloon_actual)

    df = pd.DataFrame(recs.data)
    fig = px.area(
        df,
        x="boot time (sec)",
        y="Memory usage (GB)",
        color="process",
    )
    fig.update_layout(title={"text": args.title})
    fig.add_trace(
        go.Scatter(
            x=ballon_sizes[0],
            y=ballon_sizes[1],
            mode="lines",
            name="(total memory) - (balloon size)",
        )
    )

    base, _ = os.path.splitext(args.input)
    outname = base + "." + args.format
    if args.format == "html":
        fig.write_html(outname)
    else:
        plotly.io.write_image(fig, outname, format="png")
    print(f"{outname} is written")
    return outname


def main():
    parser = argparse.ArgumentParser(description="Plot JSON generated by memstats_chart")
    parser.add_argument("-i", "--input", required=True, help="input JSON file path")
    parser.add_argument("--format", choices=["html", "png"], default="html")
    parser.add_argument("--title", default="crosvm memory usage")
    args = parser.parse_args()

    with open(args.input) as f:
        data = json.load(f)

    outfile = memstat_plot(data, args)

    try:
        subprocess.run(["google-chrome", outfile])
    except Exception as e:
        print(f"Failed to open {outfile} with google-chrome: {e}")


main()
