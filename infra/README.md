# WIP Luci Infrastructure

This directory contains the configuration and build recipes run by our luci infrastructure for CI
and presubmit testing. This is currently a work in progress.

See [Kokoro](../ci/kokoro) configs for the actively used presubmit system.

Note: Luci applies config and recipes changes asynchronously. Do not submit changes to this
directory in the same commit as changes to other crosvm source.
