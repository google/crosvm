# VP9 Test Data

This document lists the test data used by the VP9 decoder.

Unless otherwise noted, the CRCs were computed using GStreamer's VA-API decoder in
`gst-plugins-bad`.

## test-25fps.vp9

Same as Chromium's `test-25fps.vp9`.

## vp90_2_10_show_existing_frame2_vp9

Test taken from `libvpx` official test suite.

The slice data in vp90_2_10_show_existing_frame2-vp9-ivf-slice-data-\*.bin was manually extracted
from GStreamer using GDB.

## vp90_2_10_show_existing_frame_vp9

Test taken from `libvpx` official test suite.

## resolution_change_500frames_vp9

Same as Chromium's `test_resolution_change_500frames_vp9`.

More information can be gathered from the Chromium documentation:

```
Dumped compressed stream of videos on
[http://crosvideo.appspot.com](http://crosvideo.appspot.com) manually
changing resolutions at random. Those contain 144p, 240p, 360p, 480p, 720p, and
1080p frames. Those frame sizes can be found by

ffprobe -show_frames resolution_change_500frames.vp9
```

The slice data in resolution_change_500frames-vp9-ivf-slice-data-\*.bin was manually extracted from
GStreamer using GDB.

## vp9-superframe.bin

Raw dump of a VP9 superframe. Extracted from GStreamer. Available at

```
gst-plugins-bad/tests/check/libs/vp9parser.c
```
