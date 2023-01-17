# H.264 Test Data

This document lists the test data used by the H.264 decoder.

Unless otherwise noted, the CRCs were computed using GStreamer's VA-API decoder in
`gst-plugins-bad`.

## 16x16-I.h264

A 16x16 progressive byte-stream encoded I-frame to make it easier to spot errors on the libva trace.
Encoded with the following GStreamer pipeline:

```
gst-launch-1.0 videotestsrc num-buffers=1 ! video/x-raw,format=I420,width=16,height=16 ! \
x264enc ! video/x-h264,profile=constrained-baseline,stream-format=byte-stream ! \
filesink location="/tmp/16x16-I.h264"
```

## 16x16-I-P.h264

A 16x16 progressive byte-stream encoded I-frame and P-frame to make it easier to spot errors on the
libva trace. Encoded with the following GStreamer pipeline:

```
gst-launch-1.0 videotestsrc num-buffers=2 ! video/x-raw,format=I420,width=16,height=16 ! \
x264enc b-adapt=false ! video/x-h264,profile=constrained-baseline,stream-format=byte-stream ! \
filesink location="/tmp/16x16-I-P.h264"
```

## 16x16-I-P-B-P.h264

A 16x16 progressive byte-stream encoded I-P-B-P sequence to make it easier to it easier to spot
errors on the libva trace. Encoded with the following GStreamer pipeline:

```
gst-launch-1.0 videotestsrc num-buffers=3 ! video/x-raw,format=I420,width=16,height=16 ! \
x264enc b-adapt=false bframes=1 ! video/x-h264,profile=constrained-baseline,stream-format=byte-stream ! \
filesink location="/tmp/16x16-I-B-P.h264"
```

## 16x16-I-P-B-P-high.h264

A 16x16 progressive byte-stream encoded I-P-B-P sequence to make it easier to it easier to spot
errors on the libva trace. Also tests whether the decoder supports the high profile. Encoded with
the following GStreamer pipeline:

```
gst-launch-1.0 videotestsrc num-buffers=3 ! video/x-raw,format=I420,width=16,height=16 ! \
x264enc b-adapt=false bframes=1 ! video/x-h264,profile=high,stream-format=byte-stream ! \
filesink location="/tmp/16x16-I-B-P-high.h264"
```

## test-25fps.h264

Same as Chromium's `test-25fps.h264`. The slice data in `test-25fps-h264-slice-data-*.bin` was
manually extracted from GStreamer using GDB.

## test-25fps-interlaced.h264

Adapted from Chromium's `test-25fps.h264`. Same file as above, but encoded as interlaced instead
using the following ffmpeg command:

```
ffmpeg -i \
src/third_party/blink/web_tests/media/content/test-25fps.mp4 \
-flags +ilme+ildct  -vbsf h264_mp4toannexb -an test-25fps.h264
```

This test makes sure that the interlaced logic in the decoder actually works, specially that "frame
splitting" works, as the fields here were encoded as frames.
