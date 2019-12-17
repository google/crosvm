#!/bin/bash
# Copyright 2019 The Chromium OS Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

cd "${0%/*}"

cat >xlib.rs <<EOF
// Copyright 2019 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Generated using ./xlib_generator.sh

#[link(name = "X11")]
extern "C" {}

#[link(name = "Xext")]
extern "C" {}

EOF

bindgen --no-layout-tests --no-derive-debug \
  --whitelist-function XAllocSizeHints \
  --whitelist-function XBlackPixelOfScreen \
  --whitelist-function XClearWindow \
  --whitelist-function XCloseDisplay \
  --whitelist-function XConnectionNumber \
  --whitelist-function XCreateGC \
  --whitelist-function XCreateSimpleWindow \
  --whitelist-function XDefaultDepthOfScreen \
  --whitelist-function XDefaultScreenOfDisplay \
  --whitelist-function XDefaultVisualOfScreen \
  --whitelist-function XDestroyImage \
  --whitelist-function XDestroyWindow \
  --whitelist-function XFlush \
  --whitelist-function XFree \
  --whitelist-function XFreeGC \
  --whitelist-function XGetVisualInfo \
  --whitelist-function XInternAtom \
  --whitelist-function XKeycodeToKeysym \
  --whitelist-function XMapRaised \
  --whitelist-function XNextEvent \
  --whitelist-function XOpenDisplay \
  --whitelist-function XPending \
  --whitelist-function XRootWindowOfScreen \
  --whitelist-function XScreenNumberOfScreen \
  --whitelist-function XSelectInput \
  --whitelist-function XSetWMNormalHints \
  --whitelist-function XSetWMProtocols \
  --whitelist-function XShmAttach \
  --whitelist-function XShmCreateImage \
  --whitelist-function XShmDetach \
  --whitelist-function XShmGetEventBase \
  --whitelist-function XShmPutImage \
  --whitelist-function XShmQueryExtension \
  --whitelist-var 'XK_.*' \
  --whitelist-var ButtonPress \
  --whitelist-var ButtonPressMask \
  --whitelist-var Button1 \
  --whitelist-var Button1Mask \
  --whitelist-var ButtonRelease \
  --whitelist-var ButtonReleaseMask \
  --whitelist-var ClientMessage \
  --whitelist-var Expose \
  --whitelist-var ExposureMask \
  --whitelist-var KeyPress \
  --whitelist-var KeyPressMask \
  --whitelist-var KeyRelease \
  --whitelist-var KeyReleaseMask \
  --whitelist-var MotionNotify \
  --whitelist-var PMaxSize \
  --whitelist-var PMinSize \
  --whitelist-var PointerMotionMask \
  --whitelist-var ShmCompletion \
  --whitelist-var VisualBlueMaskMask \
  --whitelist-var VisualDepthMask \
  --whitelist-var VisualGreenMaskMask \
  --whitelist-var VisualRedMaskMask \
  --whitelist-var VisualScreenMask \
  --whitelist-var ZPixmap \
  --whitelist-type Display \
  --whitelist-type GC \
  --whitelist-type Screen \
  --whitelist-type XShmCompletionEvent \
  --whitelist-type ShmSeg \
  --whitelist-type Visual \
  --whitelist-type Window \
  --whitelist-type XVisualInfo \
  xlib_wrapper.h >>xlib.rs
