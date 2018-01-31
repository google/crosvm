// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "qcow_utils.h"

int main(int argc, char **argv) {
	return create_qcow_with_size("/tmp/test.qcow2", 1024*1024*100);
}
