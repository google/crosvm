/* Copyright 2022 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

.section .boot, "awx"
.global _start
.code64

_start:
    lea rsp, _stack_end

    jmp main
