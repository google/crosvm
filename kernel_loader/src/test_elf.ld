/* Copyright 2022 The ChromiumOS Authors All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

/* Load the kernel starting at paddr 0x200000 */
MEMORY {
    VMA : ORIGIN = 0x00200000, LENGTH = 0x200000
}

SECTIONS {
  .rodata : { *(.rodata) } > VMA
  .text : { *(.text) } > VMA
}
