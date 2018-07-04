// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <stdint.h>

void host_cpuid(uint32_t func, uint32_t func2, uint32_t *pEax,
                uint32_t *pEbx, uint32_t *pEcx, uint32_t *pEdx) {
    asm volatile("cpuid" : "=a"(*pEax), "=b"(*pEbx), "=c"(*pEcx), "=d"(*pEdx) :
                 "0"(func), "2"(func2) : "cc");
}
