# Copyright 2022 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# Build instructions:
#
# For a 64-bit kernel:
#  x86_64-linux-gnu-as test_elf.S -o test_elf64.o
#  x86_64-linux-gnu-ld test_elf64.o -o test_elf64.bin -T test_elf.ld
#
# For a 32-bit kernel:
#  i686-linux-gnu-as test_elf.S -o test_elf32.o
#  i686-linux-gnu-ld test_elf32.o -o test_elf32.bin -T test_elf.ld

    .intel_syntax noprefix

    .section .rodata
hello_world:
    .string "Hello world!\n"
    .set hello_size, .-hello_world

    .text
    .globl _start
_start:
    lea esi, [hello_world]          # esi -> message string
    mov ecx, hello_size             # ecx = length of message
    mov dx, 0x3F8                   # dx = COM1 port

.print_loop:
    # Wait for the transmit buffer to be empty by polling the line status.
    add dx, 5                       # dx = line status register
.wait_empty:
    in al, dx                       # read line status
    test al, 0x20                   # check buffer empty flag
    jz .wait_empty                  # keep waiting if flag is not set

.wait_done:
    sub dx, 5                       # dx = data register

    # Load a byte of the message and send it to the serial port.
    lodsb                           # load message byte from RSI to AL
    out dx, al                      # send byte to serial port
    loop .print_loop                # repeat hello_size times

.done:
    int3                            # cause vcpu to exit
