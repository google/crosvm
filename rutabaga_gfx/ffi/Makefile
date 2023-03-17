# Copyright 2023 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

prefix ?= /usr/local
libdir = ${prefix}/lib
includedir = ${prefix}/include

ifdef debug
  release :=
  target :=debug
  extension :=debug
  OUT = target/debug
else
  release :=--release
  target :=release
  extension :=
  OUT = target/release
endif

RUTABAGA_VERSION_MAJOR := 0
SRC ?= src
LIB_NAME := librutabaga_gfx_ffi.so
RUTABAGA_VERSION := $(RUTABAGA_VERSION_MAJOR).1.1-alpha.1

all: build

build:
	cargo build $(release)

install: build
	mkdir -p $(DESTDIR)$(prefix)
	install -D -m 755 $(OUT)/$(LIB_NAME) $(DESTDIR)$(libdir)
	ln -sf $(DESTDIR)$(prefix)/$(LIB_NAME) $(DESTDIR)$(libdir)/$(LIB_NAME).$(RUTABAGA_VERSION)
	ln -sf $(DESTDIR)$(prefix)/$(LIB_NAME) $(DESTDIR)$(libdir)/$(LIB_NAME).$(RUTABAGA_VERSION_MAJOR)
	install -D -m 0644 $(SRC)/share/rutabaga_gfx_ffi.pc $(DESTDIR)$(libdir)/pkgconfig/rutabaga_gfx_ffi.pc
	install -D -m 0644 $(SRC)/include/rutabaga_gfx_ffi.h $(DESTDIR)$(includedir)/rutabaga_gfx_ffi.h

clean:
	cargo clean $(release)

distclean:
	cargo clean $(release)

help:
	@echo "usage: make $(prog) [debug=1]"
