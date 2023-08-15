# Copyright 2023 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

prefix ?= /usr/local
libdir = ${prefix}/lib
includedir = ${prefix}/include/rutabaga_gfx

UNAME := $(shell uname -s)

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

ifeq ($(UNAME), Linux)
LIB_NAME := librutabaga_gfx_ffi.so
endif

ifeq ($(UNAME), Darwin)
LIB_NAME := librutabaga_gfx_ffi.dylib
endif

RUTABAGA_VERSION := $(RUTABAGA_VERSION_MAJOR).1.2

all: build

build:
	cargo build --features=gfxstream $(release)

install: build
ifeq ($(UNAME), Linux)
	install -D -m 755 -t $(DESTDIR)$(libdir) $(OUT)/$(LIB_NAME)
endif
ifeq ($(UNAME), Darwin)
        install_name_tool -id $(DESTDIR)$(libdir)/$(LIB_NAME) $(DESTDIR)$(libdir)/$(LIB_NAME)
endif
	ln -sf $(DESTDIR)$(libdir)/$(LIB_NAME) $(DESTDIR)$(libdir)/$(LIB_NAME).$(RUTABAGA_VERSION)
	ln -sf $(DESTDIR)$(libdir)/$(LIB_NAME) $(DESTDIR)$(libdir)/$(LIB_NAME).$(RUTABAGA_VERSION_MAJOR)
ifeq ($(UNAME), Linux)
	install -D -m 0644 $(SRC)/share/rutabaga_gfx_ffi.pc $(DESTDIR)$(libdir)/pkgconfig/rutabaga_gfx_ffi.pc
	install -D -m 0644 $(SRC)/include/rutabaga_gfx_ffi.h $(DESTDIR)$(includedir)/rutabaga_gfx_ffi.h
endif
ifeq ($(UNAME), Darwin)
	install -m 0644 $(SRC)/share/rutabaga_gfx_ffi.pc $(DESTDIR)$(libdir)/pkgconfig/rutabaga_gfx_ffi.pc
	install -m 0644 $(SRC)/include/rutabaga_gfx_ffi.h $(DESTDIR)$(includedir)/rutabaga_gfx_ffi.h
endif

clean:
	cargo clean $(release)

distclean:
	cargo clean $(release)

help:
	@echo "usage: make $(prog) [debug=1]"
