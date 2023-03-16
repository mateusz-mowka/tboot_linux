# SPDX-License-Identifier: GPL-2.0
# Makefile for Intel Software Defined Silicon provisioning tool

ifeq ($(srctree),)
srctree := $(patsubst %/,%,$(dir $(CURDIR)))
srctree := $(patsubst %/,%,$(dir $(srctree)))
srctree := $(patsubst %/,%,$(dir $(srctree)))
# $(info Determined 'srctree' to be $(srctree))
endif

INCL_PATH = \
-Ilib/

CC=gcc

CFLAGS = -L. -Wextra

BINDIR ?= /usr/sbin

LDFLAGS += -l:libsdsi_spdm.so -lkeyutils

override CFLAGS += -O2 -Wall

intel_sdsi: sdsi.c libsdsi_spdm.so
	$(CC) $(CFLAGS) $(INCL_PATH) -o $@ $< $(LDFLAGS)

libsdsi_spdm.so:
	$(MAKE) -C lib/
	cp lib/$@ .

.PHONY : clean
clean :
	@rm -f intel_sdsi libsdsi_spdm.so
	$(MAKE) clean -C lib/

install : intel_sdsi
	install -d  $(DESTDIR)$(BINDIR)
	install -m 755 -p intel_sdsi $(DESTDIR)$(BINDIR)/intel_sdsi
