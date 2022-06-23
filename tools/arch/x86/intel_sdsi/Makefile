# SPDX-License-Identifier: GPL-2.0
# Makefile for Intel Software Defined Silicon provisioning tool

ifeq ($(srctree),)
srctree := $(patsubst %/,%,$(dir $(CURDIR)))
srctree := $(patsubst %/,%,$(dir $(srctree)))
srctree := $(patsubst %/,%,$(dir $(srctree)))
# $(info Determined 'srctree' to be $(srctree))
endif

INCL_PATH = \
-I$(srctree)/lib/intel_sdsi

CC=gcc

CFLAGS = -L/home/debox1/ext/repos/linux/tools/lib/intel_sdsi -Wextra

BINDIR ?= /usr/sbin

LDFLAGS += -l:libsdsi_spdm.so -lkeyutils

override CFLAGS += -O2 -Wall

intel_sdsi: sdsi.c
	$(CC) $(CFLAGS) $(INCL_PATH) -o $@ $< $(LDFLAGS)

.PHONY : clean
clean :
	@rm -f intel_sdsi

install : intel_sdsi
	install -d  $(DESTDIR)$(BINDIR)
	install -m 755 -p intel_sdsi $(DESTDIR)$(BINDIR)/intel_sdsi
