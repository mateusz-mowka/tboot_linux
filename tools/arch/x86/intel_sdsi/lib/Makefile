ifeq ($(srctree),)
srctree := $(patsubst %/,%,$(dir $(CURDIR)))
srctree := $(patsubst %/,%,$(dir $(srctree)))
srctree := $(patsubst %/,%,$(dir $(srctree)))
srctree := $(patsubst %/,%,$(dir $(srctree)))
srctree := $(patsubst %/,%,$(dir $(srctree)))
# $(info Determined 'srctree' to be $(srctree))
endif

CC = gcc

INCL_PATH = \
-I/usr/include/libnl3 \
-I$(srctree)/tools/include	# For ARRAY_SIZE

CFLAGS = -Wextra

override CFLAGS += -O2 -Wall -Wno-unused-parameter -g -Werror
#override CFLAGS += -Wall -Wno-unused-parameter -g #-Werror

SDSI_GENL_HDR := drivers/platform/x86/intel/sdsi_genl.h
$(SDSI_GENL_HDR) : FORCE
	make clean
	echo $(srctree)
	ln -sf $(srctree)/$@ .
	make libsdsi_spdm.so

libsdsi_spdm.so : sdsi_spdm_nl.o sdsi_spdm.o
	$(CC) $(CFLAGS) -shared -o $@ $^ -L/lib/x86_64-linux-gnu -lnl-3 -lnl-genl-3

sdsi_spdm.o : sdsi_spdm.c
	$(CC) $(CFLAGS) -c -fPIC $(INCL_PATH) -o $@ $< -L/lib/x86_64-linux-gnu -lnl-3 -lnl-genl-3

sdsi_spdm_nl.o : sdsi_spdm_nl.c
	$(CC) $(CFLAGS) -c -fPIC $(INCL_PATH) -o $@ $< -L/lib/x86_64-linux-gnu -lnl-3 -lnl-genl-3

clean:
	rm -f *.o *.so sdsi_genl.h

FORCE:

.PHONY : clean FORCE
