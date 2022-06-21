ifeq ($(srctree),)
srctree := $(patsubst %/,%,$(dir $(CURDIR)))
srctree := $(patsubst %/,%,$(dir $(srctree)))
srctree := $(patsubst %/,%,$(dir $(srctree)))
# $(info Determined 'srctree' to be $(srctree))
endif

CC = gcc

INCL_PATH = \
-I/usr/include/libnl3 \
-I$(srctree)/tools/include	# For ARRAY_SIZE

CFLAGS = -Wextra

#override CFLAGS += -O2 -Wall -Wno-unused-parameter -g #-Werror
override CFLAGS += -Wall -Wno-unused-parameter -g #-Werror

SDSI_GENL_HDR := drivers/platform/x86/intel/sdsi_genl.h
$(SDSI_GENL_HDR) : FORCE
	make clean
	ln -sf $(srctree)/$@ $(srctree)/tools/lib/intel_sdsi/
	make libsdsi.so

libsdsi.so : sdsi_nl.o sdsi.o
	$(CC) $(CFLAGS) -shared -o $@ $^ -L/lib/x86_64-linux-gnu -lnl-3 -lnl-genl-3

sdsi.o : sdsi.c
	$(CC) $(CFLAGS) -c -fPIC $(INCL_PATH) -o $@ $< -L/lib/x86_64-linux-gnu -lnl-3 -lnl-genl-3

sdsi_nl.o : sdsi_nl.c
	$(CC) $(CFLAGS) -c -fPIC $(INCL_PATH) -o $@ $< -L/lib/x86_64-linux-gnu -lnl-3 -lnl-genl-3

clean:
	rm -f *.o *.so sdsi_genl.h $(srctree)/tools/lib/intel_sdsi/$(SDSI_GENL_HDR)

FORCE:

.PHONY : clean FORCE
