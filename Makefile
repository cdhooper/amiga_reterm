#
# This program is built with gcc. Make sure it is in your path before
# typing make. Example:
#     PATH=$PATH:/opt/amiga-gcc/bin
#     make

VER     ?= 1.1+

PROGS   := reterm conperf
CC      := m68k-amigaos-gcc
CFLAGS  := -Wall -Wno-pointer-sign -Os -DVER=\"$(VER)\"
CFLAGS  += -fomit-frame-pointer
#CFLAGS += -pg   # Generate profile info to gmon.out.  To view:
#                          m68k-amigaos-gprof reterm gmon.out

LDFLAGS = -Xlinker -Map=objs/$@.map -mcrt=clib2

#CFLAGS += -g
#LDFLAGS += -g

ifeq (, $(shell which $(CC) 2>/dev/null ))
$(error "No $(CC) in PATH: maybe do PATH=$$PATH:/opt/amiga/bin")
endif

all: $(PROGS)

gdb:
	m68k-amigaos-gdb $(PROG)

reterm: reterm.c
conperf: conperf.c

$(PROGS): Makefile
	$(CC) $(CFLAGS) $(filter %.c,$^) -o $@ $(LDFLAGS)

clean:
	rm $(PROGS)
