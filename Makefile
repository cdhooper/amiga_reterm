#
# This program is built with gcc. Make sure it is in your path before
# typing make. Example:
#     PATH=$PATH:/opt/amiga-gcc/bin
#     make

VERSION ?= 1.2+

PROGS   := reterm conperf
CC      := m68k-amigaos-gcc

CFLAGS  := -Wall -Wno-pointer-sign -Os -DVERSION=\"$(VERSION)\"
CFLAGS  += -fomit-frame-pointer
#CFLAGS += -pg   # Generate profile info to gmon.out.  To view:
#                          m68k-amigaos-gprof reterm gmon.out

LDFLAGS = -Xlinker -Map=objs/$@.map -mcrt=clib2

#CFLAGS += -g
#LDFLAGS += -g

BUILD_TIMESTAMP := $(shell date '+%Y-%m-%d %H:%M:%S')
DATE := $(word 1,$(BUILD_TIMESTAMP))
TIME := $(word 2,$(BUILD_TIMESTAMP))
CFLAGS += -DBUILD_DATE=\"$(DATE)\" -DBUILD_TIME=\"$(TIME)\"

PROGVER := reterm_$(VERSION)

ifeq (, $(shell which $(CC) 2>/dev/null ))
$(error "No $(CC) in PATH: maybe do PATH=$$PATH:/opt/amiga/bin")
endif

all: $(PROGS)

gdb:
	m68k-amigaos-gdb reterm

reterm: reterm.c
conperf: conperf.c

$(PROGS): Makefile
	$(CC) $(CFLAGS) $(filter %.c,$^) -o $@ $(LDFLAGS)

clean:
	rm $(PROGS)

RELEASE_DIR := release/reterm_$(VERSION)
RELEASE_LHA := release/reterm_$(VERSION).lha
RELEASE_SUBDIR := $(patsubst release/%,%,$(RELEASE_DIR))
$(info RELEASE_SUBDIR=$(RELEASE_SUBDIR))

RELEASE_TARGETS :=
RELEASE_DIRS :=
define RELEASE_IT
ifneq (,$(wildcard $(1)))
RELEASE_TARGETS += $(RELEASE_DIR)/$(2)
RELEASE_DIRS += $(dir $(RELEASE_DIR)/$(2))
$(RELEASE_DIR)/$(2): $(1)
endif
endef
$(eval $(call RELEASE_IT,reterm,reterm))
$(eval $(call RELEASE_IT,conperf,conperf))
$(eval $(call RELEASE_IT,README.md,README.md))
$(eval $(call RELEASE_IT,reterm.doc,reterm.doc))
$(eval $(call RELEASE_IT,LICENSE,LICENSE))

RELEASE_DIRS := $(sort $(RELEASE_DIR) $(RELEASE_DIRS))

ifneq (,$(wildcard $(RELEASE_LHA))$(wildcard $(RELEASE_ZIP))$(wildcard $(RELEASE_ADF)))
release:
	@echo $(RELEASE_LHA) already exists.
else
release: all
	@$(MAKE) do_release

do_release: populating $(RELEASE_TARGETS) $(RELEASE_LHA)

zip:
	@echo Building $(PROGVER).zip
	$(QUIET)rm -rf $(PROGS).zip $(PROGVER)
	$(QUIET)mkdir $(PROGVER)
	$(QUIET)cp -p $(PROGS) README.md $(PROGVER)/
	$(QUIET)zip -rq $(PROGVER).zip $(PROGVER)
	$(QUIET)rm -rf $(PROGVER)

$(RELEASE_LHA):
	@echo Building $(RELEASE_LHA)
	@rm -f $@
	(cd release; lha -aq2 $(notdir $@) $(RELEASE_SUBDIR)/*)

populating:
	@echo "* Populating $(RELEASE_DIR)"

$(RELEASE_TARGETS): | $(RELEASE_DIRS)
	cp -p $^ $@

$(info RELEASE_DIRS=$(RELEASE_DIRS))
$(RELEASE_DIRS):
	mkdir -p $@
endif
