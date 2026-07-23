# SPDX-License-Identifier: GPL-2.0

include ../../../../build/Build.include
include ../../../../scripts/Makefile.arch
include ../../../../scripts/Makefile.include

TEST_GEN_PROGS := file_range_test

CFLAGS += -Wall -Wextra -O2 -g $(KHDR_INCLUDES) $(TOOLS_INCLUDES)
CFLAGS += -I$(OUTPUT) -I$(INCLUDE_DIR)
LDLIBS += -lelf -lz

OVERRIDE_TARGETS := 1
include ../../lib.mk

TOOLSDIR := $(top_srcdir)/tools
BPFDIR := $(TOOLSDIR)/lib/bpf
BPFTOOLDIR := $(TOOLSDIR)/bpf/bpftool
SCRATCH_DIR := $(OUTPUT)/tools
BUILD_DIR := $(SCRATCH_DIR)/build
INCLUDE_DIR := $(SCRATCH_DIR)/include
BPFOBJ := $(BUILD_DIR)/libbpf/libbpf.a

ifneq ($(CROSS_COMPILE),)
HOST_BUILD_DIR := $(BUILD_DIR)/host
HOST_SCRATCH_DIR := $(OUTPUT)/host-tools
HOST_INCLUDE_DIR := $(HOST_SCRATCH_DIR)/include
else
HOST_BUILD_DIR := $(BUILD_DIR)
HOST_SCRATCH_DIR := $(SCRATCH_DIR)
HOST_INCLUDE_DIR := $(INCLUDE_DIR)
endif

HOST_BPFOBJ := $(HOST_BUILD_DIR)/libbpf/libbpf.a
DEFAULT_BPFTOOL := $(HOST_SCRATCH_DIR)/sbin/bpftool
BPFTOOL ?= $(DEFAULT_BPFTOOL)
CLANG ?= clang

VMLINUX_BTF_PATHS ?= $(if $(O),$(O)/vmlinux) \
		     $(if $(KBUILD_OUTPUT),$(KBUILD_OUTPUT)/vmlinux) \
		     ../../../../../vmlinux \
		     /sys/kernel/btf/vmlinux \
		     /boot/vmlinux-$(shell uname -r)
VMLINUX_BTF ?= $(abspath $(firstword $(wildcard $(VMLINUX_BTF_PATHS))))
ifeq ($(VMLINUX_BTF),)
$(error Cannot find vmlinux BTF at any of "$(VMLINUX_BTF_PATHS)")
endif

MAKE_DIRS := $(sort $(BUILD_DIR)/libbpf $(HOST_BUILD_DIR)/libbpf \
	       $(HOST_BUILD_DIR)/bpftool $(INCLUDE_DIR))
$(MAKE_DIRS):
	$(call msg,MKDIR,,$@)
	$(Q)mkdir -p $@

$(BPFOBJ): $(wildcard $(BPFDIR)/*.[ch] $(BPFDIR)/Makefile) \
	   | $(BUILD_DIR)/libbpf
	$(Q)$(MAKE) $(submake_extras) -C $(BPFDIR) \
		OUTPUT=$(BUILD_DIR)/libbpf/ EXTRA_CFLAGS='-g -O0' \
		DESTDIR=$(SCRATCH_DIR) prefix= all install_headers

ifneq ($(BPFOBJ),$(HOST_BPFOBJ))
$(HOST_BPFOBJ): $(wildcard $(BPFDIR)/*.[ch] $(BPFDIR)/Makefile) \
		| $(HOST_BUILD_DIR)/libbpf
	$(Q)$(MAKE) $(submake_extras) -C $(BPFDIR) ARCH= CROSS_COMPILE= \
		OUTPUT=$(HOST_BUILD_DIR)/libbpf/ CC=$(HOSTCC) LD=$(HOSTLD) \
		DESTDIR=$(HOST_SCRATCH_DIR) prefix= all install_headers
endif

$(DEFAULT_BPFTOOL): $(wildcard $(BPFTOOLDIR)/*.[ch] \
			       $(BPFTOOLDIR)/Makefile) $(HOST_BPFOBJ) \
			       | $(HOST_BUILD_DIR)/bpftool
	$(Q)$(MAKE) $(submake_extras) -C $(BPFTOOLDIR) ARCH= CROSS_COMPILE= \
		CC=$(HOSTCC) LD=$(HOSTLD) EXTRA_CFLAGS='-g -O0' \
		OUTPUT=$(HOST_BUILD_DIR)/bpftool/ \
		LIBBPF_OUTPUT=$(HOST_BUILD_DIR)/libbpf/ \
		LIBBPF_DESTDIR=$(HOST_SCRATCH_DIR)/ prefix= \
		DESTDIR=$(HOST_SCRATCH_DIR)/ install-bin

$(INCLUDE_DIR)/vmlinux.h: $(VMLINUX_BTF) $(BPFTOOL) | $(INCLUDE_DIR)
	$(call msg,GEN,,$@)
	$(Q)$(BPFTOOL) btf dump file $(VMLINUX_BTF) format c > $@

define get_sys_includes
$(shell $(1) -v -E - </dev/null 2>&1 \
	| sed -n '/<...> search starts here:/,/End of search list./{ s| \(/.*\)|-idirafter \1|p }')
endef

IS_LITTLE_ENDIAN := $(shell $(CC) -dM -E - </dev/null | \
	grep 'define __BYTE_ORDER__ __ORDER_LITTLE_ENDIAN__')
MENDIAN := $(if $(IS_LITTLE_ENDIAN),-mlittle-endian,-mbig-endian)
BPF_CFLAGS := -g -Werror -D__TARGET_ARCH_$(SRCARCH) $(MENDIAN) \
	-Wno-microsoft-anon-tag -fms-extensions -I$(INCLUDE_DIR) \
	$(call get_sys_includes,$(CLANG))

$(OUTPUT)/file_range_cred.bpf.o: file_range_cred.bpf.c \
				       $(INCLUDE_DIR)/vmlinux.h $(BPFOBJ) \
				       | $(OUTPUT)
	$(call msg,CLNG-BPF,,$@)
	$(Q)$(CLANG) $(BPF_CFLAGS) -O2 --target=bpf -c $< -mcpu=v3 -o $@

$(OUTPUT)/file_range_cred.skel.h: $(OUTPUT)/file_range_cred.bpf.o \
					 $(BPFTOOL) | $(OUTPUT)
	$(call msg,GEN-SKEL,,$@)
	$(Q)$(BPFTOOL) gen skeleton $< name file_range_cred > $@

$(OUTPUT)/file_range_test.o: file_range_test.c \
				   $(OUTPUT)/file_range_cred.skel.h $(BPFOBJ)
	$(call msg,CC,,$@)
	$(Q)$(CC) $(CFLAGS) -c $< -o $@

$(OUTPUT)/file_range_test: $(OUTPUT)/file_range_test.o $(BPFOBJ)
	$(call msg,BINARY,,$@)
	$(Q)$(LINK.c) $^ $(LDLIBS) -o $@

EXTRA_CLEAN := $(SCRATCH_DIR) $(HOST_SCRATCH_DIR) \
	$(OUTPUT)/file_range_test.o $(OUTPUT)/file_range_cred.bpf.o \
	$(OUTPUT)/file_range_cred.skel.h
