# KGuard Kernel Module Makefile

obj-m += kguard.o
kguard-objs := src/kguard_main.o src/kguard_ring.o src/kguard_dev.o \
	       src/kguard_proc.o src/kguard_netfilter.o src/kguard_genl.o \
	       src/kguard_stats.o src/kguard_track.o src/kguard_guard.o

# KGuard's UAPI header and the tracepoint header (TRACE_INCLUDE_PATH .)
ccflags-y += -I$(src)/include -I$(src)/src

# Treat every compiler warning in KGuard's own code as an error
ccflags-y += -Werror

# Kernel build directory (override with: make KDIR=/path/to/kernel/build)
KDIR ?= /lib/modules/$(shell uname -r)/build

# Current directory
PWD := $(shell pwd)

# Default target
all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

# Clean target
clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
	rm -f src/*.o tools/kguard_reader

# Kernel coding-style check (checkpatch.pl ships with the kernel headers).
# kguard_trace.h is left out: TRACE_EVENT() blocks follow the tracing
# subsystem's own layout, which checkpatch's generic rules flag.
CHECKPATCH ?= $(KDIR)/scripts/checkpatch.pl
CHECKPATCH_FILES := $(filter-out src/kguard_trace.h,$(wildcard src/*.c src/*.h)) \
		    $(wildcard include/uapi/linux/*.h)
checkpatch:
	perl $(CHECKPATCH) --no-tree --strict --terse -f $(CHECKPATCH_FILES)

# sparse (make C=2): type, address-space and endianness checks on every
# source file. Fails on any warning (sparse itself never fails the build).
sparse:
	@$(MAKE) -C $(KDIR) M=$(PWD) C=2 modules > sparse.log 2>&1; status=$$?; cat sparse.log; \
		if [ $$status -ne 0 ]; then echo "sparse: the build failed"; exit $$status; fi
	@if grep -E "^[^ ]+\.[ch]:[0-9]+:[0-9]+: (warning|error):" sparse.log; then exit 1; fi
	@echo "sparse: no warnings"

# smatch (https://github.com/error27/smatch) with the kernel checks: any
# warning or error in our files fails. SMATCH=/path/to/smatch if not on PATH.
# Objects are cleaned first so that every file is checked.
SMATCH ?= smatch
smatch:
	@$(MAKE) -C $(KDIR) M=$(PWD) clean >/dev/null
	@$(MAKE) -C $(KDIR) M=$(PWD) C=2 CHECK="$(SMATCH) -p=kernel" modules > smatch.log 2>&1; status=$$?; \
		cat smatch.log; if [ $$status -ne 0 ]; then echo "smatch: the build failed"; exit $$status; fi
	@test $$(grep -c "CHECK " smatch.log) -gt 0 || { echo "smatch: no file was checked"; exit 1; }
	@if grep -E "^$(PWD)/[^ ]+\.[ch]:[0-9]+ .*(warn|error):" smatch.log; then exit 1; fi
	@echo "smatch: no warnings ($$(grep -c "CHECK " smatch.log) files checked)"

# kselftest-style tests (TAP): device, Netlink commands, blocking. Run as
# root with the module loaded: tests/selftests/kguard_test
selftest: tests/selftests/kguard_test
tests/selftests/kguard_test: tests/selftests/kguard_test.c include/uapi/linux/kguard.h
	$(CC) -O2 -Wall -Wextra -Werror -Iinclude/uapi -o $@ $<

# libFuzzer harness for the shared TCP options parser (ASan + UBSan)
fuzz: tests/fuzz/tcp_options_fuzz
tests/fuzz/tcp_options_fuzz: tests/fuzz/tcp_options_fuzz.c src/kguard_parse.h include/uapi/linux/kguard.h
	clang -g -O1 -fsanitize=fuzzer,address,undefined -fno-sanitize-recover=all \
		-Iinclude -Iinclude/uapi -Isrc -o $@ $<

# User-space tools: the zero-copy mmap reader (kguardctl.py needs no build)
tools: tools/kguard_reader
tools/kguard_reader: tools/kguard_reader.c include/uapi/linux/kguard.h
	$(CC) -O2 -Wall -Wextra -Werror -I include/uapi -o $@ $<

# Install target (requires root). insmod does not load dependencies, so
# load the conntrack and socket-lookup modules first.
install: all
	sudo modprobe -a nf_conntrack nf_socket_ipv4 nf_socket_ipv6
	sudo insmod kguard.ko

# Uninstall target (requires root)
uninstall:
	sudo rmmod kguard

# Check if module is loaded
status:
	lsmod | grep kguard || echo "KGuard module not loaded"

# View kernel logs
logs:
	dmesg | tail -20 | grep -i kguard

# Help target
help:
	@echo "KGuard Kernel Module Build System"
	@echo ""
	@echo "Targets:"
	@echo "  all       - Build the kernel module"
	@echo "  clean     - Clean build artifacts"
	@echo "  checkpatch - Check kernel coding style (KDIR or CHECKPATCH must point to it)"
	@echo "  tools     - Build the user-space mmap reader (tools/kguard_reader)"
	@echo "  install   - Load the kernel module (requires root)"
	@echo "  uninstall - Unload the kernel module (requires root)"
	@echo "  status    - Check if module is loaded"
	@echo "  logs      - View recent kernel logs for KGuard"
	@echo "  help      - Show this help message"

.PHONY: all clean checkpatch sparse smatch selftest fuzz tools install uninstall status logs help