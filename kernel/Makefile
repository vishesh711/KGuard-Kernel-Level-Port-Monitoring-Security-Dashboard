# KGuard Kernel Module Makefile

obj-m += kguard.o
kguard-objs := src/kguard_main.o src/kguard_netfilter.o src/kguard_proc.o src/kguard_buffer.o

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
	rm -f src/*.o

# Kernel coding-style check (checkpatch.pl ships with the kernel headers)
CHECKPATCH ?= $(KDIR)/scripts/checkpatch.pl
checkpatch:
	perl $(CHECKPATCH) --no-tree --strict --terse -f src/*.c src/*.h

# Install target (requires root)
install: all
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
	@echo "  install   - Load the kernel module (requires root)"
	@echo "  uninstall - Unload the kernel module (requires root)"
	@echo "  status    - Check if module is loaded"
	@echo "  logs      - View recent kernel logs for KGuard"
	@echo "  help      - Show this help message"

.PHONY: all clean checkpatch install uninstall status logs help