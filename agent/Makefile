# kguard-agent: collects KGuard events (kernel module or eBPF) and ships them
# to the backend.
#
#   make            build build/kguard-agent
#   make clean
#
# Needs: clang (BPF target), bpftool, libbpf-dev, libelf-dev, zlib1g-dev,
# libcurl4-openssl-dev.

CC        ?= cc
CLANG     ?= clang
BPFTOOL   ?= $(firstword $(wildcard /usr/lib/linux-tools/*/bpftool) $(shell command -v bpftool))
ARCH      := $(shell uname -m | sed 's/x86_64/x86/; s/aarch64/arm64/')
UAPI      := ../kernel/include/uapi
BUILD     := build

CFLAGS    ?= -O2 -g
CFLAGS    += -Wall -Wextra -Werror -std=gnu11 -I$(UAPI) -I$(BUILD) -Isrc
LDLIBS    := -lbpf -lelf -lz -lcurl -lpthread

SRCS      := $(wildcard src/*.c)
OBJS      := $(patsubst src/%.c,$(BUILD)/%.o,$(SRCS))

all: $(BUILD)/kguard-agent

$(BUILD):
	mkdir -p $@

# eBPF object and its libbpf skeleton
$(BUILD)/kguard.bpf.o: bpf/kguard.bpf.c $(UAPI)/linux/kguard.h | $(BUILD)
	$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) -Wall -Werror \
		-I$(UAPI) -I/usr/include/$(shell uname -m)-linux-gnu -c $< -o $@

$(BUILD)/kguard.skel.h: $(BUILD)/kguard.bpf.o
	$(BPFTOOL) gen skeleton $< name kguard_bpf > $@

$(BUILD)/%.o: src/%.c src/agent.h $(BUILD)/kguard.skel.h | $(BUILD)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD)/kguard-agent: $(OBJS)
	$(CC) $(CFLAGS) $^ -o $@ $(LDLIBS)

clean:
	rm -rf $(BUILD)

.PHONY: all clean
