#!/bin/bash

# KGuard Kernel Module Syntax Test Script
# This script performs basic syntax validation without requiring Linux kernel headers

echo "KGuard Kernel Module Syntax Test"
echo "================================="

# Check if source files exist
echo "Checking source files..."
for file in src/kguard.h src/kguard_main.c src/kguard_buffer.c src/kguard_netfilter.c src/kguard_proc.c; do
    if [ -f "$file" ]; then
        echo "✓ $file exists"
    else
        echo "✗ $file missing"
        exit 1
    fi
done

# Check basic C syntax using gcc (if available)
if command -v gcc >/dev/null 2>&1; then
    echo ""
    echo "Performing basic syntax checks..."
    
    # Create a minimal test that includes our headers
    cat > test_compile.c << 'EOF'
// Minimal Linux kernel definitions for syntax testing
#define __KERNEL__
#define MODULE

// Mock kernel types and functions for syntax checking
typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long long u64;
typedef unsigned long long ktime_t;

#define KERN_INFO ""
#define KERN_DEBUG ""
#define KERN_WARNING ""
#define KERN_ERR ""
#define printk(fmt, ...) printf(fmt, ##__VA_ARGS__)

#define GFP_KERNEL 0
#define ENOMEM 12
#define EINVAL 22

#define IPPROTO_TCP 6
#define IPPROTO_UDP 17
#define IPPROTO_ICMP 1

#define PF_INET 2
#define NF_INET_PRE_ROUTING 0
#define NF_IP_PRI_FIRST -400
#define NF_ACCEPT 1

#define MODULE_LICENSE(x)
#define MODULE_DESCRIPTION(x)
#define MODULE_AUTHOR(x)
#define MODULE_VERSION(x)
#define module_init(x)
#define module_exit(x)

// Mock structures
struct sk_buff { int len; void *data; };
struct iphdr { u8 protocol; u32 saddr; u32 daddr; };
struct tcphdr { u16 source; u16 dest; u8 syn:1; u8 ack:1; u8 fin:1; u8 rst:1; };
struct udphdr { u16 source; u16 dest; };
struct nf_hook_state {};
struct nf_hook_ops { void *hook; int pf; int hooknum; int priority; };
struct proc_dir_entry {};
struct seq_file {};
struct inode {};
struct file {};
struct proc_ops { void *proc_open; void *proc_read; void *proc_lseek; void *proc_release; };

// Mock functions
static inline void *kmalloc(size_t size, int flags) { return malloc(size); }
static inline void kfree(void *ptr) { free(ptr); }
static inline void *memcpy(void *dest, const void *src, size_t n) { return dest; }
static inline void *memset(void *s, int c, size_t n) { return s; }
static inline u64 ktime_get_ns(void) { return 0; }
static inline struct iphdr *ip_hdr(struct sk_buff *skb) { return NULL; }
static inline struct tcphdr *tcp_hdr(struct sk_buff *skb) { return NULL; }
static inline struct udphdr *udp_hdr(struct sk_buff *skb) { return NULL; }
static inline u32 ntohl(u32 x) { return x; }
static inline u16 ntohs(u16 x) { return x; }

// Include standard headers first
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>

// Include our header
#include "src/kguard.h"

int main() {
    printf("Syntax test passed!\n");
    return 0;
}
EOF

    # Try to compile the test
    if gcc -I. -c test_compile.c -o test_compile.o 2>/dev/null; then
        echo "✓ Basic syntax validation passed"
        rm -f test_compile.o
    else
        echo "✗ Syntax errors detected"
        gcc -I. -c test_compile.c 2>&1 | head -10
    fi
    
    rm -f test_compile.c
else
    echo "gcc not available, skipping syntax check"
fi

echo ""
echo "Checking Makefile..."
if [ -f "Makefile" ]; then
    echo "✓ Makefile exists"
    echo "✓ Makefile targets:"
    grep "^[a-zA-Z].*:" Makefile | sed 's/:.*$//' | sed 's/^/  - /'
else
    echo "✗ Makefile missing"
fi

echo ""
echo "Module structure validation complete!"
echo ""
echo "To build on a Linux system with kernel headers:"
echo "  make clean"
echo "  make"
echo "  sudo make install"