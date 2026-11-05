# KGuard Kernel Module

The KGuard kernel module provides low-level network packet monitoring using Linux Netfilter hooks. It captures network traffic metadata and exposes it to user-space applications through the `/proc/kguard` interface.

## Features

- Netfilter hook integration for packet interception
- Circular buffer for efficient event storage
- /proc filesystem interface for user-space access
- Thread-safe operations for concurrent access
- Comprehensive error handling and logging

## Building

### Prerequisites

```bash
# Install kernel headers and build tools
sudo apt install linux-headers-$(uname -r) build-essential

# Verify kernel headers are available
ls /lib/modules/$(uname -r)/build
```

### Compilation

```bash
# Build the module
make

# Clean build artifacts
make clean

# Build against a different kernel tree
make KDIR=/path/to/kernel/build

# Check kernel coding style (strict checkpatch)
make checkpatch
```

The build treats every compiler warning as an error.

## Usage

### Loading the Module

```bash
# Load the module (requires root)
sudo make install
# or
sudo insmod kguard.ko

# Choose how many events the buffer holds (64 to 1048576, default 65536)
sudo insmod kguard.ko buffer_size=262144

# Verify module is loaded
make status
# or
lsmod | grep kguard
```

### Reading Data

```bash
# Read and remove the queued network events (root only)
sudo cat /proc/kguard
```

Reading `/proc/kguard` **removes** the events it returns, so only one program
should read it: normally the KGuard backend. Each open takes every queued event
into a private copy, so an event is never lost part-way through a read.

The file is readable by root only (mode 0400), because reading it consumes
events. To let one non-root reader in (for example the backend's Docker
container, which runs as an unprivileged user), load the module with a group
ID; the file then becomes 0440, owned by that group:

```bash
sudo insmod kguard.ko reader_gid=1500
```

The Docker Compose files add group 1500 to the backend container (override
with `KGUARD_READER_GID`).

### Module parameters

| Parameter | Default | Meaning |
|---|---|---|
| `buffer_size` | 65536 | Events the buffer can hold (64 to 1048576) |
| `reader_gid` | -1 | Group allowed to read `/proc/kguard`; -1 means root only |

### Unloading the Module

```bash
# Unload the module (requires root)
sudo make uninstall
# or
sudo rmmod kguard
```

## Data Format

Each read returns one JSON document, with one event per line:

```json
{"dropped": 0, "events": [
{"timestamp": 1762380000123456789, "src_ip": "192.168.1.100", "dst_ip": "10.0.0.1", "src_port": 45678, "dst_port": 80, "protocol": "TCP", "flags": 2}
]}
```

| Field | Meaning |
|---|---|
| `dropped` | Events overwritten because the buffer was full, since the module loaded. Above 0 means raise `buffer_size` or read more often. |
| `timestamp` | Wall-clock time in nanoseconds since the Unix epoch |
| `protocol` | `TCP`, `UDP`, `ICMP` or `OTHER` |
| `flags` | TCP flags: FIN `0x01`, SYN `0x02`, RST `0x04`, PSH `0x08`, ACK `0x10`, URG `0x20` |

Ports are 0 for protocols without ports and for non-first IP fragments.

## Troubleshooting

### Common Issues

1. **Module fails to load**: Check kernel headers are installed for current kernel
2. **Permission denied**: Ensure you're running with root privileges
3. **No data in /proc/kguard**: Verify network traffic is flowing through the system

### Debugging

```bash
# View kernel logs
make logs
# or
dmesg | grep -i kguard

# Check module information
modinfo kguard.ko
```

## Security Considerations

- This module runs in kernel space with full system privileges
- Only load in controlled environments
- Review code thoroughly before production use
- Monitor system stability after loading

## Development

### File Structure

```
kernel/
├── src/
│   ├── kguard_main.c      # Module initialization and cleanup
│   ├── kguard_netfilter.c # Netfilter hook implementation
│   ├── kguard_proc.c      # /proc interface implementation
│   ├── kguard_buffer.c    # Circular buffer implementation
│   └── kguard.h           # Header file with shared definitions
├── Makefile               # Build configuration
└── README.md             # This file
```

### Adding Features

1. Modify the appropriate source file
2. Update header file if needed
3. Rebuild with `make clean && make`
4. Test thoroughly in a safe environment