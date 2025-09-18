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
```

## Usage

### Loading the Module

```bash
# Load the module (requires root)
sudo make install
# or
sudo insmod kguard.ko

# Verify module is loaded
make status
# or
lsmod | grep kguard
```

### Reading Data

```bash
# Read captured network events
cat /proc/kguard

# Monitor in real-time
tail -f /proc/kguard
```

### Unloading the Module

```bash
# Unload the module (requires root)
sudo make uninstall
# or
sudo rmmod kguard
```

## Data Format

The module outputs JSON-formatted network events:

```json
{
  "timestamp": 1635789123456789,
  "src_ip": "192.168.1.100",
  "dst_ip": "10.0.0.1",
  "src_port": 45678,
  "dst_port": 80,
  "protocol": "TCP",
  "flags": 2
}
```

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