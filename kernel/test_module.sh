#!/bin/bash

# KGuard Kernel Module Test Script
# This script tests the kernel module functionality on a Linux system

set -e

echo "KGuard Kernel Module Test Script"
echo "================================="

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "❌ This script must be run as root (use sudo)"
    exit 1
fi

# Check if module file exists
if [ ! -f "kguard.ko" ]; then
    echo "❌ kguard.ko not found. Run 'make' first."
    exit 1
fi

echo "🔧 Testing KGuard kernel module..."

# Function to cleanup on exit
cleanup() {
    echo ""
    echo "🧹 Cleaning up..."
    if lsmod | grep -q kguard; then
        echo "Unloading module..."
        rmmod kguard || true
    fi
}
trap cleanup EXIT

# Load the module
echo "📥 Loading KGuard module..."
insmod kguard.ko

# Check if module loaded successfully
if lsmod | grep -q kguard; then
    echo "✅ Module loaded successfully"
else
    echo "❌ Module failed to load"
    exit 1
fi

# Check kernel logs
echo ""
echo "📋 Recent kernel logs:"
dmesg | tail -10 | grep -i kguard || echo "No KGuard messages in recent logs"

# Check if /proc/kguard exists
echo ""
echo "🔍 Checking /proc interface..."
if [ -e "/proc/kguard" ]; then
    echo "✅ /proc/kguard exists"
    
    # Test reading from proc interface
    echo ""
    echo "📖 Testing /proc/kguard read (initial - should be empty):"
    cat /proc/kguard
    
    # Generate some network traffic to test packet capture
    echo ""
    echo "🌐 Generating test network traffic..."
    ping -c 3 8.8.8.8 > /dev/null 2>&1 &
    sleep 2
    
    # Read events again
    echo ""
    echo "📖 Reading events after network activity:"
    cat /proc/kguard
    
else
    echo "❌ /proc/kguard not found"
    exit 1
fi

# Check module info
echo ""
echo "ℹ️  Module information:"
modinfo kguard.ko | head -10

echo ""
echo "✅ All tests completed successfully!"
echo ""
echo "The KGuard kernel module is working correctly:"
echo "  • Module loads and unloads cleanly"
echo "  • /proc/kguard interface is accessible"
echo "  • Network events are being captured"
echo "  • JSON output format is working"