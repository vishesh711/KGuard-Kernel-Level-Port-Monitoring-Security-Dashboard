# KGuard: Kernel-Level Port Monitoring & Security Dashboard

KGuard is a comprehensive security monitoring solution that combines Linux kernel programming with modern web development. It provides real-time network traffic monitoring, port scanning detection, and security analytics through a kernel module that captures network packets and feeds data to a web-based dashboard.

## Architecture

- **Kernel Module**: Low-level packet capture using Netfilter hooks
- **Backend API**: FastAPI service with SQLite database and real-time WebSocket streaming
- **Frontend Dashboard**: React-based visualization with real-time charts and alerts
- **Deployment**: Containerized with Docker and docker-compose

## Project Structure

```
kguard/
├── kernel/                 # Linux kernel module
│   ├── src/
│   ├── Makefile
│   └── README.md
├── backend/                # FastAPI backend service
│   ├── app/
│   ├── tests/
│   ├── requirements.txt
│   ├── Dockerfile
│   └── README.md
├── frontend/               # React dashboard
│   ├── src/
│   ├── public/
│   ├── package.json
│   ├── Dockerfile
│   └── README.md
├── docker-compose.yml      # Development orchestration
├── docker-compose.prod.yml # Production orchestration
└── docs/                   # Documentation
```

## Quick Start

### Prerequisites

- Linux system with kernel headers installed
- Docker and docker-compose
- Python 3.9+
- Node.js 18+

### Development Setup

1. Clone the repository
2. Set up kernel development environment:
   ```bash
   sudo apt install linux-headers-$(uname -r) build-essential
   ```
3. Start the development environment:
   ```bash
   docker-compose up -d
   ```

## Security Notice

This project includes a Linux kernel module that requires root privileges to load. Only use in controlled environments and review the code thoroughly before deployment.

## License

GPL v2 (required for Linux kernel modules)