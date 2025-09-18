# KGuard Deployment Guide

This guide provides step-by-step instructions for deploying KGuard in development and production environments.

## Prerequisites

### System Requirements
- Linux system (Ubuntu 20.04+ recommended)
- Kernel headers installed: `sudo apt install linux-headers-$(uname -r)`
- Docker and Docker Compose
- Build tools: `sudo apt install build-essential`
- Python 3.9+
- Node.js 18+

### Hardware Requirements
- **Minimum**: 2 CPU cores, 4GB RAM, 20GB disk
- **Recommended**: 4 CPU cores, 8GB RAM, 50GB disk
- **Production**: 8+ CPU cores, 16GB+ RAM, 100GB+ disk

## Quick Start (Development)

1. **Clone and Setup**
   ```bash
   git clone <repository-url>
   cd kguard
   make setup
   ```

2. **Build Kernel Module**
   ```bash
   cd kernel
   make clean && make
   ```

3. **Start Services**
   ```bash
   make dev
   ```

4. **Load Kernel Module**
   ```bash
   sudo make install
   ```

5. **Access Dashboard**
   - Frontend: http://localhost:3000
   - Backend API: http://localhost:8000
   - API Docs: http://localhost:8000/docs

## Production Deployment

### 1. Environment Preparation

```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install dependencies
sudo apt install -y linux-headers-$(uname -r) build-essential docker.io docker-compose

# Add user to docker group
sudo usermod -aG docker $USER
newgrp docker

# Clone repository
git clone <repository-url>
cd kguard
```

### 2. Configuration

```bash
# Copy environment files
cp backend/.env.example backend/.env
cp frontend/.env.example frontend/.env

# Edit configuration
nano backend/.env
nano frontend/.env
```

**Important Configuration Changes:**
- Set `SECRET_KEY` to a secure random string
- Configure `ALLOWED_ORIGINS` for your domain
- Set `DEBUG=false` for production
- Configure database settings if using external DB

### 3. Build and Deploy

```bash
# Build kernel module
cd kernel
make clean && make
cd ..

# Build and start production services
docker-compose -f docker-compose.prod.yml up -d

# Load kernel module
sudo make install
```

### 4. SSL/TLS Setup (Recommended)

```bash
# Install certbot
sudo apt install certbot

# Get SSL certificate
sudo certbot certonly --standalone -d your-domain.com

# Copy certificates to nginx directory
sudo mkdir -p nginx/ssl
sudo cp /etc/letsencrypt/live/your-domain.com/fullchain.pem nginx/ssl/
sudo cp /etc/letsencrypt/live/your-domain.com/privkey.pem nginx/ssl/

# Update nginx configuration for HTTPS
# Edit frontend/nginx.conf to add SSL configuration
```

### 5. Firewall Configuration

```bash
# Allow necessary ports
sudo ufw allow 22    # SSH
sudo ufw allow 80    # HTTP
sudo ufw allow 443   # HTTPS
sudo ufw enable
```

## Monitoring and Maintenance

### Health Checks

```bash
# Check system status
make status

# View logs
make logs

# Check kernel module
lsmod | grep kguard
cat /proc/kguard

# Check services
docker-compose ps
```

### Log Management

```bash
# View application logs
docker-compose logs -f backend
docker-compose logs -f frontend

# View kernel logs
dmesg | grep kguard

# Rotate logs (setup logrotate)
sudo nano /etc/logrotate.d/kguard
```

### Database Maintenance

```bash
# Backup database
docker-compose exec backend python -c "
from app.database import engine
import sqlite3
import shutil
shutil.copy('/app/data/kguard.db', '/app/data/kguard_backup.db')
"

# Cleanup old data
curl -X DELETE "http://localhost:8000/api/events/cleanup?days=30"
curl -X DELETE "http://localhost:8000/api/alerts/cleanup?days=90"
```

### Performance Tuning

1. **Kernel Module Optimization**
   ```bash
   # Adjust buffer size in kernel/src/kguard.h
   #define KGUARD_BUFFER_SIZE 2048  # Increase for high traffic
   
   # Rebuild and reload
   cd kernel && make clean && make
   sudo rmmod kguard && sudo insmod kguard.ko
   ```

2. **Backend Optimization**
   ```bash
   # Increase worker processes in production
   # Edit backend/Dockerfile CMD line:
   CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "8"]
   ```

3. **Database Optimization**
   ```bash
   # For high-volume environments, consider PostgreSQL
   # Update DATABASE_URL in backend/.env
   DATABASE_URL=postgresql://user:pass@localhost/kguard
   ```

## Troubleshooting

### Common Issues

1. **Kernel Module Won't Load**
   ```bash
   # Check kernel headers
   ls /lib/modules/$(uname -r)/build
   
   # Check compilation errors
   cd kernel && make clean && make
   
   # Check dmesg for errors
   dmesg | tail -20
   ```

2. **No Data in /proc/kguard**
   ```bash
   # Check if module is loaded
   lsmod | grep kguard
   
   # Check permissions
   ls -la /proc/kguard
   
   # Generate test traffic
   ping -c 5 8.8.8.8
   cat /proc/kguard
   ```

3. **Backend Connection Issues**
   ```bash
   # Check backend health
   curl http://localhost:8000/api/health
   
   # Check database connection
   curl http://localhost:8000/api/health/database
   
   # Check kernel module connection
   curl http://localhost:8000/api/health/kernel
   ```

4. **Frontend Not Loading**
   ```bash
   # Check if backend is accessible
   curl http://localhost:8000/api/health
   
   # Check CORS configuration
   # Verify ALLOWED_ORIGINS in backend/.env
   
   # Check browser console for errors
   ```

### Performance Issues

1. **High CPU Usage**
   ```bash
   # Check if kernel module is processing too many packets
   cat /proc/kguard | wc -l
   
   # Reduce collection frequency
   # Edit DATA_COLLECTION_INTERVAL in backend/.env
   ```

2. **Memory Issues**
   ```bash
   # Monitor memory usage
   free -h
   docker stats
   
   # Cleanup old data more frequently
   # Reduce buffer sizes if needed
   ```

3. **Database Performance**
   ```bash
   # Check database size
   ls -lh backend/data/kguard.db
   
   # Run cleanup more frequently
   # Consider database optimization
   ```

## Security Considerations

### Production Security Checklist

- [ ] Change default SECRET_KEY
- [ ] Set DEBUG=false
- [ ] Configure proper CORS origins
- [ ] Enable HTTPS with valid certificates
- [ ] Set up firewall rules
- [ ] Regular security updates
- [ ] Monitor for suspicious activity
- [ ] Backup data regularly
- [ ] Use strong passwords/keys
- [ ] Limit SSH access

### Network Security

```bash
# Monitor KGuard itself for anomalies
# Set up log monitoring
# Configure intrusion detection
# Regular security audits
```

## Scaling

### Horizontal Scaling

For high-traffic environments:

1. **Load Balancer Setup**
   ```bash
   # Use nginx or HAProxy for load balancing
   # Multiple backend instances
   # Shared database
   ```

2. **Database Scaling**
   ```bash
   # PostgreSQL with read replicas
   # Database connection pooling
   # Partitioning for large tables
   ```

3. **Monitoring Scaling**
   ```bash
   # Multiple kernel modules on different interfaces
   # Distributed data collection
   # Centralized analysis
   ```

## Backup and Recovery

### Automated Backups

```bash
#!/bin/bash
# backup-kguard.sh
DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_DIR="/backup/kguard"

# Create backup directory
mkdir -p $BACKUP_DIR

# Backup database
docker-compose exec -T backend python -c "
import shutil
shutil.copy('/app/data/kguard.db', '/app/data/kguard_${DATE}.db')
"

# Backup configuration
tar -czf $BACKUP_DIR/config_${DATE}.tar.gz backend/.env frontend/.env

# Cleanup old backups (keep 30 days)
find $BACKUP_DIR -name "*.db" -mtime +30 -delete
find $BACKUP_DIR -name "*.tar.gz" -mtime +30 -delete
```

### Recovery Procedures

```bash
# Stop services
docker-compose down

# Restore database
cp /backup/kguard/kguard_YYYYMMDD_HHMMSS.db backend/data/kguard.db

# Restore configuration
tar -xzf /backup/kguard/config_YYYYMMDD_HHMMSS.tar.gz

# Restart services
docker-compose up -d
```

## Support

For issues and questions:
1. Check the troubleshooting section above
2. Review application logs
3. Check system health endpoints
4. Consult the documentation
5. Create an issue in the repository

## Updates

### Updating KGuard

```bash
# Stop services
docker-compose down

# Backup current installation
./backup-kguard.sh

# Pull updates
git pull origin main

# Rebuild and restart
docker-compose build
docker-compose up -d

# Update kernel module if needed
cd kernel && make clean && make
sudo rmmod kguard && sudo insmod kguard.ko
```