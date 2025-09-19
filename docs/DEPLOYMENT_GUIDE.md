# KGuard Deployment Guide

## Table of Contents

1. [Overview](#overview)
2. [System Requirements](#system-requirements)
3. [Pre-deployment Checklist](#pre-deployment-checklist)
4. [Development Deployment](#development-deployment)
5. [Production Deployment](#production-deployment)
6. [Kubernetes Deployment](#kubernetes-deployment)
7. [Security Configuration](#security-configuration)
8. [Monitoring and Logging](#monitoring-and-logging)
9. [Backup and Recovery](#backup-and-recovery)
10. [Troubleshooting](#troubleshooting)
11. [Maintenance](#maintenance)

## Overview

KGuard is a kernel-level network security monitoring system that requires careful deployment planning due to its kernel module component and real-time processing requirements. This guide covers deployment scenarios from development to production environments.

### Deployment Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    KGuard Deployment Stack                      │
├─────────────────┬─────────────────┬─────────────────────────────┤
│   Infrastructure│   Application   │        Monitoring           │
│                 │                 │                             │
│ ┌─────────────┐ │ ┌─────────────┐ │ ┌─────────────────────────┐ │
│ │   Docker    │ │ │   Frontend  │ │ │      Prometheus         │ │
│ │ Containers  │ │ │   (React)   │ │ │      Grafana            │ │
│ └─────────────┘ │ └─────────────┘ │ │      ELK Stack          │ │
│ ┌─────────────┐ │ ┌─────────────┐ │ └─────────────────────────┘ │
│ │   Nginx     │ │ │   Backend   │ │                             │
│ │ Load Balancer│ │ │  (FastAPI)  │ │ ┌─────────────────────────┐ │
│ └─────────────┘ │ └─────────────┘ │ │      Health Checks      │ │
│ ┌─────────────┐ │ ┌─────────────┐ │ │      Alerting           │ │
│ │   Redis     │ │ │   Database  │ │ │      Log Aggregation    │ │
│ │   Cache     │ │ │  (SQLite/   │ │ └─────────────────────────┘ │
│ └─────────────┘ │ │ PostgreSQL) │ │                             │
│                 │ └─────────────┘ │                             │
│                 │ ┌─────────────┐ │                             │
│                 │ │   Kernel    │ │                             │
│                 │ │   Module    │ │                             │
│                 │ │ (kguard.ko) │ │                             │
│                 │ └─────────────┘ │                             │
└─────────────────┴─────────────────┴─────────────────────────────┘
```

## System Requirements

### Minimum Requirements

**Development Environment:**
- CPU: 2 cores
- RAM: 4GB
- Storage: 20GB
- OS: Linux (Ubuntu 20.04+ recommended)

**Production Environment:**
- CPU: 4 cores
- RAM: 8GB
- Storage: 100GB SSD
- OS: Linux (Ubuntu 20.04+ or CentOS 8+)

### Recommended Requirements

**Production Environment:**
- CPU: 8+ cores
- RAM: 16GB+
- Storage: 500GB+ SSD
- Network: 1Gbps+
- OS: Linux with kernel 5.4+

### Software Dependencies

**Required:**
- Linux kernel headers
- Docker and Docker Compose
- Build tools (gcc, make)
- Git

**Optional:**
- Kubernetes (for container orchestration)
- Prometheus/Grafana (for monitoring)
- ELK Stack (for log management)

## Pre-deployment Checklist

### System Preparation

```bash
# Update system packages
sudo apt update && sudo apt upgrade -y

# Install kernel headers
sudo apt install linux-headers-$(uname -r)

# Install build tools
sudo apt install build-essential git curl

# Install Docker
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh
sudo usermod -aG docker $USER

# Install Docker Compose
sudo curl -L "https://github.com/docker/compose/releases/download/v2.20.0/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose
```

### Network Configuration

```bash
# Configure firewall
sudo ufw allow 22    # SSH
sudo ufw allow 80    # HTTP
sudo ufw allow 443   # HTTPS
sudo ufw enable

# Verify network interfaces
ip addr show
```

### Security Preparation

```bash
# Create dedicated user
sudo useradd -m -s /bin/bash kguard
sudo usermod -aG docker kguard

# Set up SSH keys
ssh-keygen -t rsa -b 4096 -C "kguard@yourdomain.com"

# Configure sudo access
echo "kguard ALL=(ALL) NOPASSWD: /sbin/insmod, /sbin/rmmod, /sbin/modprobe" | sudo tee /etc/sudoers.d/kguard
```

## Development Deployment

### Quick Start

```bash
# Clone repository
git clone <repository-url>
cd kguard

# Setup environment
make setup

# Build kernel module
cd kernel
make clean && make
cd ..

# Start development services
make dev

# Load kernel module (in separate terminal)
sudo make install
```

### Development Environment Configuration

#### Environment Files

**backend/.env**
```bash
# API Configuration
DEBUG=true
API_HOST=0.0.0.0
API_PORT=8000
LOG_LEVEL=DEBUG

# Database
DATABASE_URL=sqlite:///./data/kguard.db

# Security (development only)
SECRET_KEY=dev-secret-key-change-in-production
ALLOWED_ORIGINS=["http://localhost:3000", "http://localhost:5173"]

# Kernel Module
PROC_KGUARD_PATH=/proc/kguard
DATA_COLLECTION_INTERVAL=1.0

# Anomaly Detection
PORT_SCAN_THRESHOLD=5
SUSPICIOUS_PORTS=[22, 23, 80, 443, 3389, 5432, 3306]
ALERT_COOLDOWN_SECONDS=60

# WebSocket
WEBSOCKET_MAX_CONNECTIONS=50
WEBSOCKET_HEARTBEAT_INTERVAL=30
```

**frontend/.env**
```bash
# API Configuration
VITE_API_BASE_URL=http://localhost:8000
VITE_WS_URL=ws://localhost:8000/ws

# Development
VITE_NODE_ENV=development
```

### Development Services

```bash
# Start all services
docker-compose up -d

# View logs
docker-compose logs -f

# Check service status
docker-compose ps

# Access services
# Frontend: http://localhost:3000
# Backend: http://localhost:8000
# API Docs: http://localhost:8000/docs
```

### Development Testing

```bash
# Test kernel module
cat /proc/kguard
dmesg | grep kguard

# Test API endpoints
curl http://localhost:8000/api/health
curl http://localhost:8000/api/events/

# Test WebSocket
wscat -c ws://localhost:8000/ws

# Generate test traffic
ping -c 10 8.8.8.8
nmap -p 1-100 localhost
```

## Production Deployment

### Production Environment Setup

#### 1. System Hardening

```bash
# Disable unnecessary services
sudo systemctl disable bluetooth
sudo systemctl disable cups

# Configure kernel parameters
echo "net.core.rmem_max = 134217728" | sudo tee -a /etc/sysctl.conf
echo "net.core.wmem_max = 134217728" | sudo tee -a /etc/sysctl.conf
echo "net.ipv4.tcp_rmem = 4096 65536 134217728" | sudo tee -a /etc/sysctl.conf
sudo sysctl -p

# Set up log rotation
sudo tee /etc/logrotate.d/kguard << EOF
/var/log/kguard/*.log {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    create 644 kguard kguard
}
EOF
```

#### 2. SSL/TLS Configuration

```bash
# Install Certbot
sudo apt install certbot

# Obtain SSL certificate
sudo certbot certonly --standalone -d your-domain.com

# Create SSL directory
sudo mkdir -p /etc/kguard/ssl
sudo cp /etc/letsencrypt/live/your-domain.com/fullchain.pem /etc/kguard/ssl/
sudo cp /etc/letsencrypt/live/your-domain.com/privkey.pem /etc/kguard/ssl/
sudo chown -R kguard:kguard /etc/kguard/ssl
sudo chmod 600 /etc/kguard/ssl/*
```

#### 3. Production Configuration

**docker-compose.prod.yml**
```yaml
version: '3.8'

services:
  backend:
    build:
      context: ./backend
      dockerfile: Dockerfile
      target: production
    restart: unless-stopped
    environment:
      - DEBUG=false
      - DATABASE_URL=postgresql://kguard:${DB_PASSWORD}@postgres:5432/kguard
      - SECRET_KEY=${SECRET_KEY}
      - LOG_LEVEL=INFO
    volumes:
      - backend_data:/app/data
      - ./logs:/app/logs
    depends_on:
      - postgres
      - redis
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8000/api/health"]
      interval: 30s
      timeout: 10s
      retries: 3
    deploy:
      resources:
        limits:
          memory: 1G
          cpus: '2'
        reservations:
          memory: 512M
          cpus: '1'

  frontend:
    build:
      context: ./frontend
      dockerfile: Dockerfile
      target: production
    restart: unless-stopped
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx/nginx.conf:/etc/nginx/nginx.conf:ro
      - /etc/kguard/ssl:/etc/nginx/ssl:ro
    depends_on:
      - backend
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost/"]
      interval: 30s
      timeout: 10s
      retries: 3

  postgres:
    image: postgres:15-alpine
    restart: unless-stopped
    environment:
      - POSTGRES_DB=kguard
      - POSTGRES_USER=kguard
      - POSTGRES_PASSWORD=${DB_PASSWORD}
    volumes:
      - postgres_data:/var/lib/postgresql/data
      - ./postgres/init.sql:/docker-entrypoint-initdb.d/init.sql
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U kguard"]
      interval: 30s
      timeout: 10s
      retries: 3

  redis:
    image: redis:7-alpine
    restart: unless-stopped
    command: redis-server --appendonly yes --requirepass ${REDIS_PASSWORD}
    volumes:
      - redis_data:/data
    healthcheck:
      test: ["CMD", "redis-cli", "--raw", "incr", "ping"]
      interval: 30s
      timeout: 10s
      retries: 3

volumes:
  backend_data:
  postgres_data:
  redis_data:

networks:
  default:
    name: kguard-production
```

**Production Environment Variables (.env.prod)**
```bash
# Generate secure secrets
SECRET_KEY=$(openssl rand -hex 32)
DB_PASSWORD=$(openssl rand -hex 16)
REDIS_PASSWORD=$(openssl rand -hex 16)

# Database
DATABASE_URL=postgresql://kguard:${DB_PASSWORD}@postgres:5432/kguard

# Security
ALLOWED_ORIGINS=["https://your-domain.com"]

# Performance
WORKERS=4
MAX_CONNECTIONS=1000
```

#### 4. Nginx Configuration

**nginx/nginx.conf**
```nginx
user nginx;
worker_processes auto;
error_log /var/log/nginx/error.log warn;
pid /var/run/nginx.pid;

events {
    worker_connections 1024;
    use epoll;
    multi_accept on;
}

http {
    include /etc/nginx/mime.types;
    default_type application/octet-stream;

    # Logging
    log_format main '$remote_addr - $remote_user [$time_local] "$request" '
                    '$status $body_bytes_sent "$http_referer" '
                    '"$http_user_agent" "$http_x_forwarded_for"';
    access_log /var/log/nginx/access.log main;

    # Performance
    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    keepalive_timeout 65;
    types_hash_max_size 2048;

    # Security headers
    add_header X-Frame-Options DENY;
    add_header X-Content-Type-Options nosniff;
    add_header X-XSS-Protection "1; mode=block";
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;

    # Gzip compression
    gzip on;
    gzip_vary on;
    gzip_min_length 1024;
    gzip_types text/plain text/css text/xml text/javascript application/javascript application/xml+rss application/json;

    # Rate limiting
    limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;
    limit_req_zone $binary_remote_addr zone=login:10m rate=1r/s;

    # Upstream backend
    upstream backend {
        server backend:8000;
        keepalive 32;
    }

    # HTTP to HTTPS redirect
    server {
        listen 80;
        server_name your-domain.com;
        return 301 https://$server_name$request_uri;
    }

    # HTTPS server
    server {
        listen 443 ssl http2;
        server_name your-domain.com;

        # SSL configuration
        ssl_certificate /etc/nginx/ssl/fullchain.pem;
        ssl_certificate_key /etc/nginx/ssl/privkey.pem;
        ssl_protocols TLSv1.2 TLSv1.3;
        ssl_ciphers ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384;
        ssl_prefer_server_ciphers off;
        ssl_session_cache shared:SSL:10m;
        ssl_session_timeout 10m;

        # Frontend static files
        location / {
            root /usr/share/nginx/html;
            index index.html;
            try_files $uri $uri/ /index.html;
            
            # Cache static assets
            location ~* \.(js|css|png|jpg|jpeg|gif|ico|svg)$ {
                expires 1y;
                add_header Cache-Control "public, immutable";
            }
        }

        # API endpoints
        location /api/ {
            limit_req zone=api burst=20 nodelay;
            
            proxy_pass http://backend;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
            
            # Timeouts
            proxy_connect_timeout 5s;
            proxy_send_timeout 60s;
            proxy_read_timeout 60s;
        }

        # WebSocket endpoint
        location /ws {
            proxy_pass http://backend;
            proxy_http_version 1.1;
            proxy_set_header Upgrade $http_upgrade;
            proxy_set_header Connection "upgrade";
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
            
            # WebSocket timeouts
            proxy_read_timeout 86400;
        }

        # Health check endpoint
        location /health {
            access_log off;
            return 200 "healthy\n";
            add_header Content-Type text/plain;
        }
    }
}
```

#### 5. Production Deployment

```bash
# Create production directory
sudo mkdir -p /opt/kguard
sudo chown kguard:kguard /opt/kguard
cd /opt/kguard

# Clone repository
git clone <repository-url> .

# Set up environment
cp .env.example .env.prod
# Edit .env.prod with production values

# Build kernel module
cd kernel
make clean && make
cd ..

# Start production services
docker-compose -f docker-compose.prod.yml up -d

# Load kernel module
sudo make install

# Verify deployment
curl -k https://your-domain.com/api/health
```

### Production Monitoring

#### Health Checks

```bash
#!/bin/bash
# health-check.sh

# Check services
docker-compose -f docker-compose.prod.yml ps

# Check kernel module
if lsmod | grep -q kguard; then
    echo "✓ Kernel module loaded"
else
    echo "✗ Kernel module not loaded"
fi

# Check API health
if curl -f -s https://your-domain.com/api/health > /dev/null; then
    echo "✓ API healthy"
else
    echo "✗ API unhealthy"
fi

# Check database
if docker-compose -f docker-compose.prod.yml exec -T postgres pg_isready -U kguard > /dev/null; then
    echo "✓ Database healthy"
else
    echo "✗ Database unhealthy"
fi
```

#### Automated Deployment Script

```bash
#!/bin/bash
# deploy.sh

set -e

DEPLOY_DIR="/opt/kguard"
BACKUP_DIR="/opt/kguard-backups"
DATE=$(date +%Y%m%d_%H%M%S)

echo "Starting KGuard deployment..."

# Create backup
echo "Creating backup..."
mkdir -p $BACKUP_DIR
tar -czf $BACKUP_DIR/kguard_backup_$DATE.tar.gz -C $DEPLOY_DIR .

# Pull latest code
echo "Pulling latest code..."
cd $DEPLOY_DIR
git pull origin main

# Build kernel module
echo "Building kernel module..."
cd kernel
make clean && make
cd ..

# Build and restart services
echo "Building and restarting services..."
docker-compose -f docker-compose.prod.yml build
docker-compose -f docker-compose.prod.yml up -d

# Reload kernel module
echo "Reloading kernel module..."
sudo rmmod kguard || true
sudo make install

# Wait for services to start
echo "Waiting for services to start..."
sleep 30

# Health check
echo "Performing health check..."
if curl -f -s https://your-domain.com/api/health > /dev/null; then
    echo "✓ Deployment successful"
else
    echo "✗ Deployment failed - rolling back"
    # Rollback logic here
    exit 1
fi

echo "Deployment completed successfully"
```

## Kubernetes Deployment

### Kubernetes Manifests

#### Namespace

```yaml
# namespace.yaml
apiVersion: v1
kind: Namespace
metadata:
  name: kguard
  labels:
    name: kguard
```

#### ConfigMap

```yaml
# configmap.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: kguard-config
  namespace: kguard
data:
  backend.env: |
    DEBUG=false
    LOG_LEVEL=INFO
    API_HOST=0.0.0.0
    API_PORT=8000
    PROC_KGUARD_PATH=/proc/kguard
    DATA_COLLECTION_INTERVAL=1.0
    PORT_SCAN_THRESHOLD=10
    ALERT_COOLDOWN_SECONDS=300
    WEBSOCKET_MAX_CONNECTIONS=100
  frontend.env: |
    VITE_API_BASE_URL=https://kguard.yourdomain.com
    VITE_WS_URL=wss://kguard.yourdomain.com/ws
```

#### Secrets

```yaml
# secrets.yaml
apiVersion: v1
kind: Secret
metadata:
  name: kguard-secrets
  namespace: kguard
type: Opaque
data:
  secret-key: <base64-encoded-secret>
  db-password: <base64-encoded-password>
  redis-password: <base64-encoded-password>
```

#### PostgreSQL Deployment

```yaml
# postgres.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: postgres
  namespace: kguard
spec:
  replicas: 1
  selector:
    matchLabels:
      app: postgres
  template:
    metadata:
      labels:
        app: postgres
    spec:
      containers:
      - name: postgres
        image: postgres:15-alpine
        env:
        - name: POSTGRES_DB
          value: kguard
        - name: POSTGRES_USER
          value: kguard
        - name: POSTGRES_PASSWORD
          valueFrom:
            secretKeyRef:
              name: kguard-secrets
              key: db-password
        ports:
        - containerPort: 5432
        volumeMounts:
        - name: postgres-storage
          mountPath: /var/lib/postgresql/data
        resources:
          requests:
            memory: "256Mi"
            cpu: "250m"
          limits:
            memory: "512Mi"
            cpu: "500m"
      volumes:
      - name: postgres-storage
        persistentVolumeClaim:
          claimName: postgres-pvc
---
apiVersion: v1
kind: Service
metadata:
  name: postgres
  namespace: kguard
spec:
  selector:
    app: postgres
  ports:
  - port: 5432
    targetPort: 5432
---
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: postgres-pvc
  namespace: kguard
spec:
  accessModes:
    - ReadWriteOnce
  resources:
    requests:
      storage: 10Gi
```

#### Backend Deployment

```yaml
# backend.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: kguard-backend
  namespace: kguard
spec:
  replicas: 3
  selector:
    matchLabels:
      app: kguard-backend
  template:
    metadata:
      labels:
        app: kguard-backend
    spec:
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
      containers:
      - name: backend
        image: kguard/backend:latest
        ports:
        - containerPort: 8000
        env:
        - name: DATABASE_URL
          value: postgresql://kguard:$(DB_PASSWORD)@postgres:5432/kguard
        - name: SECRET_KEY
          valueFrom:
            secretKeyRef:
              name: kguard-secrets
              key: secret-key
        - name: DB_PASSWORD
          valueFrom:
            secretKeyRef:
              name: kguard-secrets
              key: db-password
        envFrom:
        - configMapRef:
            name: kguard-config
        volumeMounts:
        - name: data-volume
          mountPath: /app/data
        - name: proc-kguard
          mountPath: /proc/kguard
          readOnly: true
        resources:
          requests:
            memory: "512Mi"
            cpu: "500m"
          limits:
            memory: "1Gi"
            cpu: "1000m"
        livenessProbe:
          httpGet:
            path: /api/health
            port: 8000
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /api/health
            port: 8000
          initialDelaySeconds: 5
          periodSeconds: 5
      volumes:
      - name: data-volume
        persistentVolumeClaim:
          claimName: backend-pvc
      - name: proc-kguard
        hostPath:
          path: /proc/kguard
          type: File
---
apiVersion: v1
kind: Service
metadata:
  name: kguard-backend
  namespace: kguard
spec:
  selector:
    app: kguard-backend
  ports:
  - port: 8000
    targetPort: 8000
---
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: backend-pvc
  namespace: kguard
spec:
  accessModes:
    - ReadWriteOnce
  resources:
    requests:
      storage: 5Gi
```

#### Frontend Deployment

```yaml
# frontend.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: kguard-frontend
  namespace: kguard
spec:
  replicas: 2
  selector:
    matchLabels:
      app: kguard-frontend
  template:
    metadata:
      labels:
        app: kguard-frontend
    spec:
      containers:
      - name: frontend
        image: kguard/frontend:latest
        ports:
        - containerPort: 80
        resources:
          requests:
            memory: "64Mi"
            cpu: "100m"
          limits:
            memory: "128Mi"
            cpu: "200m"
        livenessProbe:
          httpGet:
            path: /
            port: 80
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /
            port: 80
          initialDelaySeconds: 5
          periodSeconds: 5
---
apiVersion: v1
kind: Service
metadata:
  name: kguard-frontend
  namespace: kguard
spec:
  selector:
    app: kguard-frontend
  ports:
  - port: 80
    targetPort: 80
```

#### Ingress

```yaml
# ingress.yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: kguard-ingress
  namespace: kguard
  annotations:
    kubernetes.io/ingress.class: nginx
    cert-manager.io/cluster-issuer: letsencrypt-prod
    nginx.ingress.kubernetes.io/ssl-redirect: "true"
    nginx.ingress.kubernetes.io/proxy-body-size: "10m"
    nginx.ingress.kubernetes.io/proxy-read-timeout: "300"
    nginx.ingress.kubernetes.io/proxy-send-timeout: "300"
spec:
  tls:
  - hosts:
    - kguard.yourdomain.com
    secretName: kguard-tls
  rules:
  - host: kguard.yourdomain.com
    http:
      paths:
      - path: /api
        pathType: Prefix
        backend:
          service:
            name: kguard-backend
            port:
              number: 8000
      - path: /ws
        pathType: Prefix
        backend:
          service:
            name: kguard-backend
            port:
              number: 8000
      - path: /
        pathType: Prefix
        backend:
          service:
            name: kguard-frontend
            port:
              number: 80
```

#### DaemonSet for Kernel Module

```yaml
# kernel-module-daemonset.yaml
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: kguard-kernel-module
  namespace: kguard
spec:
  selector:
    matchLabels:
      name: kguard-kernel-module
  template:
    metadata:
      labels:
        name: kguard-kernel-module
    spec:
      hostPID: true
      hostNetwork: true
      containers:
      - name: kernel-module-loader
        image: kguard/kernel-module:latest
        securityContext:
          privileged: true
        volumeMounts:
        - name: lib-modules
          mountPath: /lib/modules
          readOnly: true
        - name: proc
          mountPath: /host/proc
        command:
        - /bin/sh
        - -c
        - |
          # Load kernel module
          insmod /opt/kguard/kguard.ko
          
          # Keep container running
          while true; do
            if ! lsmod | grep -q kguard; then
              echo "Kernel module not loaded, reloading..."
              insmod /opt/kguard/kguard.ko
            fi
            sleep 60
          done
        resources:
          requests:
            memory: "64Mi"
            cpu: "100m"
          limits:
            memory: "128Mi"
            cpu: "200m"
      volumes:
      - name: lib-modules
        hostPath:
          path: /lib/modules
      - name: proc
        hostPath:
          path: /proc
      tolerations:
      - key: node-role.kubernetes.io/master
        effect: NoSchedule
```

### Kubernetes Deployment Commands

```bash
# Create namespace
kubectl apply -f namespace.yaml

# Apply configurations
kubectl apply -f configmap.yaml
kubectl apply -f secrets.yaml

# Deploy database
kubectl apply -f postgres.yaml

# Deploy backend
kubectl apply -f backend.yaml

# Deploy frontend
kubectl apply -f frontend.yaml

# Deploy ingress
kubectl apply -f ingress.yaml

# Deploy kernel module DaemonSet
kubectl apply -f kernel-module-daemonset.yaml

# Check deployment status
kubectl get pods -n kguard
kubectl get services -n kguard
kubectl get ingress -n kguard

# View logs
kubectl logs -f deployment/kguard-backend -n kguard
kubectl logs -f deployment/kguard-frontend -n kguard
```

## Security Configuration

### SSL/TLS Setup

#### Let's Encrypt with Certbot

```bash
# Install Certbot
sudo apt install certbot python3-certbot-nginx

# Obtain certificate
sudo certbot --nginx -d your-domain.com

# Auto-renewal
sudo crontab -e
# Add: 0 12 * * * /usr/bin/certbot renew --quiet
```

#### Manual Certificate Setup

```bash
# Generate private key
openssl genrsa -out kguard.key 2048

# Generate certificate signing request
openssl req -new -key kguard.key -out kguard.csr

# Generate self-signed certificate (for testing)
openssl x509 -req -days 365 -in kguard.csr -signkey kguard.key -out kguard.crt
```

### Firewall Configuration

```bash
# UFW configuration
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow ssh
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw enable

# iptables configuration (alternative)
sudo iptables -A INPUT -p tcp --dport 22 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 80 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 443 -j ACCEPT
sudo iptables -A INPUT -j DROP
sudo iptables-save > /etc/iptables/rules.v4
```

### Access Control

#### JWT Authentication Setup

```python
# backend/app/auth.py
from datetime import datetime, timedelta
from jose import JWTError, jwt
from passlib.context import CryptContext

SECRET_KEY = "your-secret-key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt
```

#### Role-Based Access Control

```python
# backend/app/models/user.py
from enum import Enum

class UserRole(Enum):
    ADMIN = "admin"
    ANALYST = "analyst"
    VIEWER = "viewer"

class User(Base):
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True)
    username = Column(String(50), unique=True, nullable=False)
    email = Column(String(100), unique=True, nullable=False)
    hashed_password = Column(String(100), nullable=False)
    role = Column(Enum(UserRole), default=UserRole.VIEWER)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
```

## Monitoring and Logging

### Prometheus Configuration

```yaml
# prometheus.yml
global:
  scrape_interval: 15s

scrape_configs:
  - job_name: 'kguard-backend'
    static_configs:
      - targets: ['backend:8000']
    metrics_path: '/metrics'
    scrape_interval: 30s

  - job_name: 'kguard-system'
    static_configs:
      - targets: ['node-exporter:9100']
    scrape_interval: 30s

rule_files:
  - "kguard_rules.yml"

alerting:
  alertmanagers:
    - static_configs:
        - targets:
          - alertmanager:9093
```

### Grafana Dashboard

```json
{
  "dashboard": {
    "title": "KGuard Security Monitoring",
    "panels": [
      {
        "title": "Network Events Rate",
        "type": "graph",
        "targets": [
          {
            "expr": "rate(kguard_events_total[5m])",
            "legendFormat": "Events/sec"
          }
        ]
      },
      {
        "title": "Security Alerts",
        "type": "stat",
        "targets": [
          {
            "expr": "kguard_alerts_total",
            "legendFormat": "Total Alerts"
          }
        ]
      },
      {
        "title": "System Health",
        "type": "table",
        "targets": [
          {
            "expr": "kguard_health_status",
            "legendFormat": "Component Health"
          }
        ]
      }
    ]
  }
}
```

### ELK Stack Configuration

#### Logstash Configuration

```ruby
# logstash.conf
input {
  beats {
    port => 5044
  }
}

filter {
  if [fields][service] == "kguard-backend" {
    json {
      source => "message"
    }
    
    date {
      match => [ "timestamp", "ISO8601" ]
    }
    
    if [level] == "ERROR" {
      mutate {
        add_tag => [ "error" ]
      }
    }
  }
}

output {
  elasticsearch {
    hosts => ["elasticsearch:9200"]
    index => "kguard-%{+YYYY.MM.dd}"
  }
}
```

#### Filebeat Configuration

```yaml
# filebeat.yml
filebeat.inputs:
- type: log
  enabled: true
  paths:
    - /var/log/kguard/*.log
  fields:
    service: kguard-backend
  fields_under_root: true

output.logstash:
  hosts: ["logstash:5044"]

processors:
  - add_host_metadata:
      when.not.contains.tags: forwarded
```

### Custom Metrics

```python
# backend/app/metrics.py
from prometheus_client import Counter, Histogram, Gauge

# Metrics
events_total = Counter('kguard_events_total', 'Total network events processed')
alerts_total = Counter('kguard_alerts_total', 'Total security alerts generated', ['severity'])
processing_time = Histogram('kguard_processing_seconds', 'Time spent processing events')
active_connections = Gauge('kguard_websocket_connections', 'Active WebSocket connections')

# Usage in code
events_total.inc()
alerts_total.labels(severity='HIGH').inc()
with processing_time.time():
    # Process events
    pass
active_connections.set(len(connection_manager.active_connections))
```

## Backup and Recovery

### Database Backup

```bash
#!/bin/bash
# backup-database.sh

BACKUP_DIR="/opt/kguard-backups"
DATE=$(date +%Y%m%d_%H%M%S)
DB_NAME="kguard"

# Create backup directory
mkdir -p $BACKUP_DIR

# PostgreSQL backup
docker-compose exec -T postgres pg_dump -U kguard $DB_NAME | gzip > $BACKUP_DIR/kguard_db_$DATE.sql.gz

# SQLite backup (if using SQLite)
cp /opt/kguard/backend/data/kguard.db $BACKUP_DIR/kguard_db_$DATE.db

# Cleanup old backups (keep 30 days)
find $BACKUP_DIR -name "kguard_db_*.sql.gz" -mtime +30 -delete
find $BACKUP_DIR -name "kguard_db_*.db" -mtime +30 -delete

echo "Database backup completed: $BACKUP_DIR/kguard_db_$DATE"
```

### Configuration Backup

```bash
#!/bin/bash
# backup-config.sh

BACKUP_DIR="/opt/kguard-backups"
DATE=$(date +%Y%m%d_%H%M%S)
CONFIG_DIR="/opt/kguard"

# Backup configuration files
tar -czf $BACKUP_DIR/kguard_config_$DATE.tar.gz \
    -C $CONFIG_DIR \
    docker-compose.prod.yml \
    .env.prod \
    nginx/ \
    ssl/

echo "Configuration backup completed: $BACKUP_DIR/kguard_config_$DATE.tar.gz"
```

### Automated Backup Script

```bash
#!/bin/bash
# automated-backup.sh

set -e

BACKUP_DIR="/opt/kguard-backups"
S3_BUCKET="your-backup-bucket"
DATE=$(date +%Y%m%d_%H%M%S)

# Create local backups
./backup-database.sh
./backup-config.sh

# Upload to S3 (optional)
if command -v aws &> /dev/null; then
    aws s3 sync $BACKUP_DIR s3://$S3_BUCKET/kguard-backups/
    echo "Backups uploaded to S3"
fi

# Send notification
curl -X POST "https://hooks.slack.com/services/YOUR/SLACK/WEBHOOK" \
    -H 'Content-type: application/json' \
    --data "{\"text\":\"KGuard backup completed successfully at $DATE\"}"
```

### Recovery Procedures

#### Database Recovery

```bash
#!/bin/bash
# restore-database.sh

BACKUP_FILE=$1
DB_NAME="kguard"

if [ -z "$BACKUP_FILE" ]; then
    echo "Usage: $0 <backup_file>"
    exit 1
fi

# Stop services
docker-compose -f docker-compose.prod.yml stop backend

# Restore PostgreSQL database
gunzip -c $BACKUP_FILE | docker-compose exec -T postgres psql -U kguard -d $DB_NAME

# Restart services
docker-compose -f docker-compose.prod.yml start backend

echo "Database restored from $BACKUP_FILE"
```

#### Full System Recovery

```bash
#!/bin/bash
# full-recovery.sh

BACKUP_DATE=$1

if [ -z "$BACKUP_DATE" ]; then
    echo "Usage: $0 <backup_date>"
    echo "Example: $0 20240115_143000"
    exit 1
fi

BACKUP_DIR="/opt/kguard-backups"

# Stop all services
docker-compose -f docker-compose.prod.yml down

# Restore configuration
tar -xzf $BACKUP_DIR/kguard_config_$BACKUP_DATE.tar.gz -C /opt/kguard/

# Restore database
gunzip -c $BACKUP_DIR/kguard_db_$BACKUP_DATE.sql.gz | docker-compose exec -T postgres psql -U kguard -d kguard

# Restart services
docker-compose -f docker-compose.prod.yml up -d

# Reload kernel module
sudo rmmod kguard || true
sudo make install

echo "Full system recovery completed"
```

## Troubleshooting

### Common Issues

#### Kernel Module Issues

**Problem: Module fails to load**
```bash
# Check kernel version compatibility
uname -r
ls /lib/modules/$(uname -r)/build

# Check compilation errors
cd kernel
make clean && make

# Check system logs
dmesg | grep kguard
journalctl -f -k | grep kguard
```

**Problem: No data in /proc/kguard**
```bash
# Verify module is loaded
lsmod | grep kguard

# Check permissions
ls -la /proc/kguard

# Generate test traffic
ping -c 5 8.8.8.8
cat /proc/kguard
```

#### Docker Issues

**Problem: Container fails to start**
```bash
# Check container logs
docker-compose logs backend
docker-compose logs frontend

# Check resource usage
docker stats

# Check disk space
df -h
```

**Problem: Database connection issues**
```bash
# Check database container
docker-compose exec postgres pg_isready -U kguard

# Check network connectivity
docker-compose exec backend ping postgres

# Check environment variables
docker-compose exec backend env | grep DATABASE
```

#### Performance Issues

**Problem: High CPU usage**
```bash
# Check system resources
htop
iotop

# Check kernel module impact
cat /proc/loadavg
cat /proc/meminfo

# Monitor network traffic
iftop
nethogs
```

**Problem: Memory leaks**
```bash
# Monitor memory usage
watch -n 1 'free -h'

# Check for memory leaks in containers
docker stats --no-stream

# Check kernel memory usage
cat /proc/slabinfo | grep kguard
```

### Diagnostic Tools

#### Health Check Script

```bash
#!/bin/bash
# health-check.sh

echo "=== KGuard Health Check ==="

# Check kernel module
if lsmod | grep -q kguard; then
    echo "✓ Kernel module loaded"
    if [ -r /proc/kguard ]; then
        echo "✓ /proc/kguard accessible"
    else
        echo "✗ /proc/kguard not accessible"
    fi
else
    echo "✗ Kernel module not loaded"
fi

# Check Docker services
echo ""
echo "=== Docker Services ==="
docker-compose ps

# Check API health
echo ""
echo "=== API Health ==="
if curl -f -s http://localhost:8000/api/health > /dev/null; then
    echo "✓ API responding"
    curl -s http://localhost:8000/api/health | jq .
else
    echo "✗ API not responding"
fi

# Check database
echo ""
echo "=== Database Health ==="
if docker-compose exec -T postgres pg_isready -U kguard > /dev/null 2>&1; then
    echo "✓ Database healthy"
else
    echo "✗ Database unhealthy"
fi

# Check disk space
echo ""
echo "=== Disk Usage ==="
df -h | grep -E "(Filesystem|/dev/)"

# Check memory usage
echo ""
echo "=== Memory Usage ==="
free -h
```

#### Log Analysis Script

```bash
#!/bin/bash
# analyze-logs.sh

HOURS=${1:-1}

echo "=== Log Analysis (last $HOURS hours) ==="

# Kernel module logs
echo "Kernel module logs:"
journalctl --since="$HOURS hours ago" | grep kguard | tail -20

# Application logs
echo ""
echo "Application logs:"
docker-compose logs --since="${HOURS}h" backend | tail -20

# Error analysis
echo ""
echo "Error summary:"
docker-compose logs --since="${HOURS}h" | grep -i error | wc -l
echo "errors found in the last $HOURS hours"

# Performance metrics
echo ""
echo "Performance metrics:"
docker stats --no-stream
```

## Maintenance

### Regular Maintenance Tasks

#### Daily Tasks

```bash
#!/bin/bash
# daily-maintenance.sh

# Health check
./health-check.sh

# Log rotation
docker-compose exec backend logrotate /etc/logrotate.conf

# Database cleanup (keep 30 days of events)
curl -X DELETE "http://localhost:8000/api/events/cleanup?days=30"

# Alert cleanup (keep 90 days of resolved alerts)
curl -X DELETE "http://localhost:8000/api/alerts/cleanup?days=90"

# Backup
./backup-database.sh
```

#### Weekly Tasks

```bash
#!/bin/bash
# weekly-maintenance.sh

# Update system packages
sudo apt update && sudo apt upgrade -y

# Docker cleanup
docker system prune -f
docker volume prune -f

# Certificate renewal check
sudo certbot renew --dry-run

# Performance analysis
./analyze-logs.sh 168  # Last week
```

#### Monthly Tasks

```bash
#!/bin/bash
# monthly-maintenance.sh

# Full system backup
./backup-config.sh

# Security updates
sudo unattended-upgrades

# Log analysis and archival
find /var/log/kguard -name "*.log" -mtime +30 -exec gzip {} \;

# Performance optimization
# Analyze database performance
docker-compose exec postgres psql -U kguard -d kguard -c "ANALYZE;"

# Update Docker images
docker-compose pull
docker-compose up -d
```

### Update Procedures

#### Application Updates

```bash
#!/bin/bash
# update-application.sh

# Create backup before update
./backup-database.sh
./backup-config.sh

# Pull latest code
git pull origin main

# Build and restart services
docker-compose build
docker-compose up -d

# Update kernel module
cd kernel
make clean && make
sudo rmmod kguard
sudo make install
cd ..

# Health check
sleep 30
./health-check.sh
```

#### Security Updates

```bash
#!/bin/bash
# security-updates.sh

# Update system packages
sudo apt update && sudo apt upgrade -y

# Update Docker images
docker-compose pull

# Restart services with new images
docker-compose up -d

# Update SSL certificates
sudo certbot renew

# Restart nginx to load new certificates
docker-compose restart frontend
```

### Monitoring and Alerting

#### Automated Monitoring

```bash
#!/bin/bash
# monitoring.sh

# Check if services are running
if ! docker-compose ps | grep -q "Up"; then
    echo "ALERT: Some services are down"
    # Send notification
fi

# Check API health
if ! curl -f -s http://localhost:8000/api/health > /dev/null; then
    echo "ALERT: API is not responding"
    # Send notification
fi

# Check disk space
DISK_USAGE=$(df / | awk 'NR==2 {print $5}' | sed 's/%//')
if [ $DISK_USAGE -gt 80 ]; then
    echo "ALERT: Disk usage is ${DISK_USAGE}%"
    # Send notification
fi

# Check memory usage
MEMORY_USAGE=$(free | awk 'NR==2{printf "%.0f", $3*100/$2}')
if [ $MEMORY_USAGE -gt 90 ]; then
    echo "ALERT: Memory usage is ${MEMORY_USAGE}%"
    # Send notification
fi
```

#### Cron Jobs Setup

```bash
# Add to crontab (crontab -e)

# Health check every 5 minutes
*/5 * * * * /opt/kguard/scripts/health-check.sh >> /var/log/kguard/health.log 2>&1

# Daily maintenance at 2 AM
0 2 * * * /opt/kguard/scripts/daily-maintenance.sh >> /var/log/kguard/maintenance.log 2>&1

# Weekly maintenance on Sunday at 3 AM
0 3 * * 0 /opt/kguard/scripts/weekly-maintenance.sh >> /var/log/kguard/maintenance.log 2>&1

# Monthly maintenance on 1st day at 4 AM
0 4 1 * * /opt/kguard/scripts/monthly-maintenance.sh >> /var/log/kguard/maintenance.log 2>&1

# Monitoring every minute
* * * * * /opt/kguard/scripts/monitoring.sh >> /var/log/kguard/monitoring.log 2>&1
```

---

This comprehensive deployment guide covers all aspects of deploying KGuard from development to production environments, including Kubernetes orchestration, security configuration, monitoring, and maintenance procedures. The guide ensures reliable, secure, and scalable deployment of the KGuard security monitoring system.