# KGuard API Documentation

## Table of Contents

1. [Overview](#overview)
2. [Authentication](#authentication)
3. [Base URLs](#base-urls)
4. [Response Format](#response-format)
5. [Network Events API](#network-events-api)
6. [Security Alerts API](#security-alerts-api)
7. [Health Monitoring API](#health-monitoring-api)
8. [WebSocket API](#websocket-api)
9. [Error Handling](#error-handling)
10. [Rate Limiting](#rate-limiting)
11. [Examples](#examples)

## Overview

The KGuard API provides comprehensive access to network monitoring data, security alerts, and system health information. The API follows RESTful principles and supports both HTTP and WebSocket protocols for real-time updates.

### API Features

- **RESTful Design**: Standard HTTP methods and status codes
- **JSON Format**: All requests and responses use JSON
- **Real-time Updates**: WebSocket support for live data
- **Pagination**: Efficient handling of large datasets
- **Filtering**: Advanced filtering and search capabilities
- **Validation**: Comprehensive input validation
- **Documentation**: Interactive OpenAPI/Swagger documentation

### API Version

Current API version: `v1`

All endpoints are prefixed with `/api/` unless otherwise specified.

## Authentication

Currently, the API operates without authentication for development purposes. In production deployments, JWT-based authentication should be implemented.

### Future Authentication (Production)

```http
Authorization: Bearer <jwt_token>
```

## Base URLs

### Development
- HTTP API: `http://localhost:8000`
- WebSocket: `ws://localhost:8000/ws`

### Production
- HTTP API: `https://your-domain.com`
- WebSocket: `wss://your-domain.com/ws`

## Response Format

### Standard Response Structure

```json
{
  "success": true,
  "data": {},
  "message": "Operation completed successfully",
  "timestamp": "2024-01-15T10:30:00Z"
}
```

### Paginated Response Structure

```json
{
  "items": [],
  "total": 1000,
  "page": 1,
  "size": 25,
  "pages": 40
}
```

### Error Response Structure

```json
{
  "error": "Validation Error",
  "detail": "Invalid input parameters",
  "timestamp": "2024-01-15T10:30:00Z",
  "path": "/api/events"
}
```

## Network Events API

Network events represent captured network packets with extracted metadata.

### List Network Events

Retrieve a paginated list of network events with optional filtering.

```http
GET /api/events/
```

#### Query Parameters

| Parameter | Type | Description | Default |
|-----------|------|-------------|---------|
| `page` | integer | Page number (≥1) | 1 |
| `size` | integer | Page size (1-100) | 25 |
| `src_ip` | string | Filter by source IP | - |
| `dst_ip` | string | Filter by destination IP | - |
| `src_port` | integer | Filter by source port (0-65535) | - |
| `dst_port` | integer | Filter by destination port (0-65535) | - |
| `protocol` | string | Filter by protocol (TCP, UDP, ICMP) | - |
| `is_suspicious` | boolean | Filter by suspicious flag | - |
| `start_time` | datetime | Start time filter (ISO 8601) | - |
| `end_time` | datetime | End time filter (ISO 8601) | - |

#### Example Request

```http
GET /api/events/?page=1&size=10&protocol=TCP&is_suspicious=true
```

#### Example Response

```json
{
  "items": [
    {
      "id": 12345,
      "timestamp": 1705312200000000000,
      "created_at": "2024-01-15T10:30:00Z",
      "src_ip": "192.168.1.100",
      "dst_ip": "10.0.0.1",
      "src_port": 54321,
      "dst_port": 22,
      "protocol": "TCP",
      "flags": 2,
      "is_suspicious": true,
      "event_type": "port_scan"
    }
  ],
  "total": 1000,
  "page": 1,
  "size": 10,
  "pages": 100
}
```

### Get Single Network Event

Retrieve details of a specific network event.

```http
GET /api/events/{event_id}
```

#### Path Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `event_id` | integer | Event ID |

#### Example Response

```json
{
  "id": 12345,
  "timestamp": 1705312200000000000,
  "created_at": "2024-01-15T10:30:00Z",
  "src_ip": "192.168.1.100",
  "dst_ip": "10.0.0.1",
  "src_port": 54321,
  "dst_port": 22,
  "protocol": "TCP",
  "flags": 2,
  "is_suspicious": true,
  "event_type": "port_scan"
}
```

### Get Event Statistics

Retrieve network event statistics for a specified time period.

```http
GET /api/events/stats/summary
```

#### Query Parameters

| Parameter | Type | Description | Default |
|-----------|------|-------------|---------|
| `hours` | integer | Hours to analyze (1-168) | 24 |

#### Example Response

```json
{
  "total_events": 15420,
  "suspicious_events": 234,
  "unique_src_ips": 45,
  "unique_dst_ips": 123,
  "protocol_distribution": {
    "TCP": 12000,
    "UDP": 3200,
    "ICMP": 220
  },
  "top_src_ips": [
    {"ip": "192.168.1.100", "count": 1500},
    {"ip": "10.0.0.50", "count": 1200}
  ],
  "top_dst_ports": [
    {"port": 80, "count": 5000},
    {"port": 443, "count": 4500},
    {"port": 22, "count": 800}
  ],
  "events_per_hour": [
    {"hour": "2024-01-15T09:00:00Z", "count": 650},
    {"hour": "2024-01-15T10:00:00Z", "count": 720}
  ]
}
```

### Get Traffic Summary

Retrieve traffic summary statistics over time intervals.

```http
GET /api/events/stats/traffic
```

#### Query Parameters

| Parameter | Type | Description | Default |
|-----------|------|-------------|---------|
| `hours` | integer | Hours to analyze (1-168) | 24 |
| `interval` | integer | Interval in hours (1-24) | 1 |

#### Example Response

```json
[
  {
    "timestamp": "2024-01-15T09:00:00Z",
    "total_packets": 1500,
    "tcp_packets": 1200,
    "udp_packets": 250,
    "icmp_packets": 50,
    "unique_connections": 45,
    "suspicious_activity": 12
  },
  {
    "timestamp": "2024-01-15T10:00:00Z",
    "total_packets": 1650,
    "tcp_packets": 1300,
    "udp_packets": 300,
    "icmp_packets": 50,
    "unique_connections": 52,
    "suspicious_activity": 8
  }
]
```

### Clean Up Old Events

Delete old network events to manage database size.

```http
DELETE /api/events/cleanup
```

#### Query Parameters

| Parameter | Type | Description | Default |
|-----------|------|-------------|---------|
| `days` | integer | Delete events older than N days (1-365) | 30 |

#### Example Response

```json
{
  "success": true,
  "message": "Deleted 5000 events older than 30 days",
  "deleted_count": 5000
}
```

## Security Alerts API

Security alerts are generated by the anomaly detection system when suspicious patterns are detected.

### List Security Alerts

Retrieve a paginated list of security alerts with optional filtering.

```http
GET /api/alerts/
```

#### Query Parameters

| Parameter | Type | Description | Default |
|-----------|------|-------------|---------|
| `page` | integer | Page number (≥1) | 1 |
| `size` | integer | Page size (1-100) | 25 |
| `alert_type` | string | Filter by alert type | - |
| `severity` | string | Filter by severity | - |
| `src_ip` | string | Filter by source IP | - |
| `acknowledged` | boolean | Filter by acknowledgment status | - |
| `resolved` | boolean | Filter by resolution status | - |
| `start_time` | datetime | Start time filter (ISO 8601) | - |
| `end_time` | datetime | End time filter (ISO 8601) | - |

#### Alert Types

- `PORT_SCAN` - Port scanning activity
- `BRUTE_FORCE` - Brute force attacks
- `SUSPICIOUS_PORT` - Access to suspicious ports
- `HIGH_FREQUENCY` - High frequency connections
- `UNUSUAL_TRAFFIC` - Unusual traffic patterns
- `UNKNOWN_PROTOCOL` - Unknown protocol usage
- `SYN_FLOOD` - Half-open connections piling up against one destination
- `SPOOFED_TRAFFIC` - Forged source addresses (TTL jumps, bogon or martian sources)
- `AMPLIFICATION` - Reflection attacks: unsolicited large UDP replies, or this host used as a reflector
- `DNS_TUNNELING` - Data hidden in DNS lookups (iodine, dnscat2, exfiltration)
- `MALICIOUS_TLS` - A TLS client fingerprint (JA3/JA4) on the blocklist

#### Severity Levels

- `LOW` - Low priority alerts
- `MEDIUM` - Medium priority alerts
- `HIGH` - High priority alerts
- `CRITICAL` - Critical priority alerts

#### Example Request

```http
GET /api/alerts/?severity=HIGH&acknowledged=false
```

#### Example Response

```json
{
  "items": [
    {
      "id": 456,
      "timestamp": "2024-01-15T10:30:00Z",
      "created_at": "2024-01-15T10:30:05Z",
      "alert_type": "PORT_SCAN",
      "severity": "HIGH",
      "title": "Port Scan Detected from 192.168.1.100",
      "description": "Detected 15 connection attempts from 192.168.1.100 to multiple ports, indicating potential port scanning activity.",
      "src_ip": "192.168.1.100",
      "dst_ip": null,
      "dst_port": null,
      "related_event_ids": [12340, 12341, 12342],
      "metadata": {
        "event_count": 15,
        "detection_method": "frequency_analysis"
      },
      "acknowledged": false,
      "acknowledged_at": null,
      "acknowledged_by": null,
      "resolved": false,
      "resolved_at": null,
      "resolution_notes": null
    }
  ],
  "total": 25,
  "page": 1,
  "size": 25,
  "pages": 1
}
```

### Get Single Security Alert

Retrieve details of a specific security alert.

```http
GET /api/alerts/{alert_id}
```

#### Path Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `alert_id` | integer | Alert ID |

### Acknowledge Alert

Mark a security alert as acknowledged.

```http
POST /api/alerts/{alert_id}/acknowledge
```

#### Request Body

```json
{
  "acknowledged_by": "admin@example.com",
  "notes": "Investigating this alert"
}
```

#### Example Response

```json
{
  "success": true,
  "message": "Alert 456 acknowledged successfully",
  "timestamp": "2024-01-15T10:35:00Z"
}
```

### Resolve Alert

Mark a security alert as resolved.

```http
POST /api/alerts/{alert_id}/resolve
```

#### Request Body

```json
{
  "resolved_by": "admin@example.com",
  "resolution_notes": "False positive - legitimate network scan by security team"
}
```

#### Example Response

```json
{
  "success": true,
  "message": "Alert 456 resolved successfully",
  "timestamp": "2024-01-15T10:40:00Z"
}
```

### Get Alert Statistics

Retrieve security alert statistics for a specified time period.

```http
GET /api/alerts/stats/summary
```

#### Query Parameters

| Parameter | Type | Description | Default |
|-----------|------|-------------|---------|
| `hours` | integer | Hours to analyze (1-168) | 24 |

#### Example Response

```json
{
  "total_alerts": 45,
  "unacknowledged_alerts": 12,
  "unresolved_alerts": 8,
  "critical_alerts": 2,
  "high_alerts": 8,
  "medium_alerts": 25,
  "low_alerts": 10,
  "alert_types_distribution": {
    "PORT_SCAN": 15,
    "SUSPICIOUS_PORT": 20,
    "HIGH_FREQUENCY": 8,
    "BRUTE_FORCE": 2
  },
  "alerts_per_hour": [
    {"hour": "2024-01-15T09:00:00Z", "count": 3},
    {"hour": "2024-01-15T10:00:00Z", "count": 5}
  ],
  "top_source_ips": [
    {"ip": "192.168.1.100", "count": 8},
    {"ip": "10.0.0.50", "count": 5}
  ]
}
```

### Get Active Alerts Summary

Get a quick summary of active (unresolved) alerts.

```http
GET /api/alerts/active/summary
```

#### Example Response

```json
{
  "total_active": 8,
  "severity_breakdown": {
    "CRITICAL": 1,
    "HIGH": 2,
    "MEDIUM": 4,
    "LOW": 1
  },
  "type_breakdown": {
    "PORT_SCAN": 3,
    "SUSPICIOUS_PORT": 4,
    "HIGH_FREQUENCY": 1
  },
  "recent_alerts": [
    {
      "id": 456,
      "type": "PORT_SCAN",
      "severity": "HIGH",
      "title": "Port Scan Detected from 192.168.1.100",
      "timestamp": "2024-01-15T10:30:00Z",
      "src_ip": "192.168.1.100"
    }
  ]
}
```

### Clean Up Old Alerts

Delete old resolved alerts to manage database size.

```http
DELETE /api/alerts/cleanup
```

#### Query Parameters

| Parameter | Type | Description | Default |
|-----------|------|-------------|---------|
| `days` | integer | Delete resolved alerts older than N days (1-365) | 90 |

## Health Monitoring API

Health monitoring endpoints provide system status and diagnostic information.

### System Health Check

Get overall system health status.

```http
GET /api/health
```

#### Example Response

```json
{
  "status": "healthy",
  "timestamp": "2024-01-15T10:30:00Z",
  "version": "1.0.0",
  "database": true,
  "kernel_module": true,
  "uptime_seconds": 86400,
  "components": {
    "data_collector": "running",
    "anomaly_detector": "running",
    "websocket_manager": "running"
  }
}
```

### Database Health Check

Check database connectivity and status.

```http
GET /api/health/database
```

#### Example Response

```json
{
  "status": "healthy",
  "connected": true,
  "response_time_ms": 5.2,
  "database_size_mb": 125.6,
  "total_events": 150000,
  "total_alerts": 1250
}
```

### Kernel Module Health Check

Check kernel module status and connectivity.

```http
GET /api/health/kernel
```

#### Example Response

```json
{
  "status": "healthy",
  "module_loaded": true,
  "proc_interface_available": true,
  "last_data_received": "2024-01-15T10:29:55Z",
  "events_in_buffer": 45,
  "collection_stats": {
    "events_collected": 150000,
    "events_stored": 149950,
    "errors": 2,
    "last_collection": "2024-01-15T10:29:58Z"
  }
}
```

## WebSocket API

The WebSocket API provides real-time updates for network events, security alerts, and system metrics.

### Connection

Connect to the WebSocket endpoint:

```javascript
const ws = new WebSocket('ws://localhost:8000/ws');
```

### Message Format

All WebSocket messages follow this format:

```json
{
  "type": "message_type",
  "data": {},
  "timestamp": "2024-01-15T10:30:00Z"
}
```

### Message Types

#### Connection Messages

**Connection Established**
```json
{
  "type": "connection",
  "data": {
    "status": "connected",
    "client_id": "client_1_1705312200",
    "server_time": "2024-01-15T10:30:00Z"
  },
  "timestamp": "2024-01-15T10:30:00Z"
}
```

**Heartbeat**
```json
{
  "type": "heartbeat",
  "data": {
    "server_time": "2024-01-15T10:30:00Z",
    "active_connections": 5
  },
  "timestamp": "2024-01-15T10:30:00Z"
}
```

#### Data Messages

**Network Event**
```json
{
  "type": "network_event",
  "data": {
    "id": 12345,
    "timestamp": 1705312200000000000,
    "src_ip": "192.168.1.100",
    "dst_ip": "10.0.0.1",
    "src_port": 54321,
    "dst_port": 80,
    "protocol": "TCP",
    "is_suspicious": false
  },
  "timestamp": "2024-01-15T10:30:00Z"
}
```

**Security Alert**
```json
{
  "type": "security_alert",
  "data": {
    "id": 456,
    "alert_type": "PORT_SCAN",
    "severity": "HIGH",
    "title": "Port Scan Detected from 192.168.1.100",
    "src_ip": "192.168.1.100",
    "timestamp": "2024-01-15T10:30:00Z"
  },
  "timestamp": "2024-01-15T10:30:00Z"
}
```

**System Metric**
```json
{
  "type": "system_metric",
  "data": {
    "metric_name": "cpu_usage",
    "value": 45.2,
    "unit": "percent",
    "source": "system_monitor"
  },
  "timestamp": "2024-01-15T10:30:00Z"
}
```

**Statistics Update**
```json
{
  "type": "stats_update",
  "data": {
    "data_collector": {
      "events_collected": 150000,
      "running": true
    },
    "anomaly_detector": {
      "alerts_generated": 1250,
      "port_scans_detected": 45
    },
    "websocket": {
      "active_connections": 5,
      "messages_sent": 25000
    }
  },
  "timestamp": "2024-01-15T10:30:00Z"
}
```

### Client Messages

#### Ping
```json
{
  "type": "ping",
  "timestamp": "2024-01-15T10:30:00Z"
}
```

#### Subscribe
```json
{
  "type": "subscribe",
  "channels": ["network_events", "security_alerts"]
}
```

#### Unsubscribe
```json
{
  "type": "unsubscribe",
  "channels": ["system_metrics"]
}
```

### JavaScript Example

```javascript
const ws = new WebSocket('ws://localhost:8000/ws');

ws.onopen = function(event) {
    console.log('Connected to KGuard WebSocket');
    
    // Send ping
    ws.send(JSON.stringify({
        type: 'ping',
        timestamp: new Date().toISOString()
    }));
};

ws.onmessage = function(event) {
    const message = JSON.parse(event.data);
    
    switch(message.type) {
        case 'network_event':
            console.log('New network event:', message.data);
            break;
        case 'security_alert':
            console.log('Security alert:', message.data);
            if (message.data.severity === 'CRITICAL') {
                alert('Critical security alert!');
            }
            break;
        case 'heartbeat':
            console.log('Heartbeat received');
            break;
        default:
            console.log('Unknown message type:', message.type);
    }
};

ws.onerror = function(error) {
    console.error('WebSocket error:', error);
};

ws.onclose = function(event) {
    console.log('WebSocket connection closed:', event.code, event.reason);
};
```

## Error Handling

### HTTP Status Codes

| Code | Description |
|------|-------------|
| 200 | OK - Request successful |
| 201 | Created - Resource created successfully |
| 400 | Bad Request - Invalid request parameters |
| 401 | Unauthorized - Authentication required |
| 403 | Forbidden - Access denied |
| 404 | Not Found - Resource not found |
| 422 | Unprocessable Entity - Validation error |
| 429 | Too Many Requests - Rate limit exceeded |
| 500 | Internal Server Error - Server error |
| 503 | Service Unavailable - Service temporarily unavailable |

### Error Response Format

```json
{
  "error": "Validation Error",
  "detail": "Invalid input parameters",
  "timestamp": "2024-01-15T10:30:00Z",
  "path": "/api/events",
  "errors": [
    {
      "field": "src_port",
      "message": "Port must be between 0 and 65535"
    }
  ]
}
```

### Common Error Scenarios

#### Validation Errors (422)

```json
{
  "error": "Validation Error",
  "detail": "Input validation failed",
  "errors": [
    {
      "field": "page",
      "message": "Page must be greater than or equal to 1"
    },
    {
      "field": "src_ip",
      "message": "Invalid IP address format"
    }
  ]
}
```

#### Resource Not Found (404)

```json
{
  "error": "Not Found",
  "detail": "Event not found",
  "timestamp": "2024-01-15T10:30:00Z",
  "path": "/api/events/99999"
}
```

#### Rate Limit Exceeded (429)

```json
{
  "error": "Rate Limit Exceeded",
  "detail": "Too many requests. Please try again later.",
  "retry_after": 60,
  "timestamp": "2024-01-15T10:30:00Z"
}
```

## Rate Limiting

The API implements rate limiting to prevent abuse and ensure fair usage.

### Default Limits

- **General API**: 100 requests per minute per IP
- **Burst Limit**: 20 requests per 10 seconds
- **WebSocket Connections**: 10 connections per IP

### Rate Limit Headers

```http
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 95
X-RateLimit-Reset: 1705312800
X-RateLimit-Window: 60
```

### Rate Limit Exceeded Response

```http
HTTP/1.1 429 Too Many Requests
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 0
X-RateLimit-Reset: 1705312800
Retry-After: 60

{
  "error": "Rate Limit Exceeded",
  "detail": "Too many requests. Please try again later.",
  "retry_after": 60
}
```

## Examples

### Complete Python Example

```python
import requests
import json
from datetime import datetime, timedelta

# Base URL
BASE_URL = "http://localhost:8000"

# Get recent network events
def get_recent_events():
    url = f"{BASE_URL}/api/events/"
    params = {
        "page": 1,
        "size": 10,
        "is_suspicious": True
    }
    
    response = requests.get(url, params=params)
    if response.status_code == 200:
        data = response.json()
        print(f"Found {data['total']} suspicious events")
        for event in data['items']:
            print(f"Event {event['id']}: {event['src_ip']} -> {event['dst_ip']}:{event['dst_port']}")
    else:
        print(f"Error: {response.status_code} - {response.text}")

# Get system health
def check_health():
    url = f"{BASE_URL}/api/health"
    response = requests.get(url)
    
    if response.status_code == 200:
        health = response.json()
        print(f"System Status: {health['status']}")
        print(f"Database: {'✓' if health['database'] else '✗'}")
        print(f"Kernel Module: {'✓' if health['kernel_module'] else '✗'}")
        print(f"Uptime: {health['uptime_seconds']} seconds")
    else:
        print(f"Health check failed: {response.status_code}")

# Acknowledge an alert
def acknowledge_alert(alert_id, user_email):
    url = f"{BASE_URL}/api/alerts/{alert_id}/acknowledge"
    data = {
        "acknowledged_by": user_email,
        "notes": "Investigating this alert"
    }
    
    response = requests.post(url, json=data)
    if response.status_code == 200:
        result = response.json()
        print(f"Alert acknowledged: {result['message']}")
    else:
        print(f"Failed to acknowledge alert: {response.status_code}")

# Get event statistics
def get_event_stats(hours=24):
    url = f"{BASE_URL}/api/events/stats/summary"
    params = {"hours": hours}
    
    response = requests.get(url, params=params)
    if response.status_code == 200:
        stats = response.json()
        print(f"Event Statistics (last {hours} hours):")
        print(f"  Total Events: {stats['total_events']}")
        print(f"  Suspicious Events: {stats['suspicious_events']}")
        print(f"  Unique Source IPs: {stats['unique_src_ips']}")
        print(f"  Protocol Distribution: {stats['protocol_distribution']}")
    else:
        print(f"Failed to get statistics: {response.status_code}")

if __name__ == "__main__":
    check_health()
    get_recent_events()
    get_event_stats()
    # acknowledge_alert(456, "admin@example.com")
```

### Complete JavaScript Example

```javascript
class KGuardAPI {
    constructor(baseUrl = 'http://localhost:8000') {
        this.baseUrl = baseUrl;
        this.wsUrl = baseUrl.replace('http', 'ws') + '/ws';
        this.ws = null;
    }

    // HTTP API Methods
    async getEvents(params = {}) {
        const url = new URL(`${this.baseUrl}/api/events/`);
        Object.keys(params).forEach(key => 
            url.searchParams.append(key, params[key])
        );

        const response = await fetch(url);
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        return await response.json();
    }

    async getAlerts(params = {}) {
        const url = new URL(`${this.baseUrl}/api/alerts/`);
        Object.keys(params).forEach(key => 
            url.searchParams.append(key, params[key])
        );

        const response = await fetch(url);
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        return await response.json();
    }

    async acknowledgeAlert(alertId, acknowledgedBy, notes = '') {
        const response = await fetch(`${this.baseUrl}/api/alerts/${alertId}/acknowledge`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                acknowledged_by: acknowledgedBy,
                notes: notes
            })
        });

        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        return await response.json();
    }

    async getHealth() {
        const response = await fetch(`${this.baseUrl}/api/health`);
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        return await response.json();
    }

    async getEventStats(hours = 24) {
        const response = await fetch(`${this.baseUrl}/api/events/stats/summary?hours=${hours}`);
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        return await response.json();
    }

    // WebSocket Methods
    connectWebSocket(callbacks = {}) {
        this.ws = new WebSocket(this.wsUrl);

        this.ws.onopen = (event) => {
            console.log('Connected to KGuard WebSocket');
            if (callbacks.onOpen) callbacks.onOpen(event);
        };

        this.ws.onmessage = (event) => {
            const message = JSON.parse(event.data);
            
            switch(message.type) {
                case 'network_event':
                    if (callbacks.onNetworkEvent) callbacks.onNetworkEvent(message.data);
                    break;
                case 'security_alert':
                    if (callbacks.onSecurityAlert) callbacks.onSecurityAlert(message.data);
                    break;
                case 'stats_update':
                    if (callbacks.onStatsUpdate) callbacks.onStatsUpdate(message.data);
                    break;
                case 'heartbeat':
                    if (callbacks.onHeartbeat) callbacks.onHeartbeat(message.data);
                    break;
                default:
                    console.log('Unknown message type:', message.type);
            }
        };

        this.ws.onerror = (error) => {
            console.error('WebSocket error:', error);
            if (callbacks.onError) callbacks.onError(error);
        };

        this.ws.onclose = (event) => {
            console.log('WebSocket connection closed:', event.code, event.reason);
            if (callbacks.onClose) callbacks.onClose(event);
        };
    }

    sendWebSocketMessage(message) {
        if (this.ws && this.ws.readyState === WebSocket.OPEN) {
            this.ws.send(JSON.stringify(message));
        }
    }

    disconnectWebSocket() {
        if (this.ws) {
            this.ws.close();
            this.ws = null;
        }
    }
}

// Usage Example
const api = new KGuardAPI();

// Check system health
api.getHealth().then(health => {
    console.log('System Health:', health);
}).catch(error => {
    console.error('Health check failed:', error);
});

// Get recent suspicious events
api.getEvents({ is_suspicious: true, size: 5 }).then(events => {
    console.log('Suspicious Events:', events);
}).catch(error => {
    console.error('Failed to get events:', error);
});

// Connect to WebSocket for real-time updates
api.connectWebSocket({
    onNetworkEvent: (event) => {
        console.log('New network event:', event);
    },
    onSecurityAlert: (alert) => {
        console.log('Security alert:', alert);
        if (alert.severity === 'CRITICAL') {
            alert('Critical security alert detected!');
        }
    },
    onStatsUpdate: (stats) => {
        console.log('Statistics updated:', stats);
    }
});
```

### cURL Examples

#### Get Network Events
```bash
# Get recent events
curl -X GET "http://localhost:8000/api/events/?page=1&size=10"

# Get suspicious events from specific IP
curl -X GET "http://localhost:8000/api/events/?src_ip=192.168.1.100&is_suspicious=true"

# Get events with time filter
curl -X GET "http://localhost:8000/api/events/?start_time=2024-01-15T00:00:00Z&end_time=2024-01-15T23:59:59Z"
```

#### Get Security Alerts
```bash
# Get unacknowledged high-severity alerts
curl -X GET "http://localhost:8000/api/alerts/?severity=HIGH&acknowledged=false"

# Get alert statistics
curl -X GET "http://localhost:8000/api/alerts/stats/summary?hours=24"
```

#### Acknowledge Alert
```bash
curl -X POST "http://localhost:8000/api/alerts/456/acknowledge" \
  -H "Content-Type: application/json" \
  -d '{
    "acknowledged_by": "admin@example.com",
    "notes": "Investigating this alert"
  }'
```

#### System Health Check
```bash
# Overall health
curl -X GET "http://localhost:8000/api/health"

# Database health
curl -X GET "http://localhost:8000/api/health/database"

# Kernel module health
curl -X GET "http://localhost:8000/api/health/kernel"
```

---

This comprehensive API documentation provides all the information needed to integrate with the KGuard security monitoring system. The API is designed to be intuitive, well-documented, and production-ready with proper error handling, validation, and real-time capabilities.