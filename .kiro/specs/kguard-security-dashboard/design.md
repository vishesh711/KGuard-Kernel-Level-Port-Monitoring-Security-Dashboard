# Design Document

## Overview

KGuard is architected as a multi-tier security monitoring system with three primary layers: a Linux kernel module for low-level packet capture, a FastAPI backend service for data processing and API services, and a React frontend for visualization and user interaction. The system uses a data pipeline approach where network events flow from kernel space through user space to the web interface in real-time.

The architecture prioritizes performance, security, and scalability while maintaining clear separation of concerns between system-level monitoring, data processing, and user interface components.

## Architecture

```mermaid
graph TB
    subgraph "Kernel Space"
        A[Network Packets] --> B[Netfilter Hooks]
        B --> C[KGuard Kernel Module]
        C --> D[Circular Buffer]
        D --> E[/proc/kguard Interface]
    end
    
    subgraph "User Space"
        E --> F[Data Collector Service]
        F --> G[SQLite Database]
        F --> H[Anomaly Detection Engine]
        H --> I[Alert Manager]
        
        subgraph "Backend API"
            J[FastAPI Server]
            K[WebSocket Manager]
            L[REST Endpoints]
        end
        
        G --> J
        I --> J
        J --> K
        J --> L
    end
    
    subgraph "Frontend"
        M[React Dashboard]
        N[Real-time Charts]
        O[Alert Notifications]
        P[Event Tables]
    end
    
    K --> M
    L --> M
    M --> N
    M --> O
    M --> P
    
    subgraph "Deployment"
        Q[Docker Container - Backend]
        R[Docker Container - Frontend]
        S[Docker Compose]
    end
    
    J --> Q
    M --> R
    Q --> S
    R --> S
```

### Data Flow

1. **Packet Capture**: Network packets are intercepted by Netfilter hooks in the kernel module
2. **Data Processing**: Packet metadata is extracted and stored in kernel-space circular buffer
3. **User Space Bridge**: Data collector service continuously reads from /proc/kguard
4. **Anomaly Detection**: Real-time analysis identifies suspicious patterns
5. **Data Persistence**: Events and alerts are stored in SQLite database
6. **API Layer**: FastAPI provides REST endpoints and WebSocket connections
7. **Real-time Updates**: Frontend receives live updates via WebSocket
8. **Visualization**: React dashboard displays charts, tables, and alerts

## Components and Interfaces

### Kernel Module (kguard.ko)

**Purpose**: Low-level network packet interception and metadata extraction

**Key Components**:
- Netfilter hook registration for NF_INET_PRE_ROUTING
- Packet parser for TCP/UDP headers
- Circular buffer implementation for event storage
- /proc filesystem interface for user-space access

**Interfaces**:
```c
// Hook function signature
unsigned int kguard_hook_func(void *priv, struct sk_buff *skb, 
                              const struct nf_hook_state *state);

// Proc interface
static const struct proc_ops kguard_proc_ops = {
    .proc_read = kguard_proc_read,
    .proc_open = kguard_proc_open,
    .proc_release = kguard_proc_release,
};
```

**Data Structure**:
```c
struct network_event {
    uint64_t timestamp;
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t protocol;
    uint8_t flags;
};
```

### Data Collector Service

**Purpose**: Bridge between kernel module and backend database

**Key Components**:
- Continuous /proc/kguard reader
- JSON parser for kernel data
- Database connection manager
- Event validation and sanitization

**Interface**:
```python
class DataCollector:
    async def read_kernel_data(self) -> List[NetworkEvent]
    async def store_events(self, events: List[NetworkEvent]) -> None
    async def start_collection_loop(self) -> None
```

### Anomaly Detection Engine

**Purpose**: Real-time identification of suspicious network patterns

**Detection Algorithms**:
- Port scan detection (multiple ports from single IP)
- Connection frequency analysis
- Unusual port access patterns
- Time-based anomaly detection

**Interface**:
```python
class AnomalyDetector:
    def analyze_event(self, event: NetworkEvent) -> Optional[Alert]
    def detect_port_scan(self, events: List[NetworkEvent]) -> List[Alert]
    def classify_threat_level(self, pattern: str) -> ThreatLevel
```

### FastAPI Backend

**Purpose**: REST API and WebSocket server for frontend communication

**Endpoints**:
- `GET /api/events` - Paginated network events
- `GET /api/events/stats` - Traffic statistics
- `GET /api/alerts` - Security alerts
- `GET /api/health` - System health check
- `WebSocket /ws` - Real-time event stream

**Models**:
```python
class NetworkEventResponse(BaseModel):
    id: int
    timestamp: datetime
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    is_suspicious: bool

class AlertResponse(BaseModel):
    id: int
    timestamp: datetime
    alert_type: str
    severity: str
    description: str
    related_events: List[int]
```

### React Frontend

**Purpose**: Interactive dashboard for security monitoring visualization

**Key Components**:
- Real-time event table with filtering
- Traffic analytics charts (Recharts)
- Alert notification system
- WebSocket client for live updates

**Component Structure**:
```typescript
interface DashboardProps {
  events: NetworkEvent[];
  alerts: Alert[];
  stats: TrafficStats;
}

interface NetworkEvent {
  id: number;
  timestamp: string;
  srcIp: string;
  dstIp: string;
  srcPort: number;
  dstPort: number;
  protocol: string;
  isSuspicious: boolean;
}
```

## Data Models

### Database Schema

```sql
-- Network events table
CREATE TABLE network_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp DATETIME NOT NULL,
    src_ip VARCHAR(45) NOT NULL,
    dst_ip VARCHAR(45) NOT NULL,
    src_port INTEGER NOT NULL,
    dst_port INTEGER NOT NULL,
    protocol VARCHAR(10) NOT NULL,
    flags INTEGER DEFAULT 0,
    is_suspicious BOOLEAN DEFAULT FALSE,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_timestamp (timestamp),
    INDEX idx_src_ip (src_ip),
    INDEX idx_dst_port (dst_port)
);

-- Security alerts table
CREATE TABLE security_alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp DATETIME NOT NULL,
    alert_type VARCHAR(50) NOT NULL,
    severity ENUM('LOW', 'MEDIUM', 'HIGH', 'CRITICAL') NOT NULL,
    description TEXT NOT NULL,
    src_ip VARCHAR(45),
    related_event_ids JSON,
    acknowledged BOOLEAN DEFAULT FALSE,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_severity (severity),
    INDEX idx_timestamp (timestamp)
);

-- System metrics table
CREATE TABLE system_metrics (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp DATETIME NOT NULL,
    metric_name VARCHAR(100) NOT NULL,
    metric_value DECIMAL(10,2) NOT NULL,
    unit VARCHAR(20),
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
```

### Configuration Models

```python
class KGuardConfig(BaseModel):
    database_url: str = "sqlite:///kguard.db"
    log_level: str = "INFO"
    api_host: str = "0.0.0.0"
    api_port: int = 8000
    websocket_max_connections: int = 100
    
class DetectionConfig(BaseModel):
    port_scan_threshold: int = 10  # connections per 10 seconds
    suspicious_ports: List[int] = [22, 23, 80, 443, 3389, 5432, 3306]
    alert_cooldown_seconds: int = 300
```

## Error Handling

### Kernel Module Error Handling

```c
// Safe packet processing with error bounds
static unsigned int kguard_hook_func(void *priv, struct sk_buff *skb, 
                                     const struct nf_hook_state *state) {
    if (!skb || !skb->data) {
        return NF_ACCEPT;
    }
    
    // Validate packet length before parsing
    if (skb->len < sizeof(struct iphdr)) {
        return NF_ACCEPT;
    }
    
    // Safe memory operations with bounds checking
    if (kguard_process_packet(skb) != 0) {
        printk(KERN_WARNING "KGuard: Failed to process packet\n");
    }
    
    return NF_ACCEPT;
}
```

### Backend Error Handling

```python
class KGuardException(Exception):
    """Base exception for KGuard errors"""
    pass

class DatabaseError(KGuardException):
    """Database operation errors"""
    pass

class KernelDataError(KGuardException):
    """Kernel data reading errors"""
    pass

# Error handling middleware
@app.exception_handler(KGuardException)
async def kguard_exception_handler(request: Request, exc: KGuardException):
    return JSONResponse(
        status_code=500,
        content={"error": str(exc), "type": exc.__class__.__name__}
    )
```

### Frontend Error Handling

```typescript
class ApiClient {
  private async handleResponse<T>(response: Response): Promise<T> {
    if (!response.ok) {
      const error = await response.json();
      throw new Error(`API Error: ${error.message}`);
    }
    return response.json();
  }
  
  async getEvents(params: EventParams): Promise<NetworkEvent[]> {
    try {
      const response = await fetch('/api/events', {
        method: 'GET',
        headers: { 'Content-Type': 'application/json' }
      });
      return this.handleResponse<NetworkEvent[]>(response);
    } catch (error) {
      console.error('Failed to fetch events:', error);
      throw error;
    }
  }
}
```

## Testing Strategy

### Unit Testing

**Kernel Module Testing**:
- Mock Netfilter hooks for packet processing tests
- Test circular buffer operations (insert, read, overflow)
- Validate /proc interface read operations
- Memory leak detection with valgrind

**Backend Testing**:
```python
# pytest configuration
@pytest.fixture
async def test_client():
    async with AsyncClient(app=app, base_url="http://test") as ac:
        yield ac

async def test_get_events(test_client):
    response = await test_client.get("/api/events")
    assert response.status_code == 200
    assert "events" in response.json()

async def test_anomaly_detection():
    detector = AnomalyDetector()
    events = create_port_scan_events()
    alerts = detector.detect_port_scan(events)
    assert len(alerts) > 0
    assert alerts[0].severity == "HIGH"
```

**Frontend Testing**:
```typescript
// Jest + React Testing Library
describe('Dashboard Component', () => {
  test('renders network events table', () => {
    const mockEvents = createMockEvents();
    render(<Dashboard events={mockEvents} />);
    expect(screen.getByText('Network Events')).toBeInTheDocument();
  });
  
  test('displays alerts with correct severity', () => {
    const mockAlerts = createMockAlerts();
    render(<AlertPanel alerts={mockAlerts} />);
    expect(screen.getByText('HIGH')).toHaveClass('alert-high');
  });
});
```

### Integration Testing

**End-to-End Pipeline Testing**:
1. Load kernel module in test environment
2. Generate controlled network traffic
3. Verify data appears in /proc/kguard
4. Confirm backend processes and stores data
5. Validate frontend displays real-time updates

**Performance Testing**:
- Kernel module performance under high packet rates
- Backend API response times under load
- WebSocket connection stability with multiple clients
- Database query performance with large datasets

### Security Testing

**Vulnerability Assessment**:
- Input validation testing for all API endpoints
- SQL injection prevention verification
- Cross-site scripting (XSS) protection
- Rate limiting effectiveness
- Kernel module stability with malformed packets

**Penetration Testing Scenarios**:
- Simulated port scans to test detection accuracy
- High-volume traffic to test system stability
- Malicious packet injection to test kernel module robustness
- API abuse testing to validate rate limiting

This design provides a comprehensive foundation for implementing the KGuard security monitoring system with clear component boundaries, robust error handling, and thorough testing strategies.