# KGuard Backend API

FastAPI-based backend service that processes network events from the kernel module and provides REST API and WebSocket endpoints for the frontend dashboard.

## Features

- REST API for network events, statistics, and alerts
- Real-time WebSocket streaming
- SQLite database with SQLAlchemy ORM
- Anomaly detection and alert generation
- Rate limiting and security controls
- Comprehensive logging and monitoring

## Setup

### Development Environment

```bash
# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Set up environment variables
cp .env.example .env
# Edit .env with your configuration
```

### Database Setup

```bash
# Initialize database
alembic upgrade head

# Create new migration (after model changes)
alembic revision --autogenerate -m "Description"
```

## Running

### Development Server

```bash
# Start development server with auto-reload
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000

# Or using the run script
python -m app.main
```

### Production Server

```bash
# Start production server
uvicorn app.main:app --host 0.0.0.0 --port 8000 --workers 4
```

## API Documentation

Once running, visit:
- Swagger UI: http://localhost:8000/docs
- ReDoc: http://localhost:8000/redoc

## API Endpoints

### Events
- `GET /api/events` - List network events with pagination
- `GET /api/events/stats` - Traffic statistics
- `GET /api/events/{id}` - Get specific event

### Alerts
- `GET /api/alerts` - List security alerts
- `POST /api/alerts/{id}/acknowledge` - Acknowledge alert

### System
- `GET /api/health` - Health check
- `WebSocket /ws` - Real-time event stream

## Configuration

Environment variables (create `.env` file):

```env
# Database
DATABASE_URL=sqlite:///./kguard.db

# API Settings
API_HOST=0.0.0.0
API_PORT=8000
DEBUG=true

# Security
SECRET_KEY=your-secret-key-here
ACCESS_TOKEN_EXPIRE_MINUTES=30

# Logging
LOG_LEVEL=INFO

# Anomaly Detection
PORT_SCAN_THRESHOLD=10
ALERT_COOLDOWN_SECONDS=300
```

## Detection rules

Every rule works per host (this server, or each agent) and per source, with
a cooldown (`ALERT_COOLDOWN_SECONDS`) so one attacker does not flood the
alert list. Sources in `TRUSTED_SOURCES` (CIDRs) are never alerted on.

| Alert | What triggers it | Settings |
|---|---|---|
| `PORT_SCAN` | One probe type (SYN, UDP, FIN, NULL, Xmas, ACK, Maimon) to many ports; the title names the scan type | `PORT_SCAN_THRESHOLD`, `DETECTION_WINDOW_SECONDS` |
| `BRUTE_FORCE` | Repeated new connections to one login/database port | `BRUTE_FORCE_PORTS`, `BRUTE_FORCE_THRESHOLD` |
| `SUSPICIOUS_PORT` | A connection attempt to a listed port | `SUSPICIOUS_PORTS` |
| `HIGH_FREQUENCY` | Too many connection attempts per minute from one source | `HIGH_FREQUENCY_THRESHOLD` |
| `SYN_FLOOD` | Half-open connections to one destination, whatever their sources | `SYN_FLOOD_THRESHOLD`, `SYN_FLOOD_WINDOW_SECONDS` |
| `UNUSUAL_TRAFFIC` | Connection attempts to a port far above its learned (EWMA) baseline | `BASELINE_*` |
| `SPOOFED_TRAFFIC` | A source's hop count (from the TTL) jumps; bogon sources (documentation, benchmarking, reserved ranges, ...); from the kernel module: loopback, own-address and martian sources on a real interface | `TTL_JUMP_HOPS`, `TTL_JUMP_PACKETS`, `BOGON_DETECTION` |
| `AMPLIFICATION` | Unsolicited large UDP replies from reflector ports (DNS, NTP, memcached, SSDP, CLDAP, chargen, ...); or this host's UDP service sending a client many times the bytes it received | `AMPLIFICATION_MIN_BYTES`, `AMPLIFICATION_THRESHOLD`, `AMPLIFICATION_WINDOW_SECONDS`, `REFLECTOR_RATIO`, `REFLECTOR_MIN_BYTES` |

| `DNS_TUNNELING` | Many never-repeated, long, random-looking names under one domain from one client, often TXT/NULL records (eBPF agents' DNS samples; `app/services/dns_tunnel.py`) | `DNS_TUNNEL_WINDOW_SECONDS`, `DNS_TUNNEL_MIN_QUERIES`, `DNS_TUNNEL_SCORE`, `DNS_TUNNEL_ALLOWLIST` |
| `MALICIOUS_TLS` | A TLS client fingerprint (JA3 or JA4) on the blocklist | `TLS_FINGERPRINT_BLOCKLIST` (CSV: fingerprint, label...; abuse.ch SSLBL format works) |

When this server's kernel module reports SYN/UDP scans, SYN-rate abuse and
spoofed sources itself, the backend leaves those to it.

**DNS and TLS** (from eBPF agents' payload samples, `app/services/payloads.py`):
every DNS lookup and TLS ClientHello is stored with the process that made
it. ClientHellos get JA3 and JA4 client fingerprints and their server name
(`app/services/tls_parser.py`). Our JA3 and JA4 match Wireshark's on real
curl, Python and Chromium handshakes (`tests/fixtures/tls`), except that
JA4 ignores GREASE signature algorithms as its specification says, so
Chromium's JA4 stays the same across connections. API:

| Endpoint | Returns |
|---|---|
| `GET /api/tls/fingerprints` | Per JA4: handshakes, JA3s, server names, processes, clients |
| `GET /api/tls/handshakes?ja4=&ja3=&sni=` | Recent ClientHellos |
| `GET /api/dns/domains?minutes=60` | Per registered domain: lookups, distinct names, tunnel score |
| `GET /api/dns/queries?domain=&client_ip=` | Recent lookups |

`scripts/dns_fp_eval.py` measures DNS tunnelling false positives on real
hostnames (500 top sites, about 6,000 third-party hosts from Ghostery's
tracker database): no alert in 36,000 lookups of a simulated 8-hour browsing
session, nor when every hostname is looked up within 10 minutes (the closest
domain, cloudfront.net, scored 0.31 against a threshold of 0.6).

**TCP fingerprints.** Every SYN gets a p0f-style guess of the sender's
operating system or scanning tool (`os_guess` on events: Linux, Windows,
macOS, FreeBSD, OpenBSD, nmap, masscan, zmap, or `crafted` for hand-made
packets) from its initial TTL, window, MSS and TCP option order
(`app/services/fingerprint.py`). Scan, brute-force and flood alerts name it.

## Flow export (IPFIX)

Set `IPFIX_COLLECTORS='["collector.example:4739"]'` and the backend groups
every host's packet events into flows and exports them over IPFIX
(RFC 7011, UDP) to any collector: nfcapd/nfdump, Wireshark, pmacct,
ntopng, Elastic. Each flow carries addresses, ports, protocol, packets,
bytes (IP length), start and end in milliseconds, TCP flags, direction,
interface and why it ended (FIN/RST, `IPFIX_IDLE_TIMEOUT`, or
`IPFIX_ACTIVE_TIMEOUT` for long flows). Each agent, and each network
namespace on this server, is its own observation domain, so a packet seen
leaving a container and arriving on the host is not counted twice
(`app/services/flow_export.py`).

## Packet capture on alert

With `PCAP_ON_ALERT=true` (root or CAP_NET_RAW) the backend keeps the last
`PCAP_SECONDS` of this server's traffic in memory and saves the packets of
each alert of `PCAP_MIN_SEVERITY` (default HIGH) or above, from before and
after the alert, as `PCAP_DIR/alert-<id>.pcap`; download it from
`GET /api/alerts/{id}/pcap`. The kernel does the heavy lifting: an
AF_PACKET `TPACKET_V3` ring mapped into the backend (whole blocks handed
over, no system call per packet) and a one-instruction classic BPF socket
filter that cuts each packet to `PCAP_SNAPLEN` bytes before it is copied
(`app/services/packet_capture.py`). Off by default: it records traffic.

`scripts/flow_pcap_lab.py` checks both in a VM (10 checks): nfdump stores
the exported flows, whose packet and byte counts equal tcpdump's for the
same connection; Wireshark decodes the messages; an nmap scan blocked by the
kernel gets a pcap of exactly the scanner's packets, including those before
the alert.

## Testing

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=app

# Run specific test file
pytest tests/test_api.py

# Run with verbose output
pytest -v
```

## Development

### Project Structure

```
backend/
├── app/
│   ├── __init__.py
│   ├── main.py              # FastAPI application
│   ├── config.py            # Configuration settings
│   ├── database.py          # Database connection
│   ├── models/              # SQLAlchemy models
│   ├── schemas/             # Pydantic schemas
│   ├── api/                 # API routes
│   ├── services/            # Business logic
│   └── utils/               # Utility functions
├── tests/                   # Test files
├── alembic/                 # Database migrations
├── requirements.txt         # Dependencies
└── README.md               # This file
```

### Adding New Features

1. Create/update models in `app/models/`
2. Create Pydantic schemas in `app/schemas/`
3. Implement business logic in `app/services/`
4. Add API routes in `app/api/`
5. Write tests in `tests/`
6. Create database migration if needed