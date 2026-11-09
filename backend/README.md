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

SQLite (the default, `DATABASE_URL=sqlite:///./kguard.db`) suits development
and small installs. Production uses PostgreSQL 16 (`docker-compose.prod.yml`):

```env
DATABASE_URL=postgresql+psycopg://kguard:PASSWORD@localhost:5432/kguard
```

The PostgreSQL database must use UTF-8 encoding (the default for the
official image; with `createdb`, pass `--encoding UTF8 --template template0`).

The schema is managed by Alembic (`alembic/versions`). The backend runs
`alembic upgrade head` itself at start-up, so a new or older database is
brought up to date automatically. A database created before migrations
existed is upgraded in place, keeping its data, and stamped at the baseline
revision.

```bash
# Build or update the schema by hand
alembic upgrade head

# After changing a model: generate a migration and review it
alembic revision --autogenerate -m "Description"

# Check that the models and the migrations agree (CI runs this)
alembic check
```

### Data retention

A job deletes old data a minute after start-up and then every
`RETENTION_INTERVAL_HOURS` (24), in batches of `RETENTION_BATCH` rows so a
large first run never locks a busy table for long:

| Data | Setting | Default |
|---|---|---|
| Network events, DNS lookups, TLS handshakes | `RETENTION_EVENTS_DAYS` | 7 |
| System metrics | `RETENTION_METRICS_DAYS` | 30 |
| Resolved alerts and their pcap files | `RETENTION_ALERTS_DAYS` | 90 |

Open alerts are never deleted. Set a value to 0 to keep that data forever.
The last run and what it deleted are shown in `/api/health/detailed`.

## Running

```bash
# Reloads on code changes when DEBUG=true; host and port from API_HOST / API_PORT
python -m app
```

Run one process. The collector reads the kernel's event rings and keeps
detection state in memory, so several workers would each see part of the
traffic. (`uvicorn app.main:app` also works, but its first few start-up
lines are printed before the JSON logging is set up.)

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

# Security (required; see "Login and security" below)
SECRET_KEY=<output of: openssl rand -hex 32>
ADMIN_PASSWORD=<first admin's password>

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
| `BRUTE_FORCE` | Repeated new connections to one login/database port (over minutes: SSH takes several passwords per connection) | `BRUTE_FORCE_PORTS`, `BRUTE_FORCE_THRESHOLD`, `BRUTE_FORCE_WINDOW_SECONDS` |
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

## Response engine (blocking)

Admins block addresses or prefixes; the record lives here and enforcers
apply it:

- **Agents** poll `GET /api/agents/blocklist` every few seconds: eBPF agents
  drop in XDP, module agents use the module's Netlink block commands (see
  `agent/README.md`).
- **This machine's kernel module**, over Generic Netlink, when the backend
  may (`LOCAL_ENFORCEMENT=auto` and `CAP_NET_ADMIN`; the production container
  has no capabilities, so there agents do it).

Enforcers hold each block as a lease of `BLOCK_LEASE_SECONDS` (300) and
renew it, so a block whose removal never reached an enforcer still ends
within one lease.

| Endpoint | Who |
|---|---|
| `GET /api/response/blocks` (`?include_removed=true` for history) | any user |
| `POST /api/response/blocks` `{"cidr", "reason", "minutes"?, "host_id"?}` | admin |
| `DELETE /api/response/blocks/{id}` | admin |
| `GET/POST /api/response/allowlist`, `DELETE /api/response/allowlist/{id}` | read: any user; change: admin |
| `GET /api/response/audit` | any user |
| `GET /api/response/status` (rules, local enforcement, each agent's sync state) | any user |

Safety rules, for manual and automatic blocks alike: never loopback,
link-local, multicast, unspecified or reserved addresses; nothing wider than
/16 (IPv4) or /32 (IPv6); nothing overlapping the allowlist or an enrolled
agent's address. Adding an allowlist entry unblocks what it covers. Blocking
an address again keeps the later expiry. Rows are never deleted: unblocking
and expiry record who and when, and every change is in the audit log.

**Automatic blocking** is off until `AUTO_BLOCK=true`. Then the source of
an alert is blocked for `AUTO_BLOCK_MINUTES` (60), doubled for each earlier
automatic block of the same address in the last day (at most a week), when:

- its type is in `AUTO_BLOCK_TYPES` (default `PORT_SCAN`, `BRUTE_FORCE`) and
  its severity is at least `AUTO_BLOCK_MIN_SEVERITY` (`HIGH`), or
- `AUTO_BLOCK_LISTED_SOURCES=true` and the source is on a threat list.

SYN floods, spoofing and amplification are not in the default list on
purpose: their source addresses are easily forged, so blocking them would
let an attacker cut off anyone.

## Alert enrichment

Every alert gets `metadata.enrichment`:

```json
{"mitre": [{"id": "T1046", "name": "Network Service Discovery", "tactic": "Discovery",
            "url": "https://attack.mitre.org/techniques/T1046/"}],
 "src": {"ip": "5.188.10.7", "country": "NL", "country_name": "Netherlands",
         "asn": 64500, "as_org": "Example Hosting", "threat_lists": ["firehol_level1"]},
 "dst": {"ip": "10.0.0.1", "scope": "not public"}}
```

- **MITRE ATT&CK** from the alert type: port scan and sensitive-port probes
  T1046, brute force T1110, SYN flood T1499.001, high packet rate
  T1498.001, amplification T1498.002, DNS tunnelling T1071.004 + T1572,
  malicious TLS client T1071.001 + T1573, unknown protocol T1095. Spoofed
  traffic and baseline anomalies have no single technique and get none.
- **Country and network owner** from MaxMind GeoLite2 (free, but needs an
  account): put `GeoLite2-Country.mmdb` and `GeoLite2-ASN.mmdb` in
  `data/geoip/` (or set `GEOIP_COUNTRY_DB`, `GEOIP_ASN_DB`). Replaced files are
  picked up automatically. Without them these fields are left out.
- **Bad-IP lists**: every `*.txt`, `*.netset`, `*.ipset` or `*.list` file in
  `THREAT_LISTS_DIR` (`data/threatlists/`) is a list named after the file,
  one address or prefix per line (FireHOL and Spamhaus DROP formats). Fetch
  FireHOL level 1 and Spamhaus DROP/DROPv6 (`THREAT_LIST_URLS`) with

  ```bash
  python -m app.threatlists update      # then: python -m app.threatlists status
  ```

  daily from cron, or set `THREAT_LIST_UPDATE_HOURS=24`. A failed or empty
  download keeps the previous copy. Files are re-read within a minute.

Private and other non-public addresses are not looked up. Enrichment runs
as a database hook when an alert is stored, so every detector gets it, and
a failure never loses the alert.

## Login and security

Every endpoint needs a login except `POST /api/auth/login`, the liveness
probe `GET /api/health/`, `GET /`, and the agents' `enroll` and `ingest`
(which use the enrollment key and agent tokens). With DEBUG on, the API docs
(`/docs`, `/openapi.json`) are public too.

**Roles.** `viewer` can read everything. `admin` can also acknowledge and
resolve alerts, delete old data, and manage users. The user who
acknowledges or resolves an alert is recorded from the login, not taken
from the request.

**First admin.** On first start, with no users yet, the backend creates an
admin from `ADMIN_USERNAME` (default `admin`) and `ADMIN_PASSWORD` (10+
characters). Or use the command line, which works any time:

```bash
python -m app.users create alice --role admin   # asks for the password
python -m app.users list
python -m app.users set-role bob viewer          # also: set-password, disable, enable, delete
```

**API.**

```bash
TOKEN=$(curl -s -H 'Content-Type: application/json' \
  -d '{"username": "alice", "password": "..."}' localhost:8000/api/auth/login | jq -r .access_token)
curl -H "Authorization: Bearer $TOKEN" localhost:8000/api/alerts/
```

| Endpoint | Who |
|---|---|
| `POST /api/auth/login` | anyone; returns a token (JWT, HS256, `ACCESS_TOKEN_EXPIRE_MINUTES`, default 8 h) |
| `GET /api/auth/me`, `POST /api/auth/password` | any user (changing your password ends your other logins) |
| `GET/POST /api/auth/users`, `PATCH/DELETE /api/auth/users/{name}` | admin |
| WebSocket `/ws?token=<token>` | any user (browsers cannot send headers on a WebSocket) |

Disabling a user, changing their role or password ends their logins at once:
the token carries a version number that must match the user's. The last
active admin cannot be removed, disabled or made a viewer. An open WebSocket
is checked when it connects; it stays open until it closes.

Passwords are stored as salted scrypt hashes. A wrong username and a wrong
password get the same answer and take the same time. Tokens and passwords
never appear in the logs (`token=` and `Bearer` values are redacted, including
uvicorn's WebSocket lines).

**Hardening.**

- No default `SECRET_KEY`: the backend refuses to start without one of 32+
  characters, or with a value from old examples. It also refuses `*` in
  `ALLOWED_ORIGINS` or `ALLOWED_HOSTS`.
- Rate limits: `RATE_LIMIT_PER_MINUTE` (300) requests per client address to
  `/api` (agents' ingest and the health probe are exempt), and
  `LOGIN_ATTEMPTS_PER_MINUTE` (5) failed logins per address and per username;
  then 429 with `Retry-After`. The client address comes from `X-Forwarded-For`
  only when the request comes from `FORWARDED_ALLOW_IPS`.
- CORS: only `ALLOWED_ORIGINS`, no credentials mode (tokens are not cookies),
  only the methods and headers the dashboard uses.
- `ALLOWED_HOSTS`: other `Host` headers get 400 (stops DNS rebinding).
- Every response has `X-Content-Type-Options: nosniff`, `X-Frame-Options:
  DENY`, `Referrer-Policy: no-referrer` and `Cache-Control: no-store`.
- Container: runs as user 10001, application code owned by root and
  read-only, no compiler or curl in the image. The production Compose file
  adds a read-only root filesystem, `cap_drop: ALL` and `no-new-privileges`,
  and publishes no backend port (only nginx reaches it).
- Kernel access without root: the module's `reader_gid` group may read
  `/proc/kguard` and consume `/dev/kguard`, but changing the module's settings
  or block lists over Netlink needs `CAP_NET_ADMIN`, which the container does
  not have. The device is opened read-write only because the reader writes
  its read position into the shared ring header.

## Notifications (Slack, email, Telegram)

Alerts at or above `NOTIFY_MIN_SEVERITY` (`HIGH`) go to every configured
channel, with the description, addresses, country, threat lists, MITRE
technique and a link to the dashboard (`DASHBOARD_URL`):

| Channel | Settings |
|---|---|
| Slack | `SLACK_WEBHOOK_URL` (an incoming webhook: Slack app, *Incoming Webhooks*) |
| Telegram | `TELEGRAM_BOT_TOKEN` (from @BotFather), `TELEGRAM_CHAT_ID` |
| Email | `SMTP_HOST`, `SMTP_PORT` (587), `SMTP_USER`, `SMTP_PASSWORD`, `SMTP_STARTTLS` (true), `EMAIL_FROM`, `EMAIL_TO` (JSON list) |

- Each channel sends at most `NOTIFY_MAX_PER_HOUR` (30) messages per hour;
  past that, alerts are counted, and the next message says how many were held
  back.
- Sending runs in the background, so a slow service never delays detection.
  Failures are retried three times (honouring `Retry-After`); a 4xx such as
  a revoked webhook is not retried.
- Webhook URLs, tokens and passwords never appear in logs or API answers.

Check a channel straight away (admin):

```bash
curl -X POST -H "Authorization: Bearer $TOKEN" localhost:8000/api/notifications/test
# {"results": {"slack": "sent", "email": "sent"}}
curl -H "Authorization: Bearer $TOKEN" localhost:8000/api/notifications/status
```

## Metrics (Prometheus and Grafana)

`GET /metrics` serves Prometheus metrics. It needs its own bearer token,
`METRICS_TOKEN` (not a user login); without one set it is off (404).

| Metric | What |
|---|---|
| `kguard_events_total{host}` | events stored, from this server (`local`) or each agent |
| `kguard_alerts_total{type,severity}` | alerts raised |
| `kguard_detection_seconds` | time to analyse one batch (histogram) |
| `kguard_kernel_events_dropped_total{host}` | events lost in kernel buffers |
| `kguard_agent_queue_dropped_total{agent}` | events lost in an agent's queue |
| `kguard_agent_online{agent}`, `kguard_agent_blocklist_in_sync{agent}` | agent health |
| `kguard_blocks_active` | addresses blocked now |
| `kguard_http_requests_total{method,status}`, `kguard_http_request_seconds` | API traffic and latency |
| `kguard_collector_errors_total`, `kguard_detection_state{backend}` | backend health |

The production Compose file runs Prometheus (scraping `/metrics` with the
token, passed as a Compose secret) and Grafana with the **KGuard overview**
dashboard already provisioned (`monitoring/`):

```bash
export METRICS_TOKEN=$(openssl rand -hex 32) GRAFANA_ADMIN_PASSWORD=...
docker compose -f docker-compose.prod.yml up -d
# Grafana: http://localhost:3001  (admin / GRAFANA_ADMIN_PASSWORD)
```

![KGuard overview dashboard](../docs/images/grafana-kguard.png)

## Detection state (Redis)

With `REDIS_URL` set, the detector's sliding windows (probes per source,
connection attempts per source and login port) and alert cooldowns live in
Redis: a backend restart keeps them, so a scan that started before the
restart and continues after it is still detected, and several backend
processes share them (a cooldown is claimed with an atomic `SET NX`, so only
one process raises a given alert). The production Compose file sets it.
The short-lived SYN-flood, spoofing and amplification trackers (seconds) stay
in memory. If Redis is unreachable, detection carries on in memory and
`/api/health/detailed` says `memory fallback`; Redis is retried every 30 s.

## Logging

The backend is started with `python -m app` (the Docker images do this). Every
log line it writes, uvicorn's included, is one JSON object:

```json
{"time": "2026-11-09T17:31:54.282Z", "level": "INFO", "logger": "kguard.access",
 "message": "GET /api/alerts/ 200", "request_id": "demo-1", "method": "GET",
 "path": "/api/alerts/", "client": "127.0.0.1", "status": 200, "duration_ms": 44.11}
```

Each HTTP request and WebSocket connection gets a request ID: the client's
`X-Request-ID` header if it is 1-64 letters, digits, `.`, `_` or `-`,
otherwise a new random one. It is sent back in the `X-Request-ID` response
header and added to every line logged while handling that request, so
`jq 'select(.request_id == "demo-1")'` shows one request's story. An
unhandled error is logged with its traceback and the request ID, and the
500 response includes the ID.

| Setting | Default | |
|---|---|---|
| `LOG_LEVEL` | `INFO` | |
| `LOG_FORMAT` | `json` | `text` for the readable `time - logger - level - message` form |
| `LOG_FILE` | empty | also write to this file |
| `LOG_MAX_BYTES` | 10000000 | rotate the file at this size |
| `LOG_BACKUP_COUNT` | 5 | old files kept (`kguard.log.1` ...) |

In production Compose the backend writes JSON to stdout, which Docker rotates
(10 MB x 5), and to `./logs/kguard.log`.

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

The suite uses a temporary SQLite database. To run it against PostgreSQL
(as CI does), point it at an empty UTF-8 database:

```bash
KGUARD_TEST_DATABASE_URL=postgresql+psycopg://postgres@localhost:5432/kguard_test pytest
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