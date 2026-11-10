# KGuard API reference

Generated from the backend by `python -m app.apidoc` (CI fails when this file is out of date).
A backend started with `DEBUG=true` also serves an interactive version at `/docs`
(OpenAPI schema at `/openapi.json`).

**Authentication.** Log in with `POST /api/auth/login` and send the returned `access_token` as
`Authorization: Bearer <token>`. *logged in* means any user (viewer or admin); *admin* means the
admin role (a viewer gets 403). Agents use the token they received at enrollment; Prometheus uses
`METRICS_TOKEN`. Calls without the required credentials get 401.

## Login and users

| Method | Path | Access | What it does |
|---|---|---|---|
| POST | `/api/auth/login` | public | Login<br>body LoginRequest: `username`, `password` |
| GET | `/api/auth/me` | logged in | Me |
| POST | `/api/auth/password` | logged in | Change Password<br>body PasswordChange: `current_password`, `new_password` |
| GET | `/api/auth/users` | admin | List Users |
| POST | `/api/auth/users` | admin | Create User<br>body UserCreate: `username`, `password`, `role`? |
| PATCH | `/api/auth/users/{username}` | admin | Update User<br>`username` (path, string, required); body UserUpdate: `role`?, `is_active`?, `password`? |
| DELETE | `/api/auth/users/{username}` | admin | Delete User<br>`username` (path, string, required) |

## Events

| Method | Path | Access | What it does |
|---|---|---|---|
| GET | `/api/events/` | logged in | Get paginated list of network events with optional filtering<br>`page` (query, integer, default `1`); `size` (query, integer, default `25`); `src_ip` (query, string); `dst_ip` (query, string); `src_port` (query, integer); `dst_port` (query, integer); `protocol` (query, string); `is_suspicious` (query, boolean); `direction` (query, string); `process_name` (query, string); `host_id` (query, integer); `ids` (query, string); `start_time` (query, string); `end_time` (query, string) |
| GET | `/api/events/{event_id}` | logged in | Get a specific network event by ID<br>`event_id` (path, integer, required) |
| GET | `/api/events/stats/summary` | logged in | Get network event statistics for the specified time period<br>`hours` (query, integer, default `24`) |
| GET | `/api/events/stats/traffic` | logged in | Get traffic summary statistics over time intervals<br>`hours` (query, integer, default `24`); `interval` (query, integer, default `1`) |
| DELETE | `/api/events/cleanup` | admin | Clean up old network events to manage database size<br>`days` (query, integer, default `30`) |

## Alerts

| Method | Path | Access | What it does |
|---|---|---|---|
| GET | `/api/alerts/` | logged in | Get paginated list of security alerts with optional filtering<br>`page` (query, integer, default `1`); `size` (query, integer, default `25`); `alert_type` (query, AlertType); `severity` (query, AlertSeverity); `src_ip` (query, string); `acknowledged` (query, boolean); `resolved` (query, boolean); `start_time` (query, string); `end_time` (query, string) |
| GET | `/api/alerts/{alert_id}` | logged in | Get a specific security alert by ID<br>`alert_id` (path, integer, required) |
| GET | `/api/alerts/{alert_id}/pcap` | logged in | The packets saved for an alert (packet capture on alert), as a pcap file<br>`alert_id` (path, integer, required) |
| POST | `/api/alerts/{alert_id}/acknowledge` | admin | Acknowledge a security alert<br>`alert_id` (path, integer, required); body AlertAcknowledge: `acknowledged_by`?, `notes`? |
| POST | `/api/alerts/{alert_id}/resolve` | admin | Resolve a security alert<br>`alert_id` (path, integer, required); body AlertResolve: `resolved_by`?, `resolution_notes` |
| GET | `/api/alerts/stats/summary` | logged in | Get security alert statistics for the specified time period<br>`hours` (query, integer, default `24`) |
| DELETE | `/api/alerts/cleanup` | admin | Clean up old resolved alerts to manage database size<br>`days` (query, integer, default `90`) |
| GET | `/api/alerts/active/summary` | logged in | Get a quick summary of active (unresolved) alerts |

## Health

| Method | Path | Access | What it does |
|---|---|---|---|
| GET | `/api/health/` | public | Comprehensive health check endpoint |
| GET | `/api/health/detailed` | logged in | Detailed health check with system metrics |
| GET | `/api/health/database` | logged in | Database-specific health check |
| GET | `/api/health/kernel` | logged in | Kernel module specific health check |
| GET | `/api/health/kernel/counters` | logged in | The kernel module's own counters over Generic Netlink: packets seen, events written and dropped, ring fill, nanoseconds per packet, guard counters. The same numbers as /sys/kernel/debug/kguard/stats. |
| GET | `/api/health/services` | logged in | Check health of background services |
| GET | `/api/health/metrics` | logged in | Get current system performance metrics |

## Agents

| Method | Path | Access | What it does |
|---|---|---|---|
| POST | `/api/agents/enroll` | enrollment key | Enroll<br>body EnrollRequest: `name`, `hostname`? |
| POST | `/api/agents/ingest` | agent token | Ingest<br>body IngestRequest: `agent`?, `kernel_dropped`?, `queue_dropped`?, `payload_dropped`?, `events`?, `payloads`? |
| POST | `/api/agents/sockets` | agent token | The agent's latest listening sockets and connections (U7.2), every few seconds<br>body SocketSnapshot: `listeners`?, `connections`? |
| GET | `/api/agents/blocklist` | agent token | What this agent's host should block. The agent polls every few seconds, applies the list and reports back the version it applied (and how many entries it could not apply) on its next poll.<br>`applied` (query, string); `failed` (query, integer, default `0`); `enforcing` (query, integer) |
| GET | `/api/agents/` | logged in | List Agents |

## DNS and TLS

| Method | Path | Access | What it does |
|---|---|---|---|
| GET | `/api/dns/queries` | logged in | Dns Queries<br>`page` (query, integer, default `1`); `size` (query, integer, default `50`); `domain` (query, string); `client_ip` (query, string); `host_id` (query, integer); `responses` (query, boolean, default `False`) |
| GET | `/api/dns/domains` | logged in | Dns Domains<br>`minutes` (query, integer, default `60`); `limit` (query, integer, default `50`) |
| GET | `/api/tls/handshakes` | logged in | Tls Handshakes<br>`page` (query, integer, default `1`); `size` (query, integer, default `50`); `ja4` (query, string); `ja3` (query, string); `sni` (query, string); `host_id` (query, integer) |
| GET | `/api/tls/fingerprints` | logged in | Tls Fingerprints<br>`limit` (query, integer, default `100`) |

## Response (blocking)

| Method | Path | Access | What it does |
|---|---|---|---|
| GET | `/api/response/blocks` | logged in | List Blocks<br>`include_removed` (query, boolean, default `False`) |
| POST | `/api/response/blocks` | admin | Add Block<br>body BlockRequest: `cidr`, `reason`, `minutes`?, `host_id`? |
| DELETE | `/api/response/blocks/{block_id}` | admin | Remove Block<br>`block_id` (path, integer, required) |
| GET | `/api/response/allowlist` | logged in | List Allowlist |
| POST | `/api/response/allowlist` | admin | Add Allow<br>body AllowRequest: `cidr`, `note`? |
| DELETE | `/api/response/allowlist/{entry_id}` | admin | Remove Allow<br>`entry_id` (path, integer, required) |
| GET | `/api/response/audit` | logged in | Audit Log<br>`page` (query, integer, default `1`); `size` (query, integer, default `50`); `action` (query, string) |
| GET | `/api/response/status` | logged in | Status |

## Notifications

| Method | Path | Access | What it does |
|---|---|---|---|
| GET | `/api/notifications/status` | logged in | Status |
| POST | `/api/notifications/test` | admin | Send Test |

## Sockets and listeners

| Method | Path | Access | What it does |
|---|---|---|---|
| GET | `/api/sockets` | logged in | Get Sockets<br>`host_id` (query, integer, default `0`) |
| POST | `/api/sockets/known` | admin | Mark Known<br>body KnownRequest: `host_id`?, `proto`, `port`, `process`? |

## Metrics

| Method | Path | Access | What it does |
|---|---|---|---|
| GET | `/metrics` | metrics token | Prometheus metrics; needs METRICS_TOKEN as a bearer token (not a user login) |

## Other

| Method | Path | Access | What it does |
|---|---|---|---|
| GET | `/` | public | Root endpoint with basic API information |

## WebSocket

`/ws?token=<access_token>` (logged in): WebSocket endpoint for real-time updates. Needs a login token: /ws?token=<access_token>; without a valid one the handshake is refused.

Messages are JSON objects `{"type": ..., "data": ..., "timestamp": ...}`; the types are
listed in `backend/app/services/websocket_manager.py`.

