# Deploying KGuard

This is the one guide for installing and running KGuard. Component details
live next to the code: [kernel/README.md](../kernel/README.md) (module
parameters, `kguardctl`), [agent/README.md](../agent/README.md),
[backend/README.md](../backend/README.md) (every setting) and
[frontend/README.md](../frontend/README.md).

## What runs where

```
 monitored host(s)                                server (docker compose)
 ┌───────────────────────────────┐                ┌───────────────────────────────────┐
 │ kguard.ko (Netfilter hooks)   │ /dev/kguard    │ frontend (nginx :80) ─► backend   │
 │   or                          │───────────────►│ backend (FastAPI) ─► PostgreSQL   │
 │ kguard-agent (eBPF or module) │ HTTPS ingest   │                   ─► Redis        │
 └───────────────────────────────┘───────────────►│ Prometheus ─► Grafana (:3001)     │
                                                  └───────────────────────────────────┘
```

* **One host:** load the module on the server itself; the backend reads
  `/dev/kguard` directly.
* **Several hosts:** run `kguard-agent` on each (eBPF needs no module), and
  it sends events to the backend over HTTPS. Both can be combined.

## Requirements

| | |
|---|---|
| Server | Linux with Docker and Docker Compose v2 (`docker compose`), 2 GB RAM |
| Kernel module | Linux 5.15 or newer (CI tests 5.15, 6.1, 6.6, 6.12 and the latest stable), its headers (`linux-headers-$(uname -r)`), `make` and `gcc` |
| Agent, eBPF engine | Linux 5.17 or newer with BTF (`/sys/kernel/btf/vmlinux`); to build: `clang`, `bpftool`, `libbpf-dev`, `libelf-dev`, `zlib1g-dev`, `libcurl4-openssl-dev` |

## 1. Install on one host (module and dashboard)

```bash
git clone https://github.com/vishesh711/KGuard-Kernel-Level-Port-Monitoring-Security-Dashboard.git kguard
cd kguard
make setup                # checks Docker and headers, creates .env from .env.example
```

Fill in `.env`. Every secret it asks for can come from `openssl rand -hex 32`;
`ADMIN_PASSWORD` must be at least 10 characters, and `KGUARD_HOSTNAME` is the
name people will type in the browser (the API refuses other `Host` headers).

Build and load the kernel module. For a permanent install use DKMS, which
rebuilds the module for every new kernel and loads it at boot:

```bash
sudo apt install dkms
sudo make -C kernel dkms-install     # /etc/modprobe.d/kguard.conf: options kguard reader_gid=1500
```

or, to try it once (gone after a reboot):

```bash
make -C kernel
sudo modprobe -a nf_conntrack nf_socket_ipv4 nf_socket_ipv6
sudo insmod kernel/kguard.ko reader_gid=1500
```

`reader_gid` is the group allowed to read events; the backend container runs
with that group (`KGUARD_READER_GID`, default 1500) and needs no root or
capabilities. The module starts in **monitor-only** mode: it never drops a
packet until you set `enforce=1` (see [kernel/README.md](../kernel/README.md#guard-detection-and-blocking)).

Start the stack with the kernel device:

```bash
docker compose -f docker-compose.prod.yml -f docker-compose.kernel.yml up -d --build
```

Without `docker-compose.kernel.yml` the backend reads `/proc/kguard` instead
(slower, no process names), or, with no module at all, collects only what
agents send.

Open `http://KGUARD_HOSTNAME/` and log in with `ADMIN_USERNAME` /
`ADMIN_PASSWORD`. Add more users with the command line (it asks for the
password) or with `POST /api/auth/users` ([API reference](API.md)):

```bash
docker compose -f docker-compose.prod.yml exec -it backend python -m app.users create alice --role viewer
```

Viewers see everything; only admins block addresses, acknowledge alerts and
manage users.

### TLS

The production stack serves plain HTTP on port 80. Put it behind a TLS
terminating proxy (Caddy, nginx, a cloud load balancer) that forwards to it,
and set `DASHBOARD_URL` to the `https://` address so alert notifications link
to it. The backend trusts `X-Forwarded-For` only from the frontend container.

## 2. Add other hosts (agent)

On the server, set `AGENT_ENROLLMENT_KEY` in `.env` and restart the backend.
On each host:

```bash
make -C agent                         # build dependencies: see Requirements
sudo make -C agent install            # /usr/local/bin/kguard-agent + systemd unit
sudo kguard-agent enroll --server https://kguard.example.com --key "$KEY" --name "$(hostname)"
sudoedit /etc/default/kguard-agent    # KGUARD_SERVER, KGUARD_ENGINE=ebpf or module
sudo systemctl enable --now kguard-agent
```

The host shows up on the Hosts page. With the eBPF engine the agent also
enforces the server's block list in XDP; with the module engine it applies it
through the module. See [agent/README.md](../agent/README.md).

## 3. Monitoring

Grafana runs on port 3001 (user `admin`, `GRAFANA_ADMIN_PASSWORD`) with the
KGuard dashboard; Prometheus scrapes the backend's `/metrics` with
`METRICS_TOKEN`. The module's own counters (packets, drops, ring fill, cost
per packet) are on the Hosts page and in `/sys/kernel/debug/kguard/stats`.

Alert notifications (Slack, Telegram, e-mail) are turned on by setting their
variables in `.env`; the Settings page shows which are on, and
`POST /api/notifications/test` (admin) sends a test message.

## 4. Operating it

| Task | How |
|---|---|
| Upgrade | `git pull`, then `docker compose -f docker-compose.prod.yml -f docker-compose.kernel.yml up -d --build`; the backend migrates the database on start. For the module: `sudo make -C kernel dkms-uninstall dkms-install` |
| Back up | `docker compose -f docker-compose.prod.yml exec postgres pg_dump -U kguard kguard > kguard.sql` |
| Data kept | Events 7 days, metrics 30, alerts 90 (`RETENTION_EVENTS_DAYS`, `RETENTION_METRICS_DAYS`, `RETENTION_ALERTS_DAYS`; 0 keeps forever); deleted daily |
| Logs | `docker compose -f docker-compose.prod.yml logs backend` (JSON lines with request IDs); `dmesg \| grep kguard` |
| Status | `make status`; `python3 kernel/tools/kguardctl.py stats` |
| Stop | `make down` (data volumes are kept) |
| Remove the module | `sudo make -C kernel dkms-uninstall` (or `sudo rmmod kguard`) |

## Troubleshooting

| Symptom | Cause |
|---|---|
| Backend exits at start: "SECRET_KEY" | `SECRET_KEY` missing or shorter than 32 characters |
| `Invalid host header` (400) in the browser | The address you typed is not in `KGUARD_HOSTNAME` |
| Backend does not start: `/dev/kguard` not found | The module is not loaded; load it or drop `docker-compose.kernel.yml` |
| Dashboard shows no kernel events | Module loaded without `reader_gid`, or with a different number than `KGUARD_READER_GID`; the Kernel health panel on the Hosts page shows what the backend sees |
| `insmod: Unknown symbol` | Load `nf_conntrack nf_socket_ipv4 nf_socket_ipv6` first (DKMS and `modprobe` do this) |
| Agent: "failed to load BPF" | Kernel without BTF or older than 5.17; use `--engine module` |
| Agent: 401 from the server | Token revoked or the host was deleted; enroll again |
