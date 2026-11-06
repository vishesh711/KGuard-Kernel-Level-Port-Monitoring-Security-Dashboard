# kguard-agent

Collects KGuard events on a host and ships them to the KGuard backend. One
binary, two capture engines:

| Engine | How it captures | Extra |
|---|---|---|
| `module` | The KGuard kernel module (`kernel/`), read zero-copy from `/dev/kguard` | Connection-tracking state; in-kernel scan/SYN-flood detection and blocking |
| `ebpf` | eBPF: XDP on ingress, TC (clsact) on egress, tracing programs for process ownership | No module to build per kernel; XDP blocklist drops before the network stack |

Both produce the same 96-byte event record (`kernel/include/uapi/linux/kguard.h`),
so the backend treats them alike.

## How it works

```
 engine ──► reader thread ──► bounded queue ──► sender thread ──► backend
                                  │                  │
                         full: drop new events,   batch (5,000 / 0.5 s), POST,
                         count them               retry with backoff until accepted
```

The queue is where backpressure lands: while the backend is down the sender
keeps retrying the same batch (500 ms, doubling, up to 30 s) and the queue
absorbs new events; only when it is full are events dropped, and the count
is reported with the next batch. The Hosts page shows those losses.

### eBPF engine

`bpf/kguard.bpf.c`, compiled with clang and loaded through a libbpf
skeleton:

- **`kguard_xdp`** (ingress): parses Ethernet/IPv4/IPv6/TCP/UDP with
  verifier-checked bounds, looks the source up in an **LPM trie blocklist**
  (`XDP_DROP` on a match, so blocked traffic never reaches the stack) and
  emits an `in` event to a **BPF ring buffer**.
- **`kguard_tc_egress`** (TC clsact egress): emits `out` events with the
  sending socket's UID.
- **Process ownership** without per-packet work: `fentry/tcp_connect`,
  `fexit/inet_csk_accept`, `fexit/inet_listen`, `fexit/inet_bind`,
  `fexit/inet6_bind` and `fentry/udp_sendmsg` record who owns each TCP
  connection, listening port and UDP port in LRU hash maps;
  `tp_btf/inet_sock_set_state` forgets closed ones. The packet programs look
  owners up by connection tuple or local port. At start-up the agent seeds
  the maps for ports that were already open, from `/proc/net/{tcp,udp}*`.
- **CO-RE**: kernel structs are declared with only the fields used and
  `preserve_access_index`; libbpf relocates them against the running
  kernel's BTF, so one build runs on many kernels. Return values are read
  with `bpf_get_func_ret()` so signature changes (like `inet_csk_accept()`
  in 6.10) do not break loading.
- Timestamps use the monotonic clock in BPF and are converted to wall-clock
  time by the agent.

Differences from the module engine: no conntrack state, no in-kernel scan
detection (the backend detects scans for eBPF hosts), and IPv6 extension
headers are not walked.

### Module engine

Maps `/dev/kguard`'s per-CPU rings, sleeps in `poll()`, and resolves socket
inodes to processes by scanning `/proc/<pid>/fd` (at most once a second).

## Building

```bash
sudo apt install clang libbpf-dev libelf-dev zlib1g-dev libcurl4-openssl-dev \
                 linux-tools-common linux-tools-$(uname -r)    # bpftool
make -C agent            # -> agent/build/kguard-agent
```

The eBPF engine needs a kernel with BTF (`/sys/kernel/btf/vmlinux`) and
5.17 or newer. Tested on Linux 6.8.

## Using it

```bash
# On the backend: set AGENT_ENROLLMENT_KEY (any long random string)

# On each host (root):
sudo agent/build/kguard-agent enroll --server https://kguard.example.com \
     --key "$KEY" --name web-1             # token saved in /var/lib/kguard-agent

sudo agent/build/kguard-agent run --engine ebpf --server https://kguard.example.com
sudo agent/build/kguard-agent run --engine module --server https://kguard.example.com

# Without a backend: print events as JSON lines
sudo agent/build/kguard-agent run --engine ebpf --stdout --iface eth0
```

| Option | Default | Meaning |
|---|---|---|
| `--engine` | `module` | `module` or `ebpf` |
| `--server` | | Backend base URL |
| `--stdout` | | Print JSON lines instead of sending |
| `--state-dir` | `/var/lib/kguard-agent` | Where the token is kept |
| `--token` | from state dir | Bearer token |
| `--iface` | all | eBPF: comma-separated interfaces to attach to |
| `--xdp-native` | generic | eBPF: native (driver) XDP |
| `--batch` / `--flush-ms` | 5000 / 500 | Batch size and longest wait |
| `--queue` | 200000 | Events buffered while the backend is unreachable |
| `--ringbuf-mb` | 8 | eBPF ring buffer size |

### XDP blocklist (eBPF engine)

The blocklist map is pinned at `/sys/fs/bpf/kguard_blocklist`, so it can
be changed while the agent runs and survives restarts:

```bash
sudo kguard-agent block 203.0.113.0/24
sudo kguard-agent block 2001:db8::5 --timeout 600
sudo kguard-agent blocks          # prefix, time left, packets dropped
sudo kguard-agent unblock 203.0.113.0/24
```

IPv4 is stored IPv4-mapped, so one trie holds both families.

## Testing

`tests/agent_tests.py` runs against a real kernel (29 checks): eBPF capture
of every packet in and out, process attribution (curl, `nc` listeners
started before and after the agent, first UDP datagram), IPv6, the XDP
blocklist against an attacker namespace (IPv4 prefix, IPv6, expiry), the
module engine, two agents with different engines reporting as two hosts,
and recovery after a backend restart without losing events.

```bash
make -C kernel && make -C agent
sudo python3 agent/tests/agent_tests.py /path/to/backend/venv/bin/python
```

Run it in a throwaway VM (see `kernel/tests/run_in_vm.sh` for a virtme-ng
setup).
