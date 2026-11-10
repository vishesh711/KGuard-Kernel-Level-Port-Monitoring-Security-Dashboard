// KGuard Frontend Type Definitions

export interface NetworkEvent {
  id: number
  timestamp: number
  created_at: string
  src_ip: string
  dst_ip: string
  src_port: number
  dst_port: number
  protocol: string
  flags: number
  is_suspicious: boolean
  event_type: string
  // Context from the kernel module (null when unknown)
  family?: number | null
  direction?: 'in' | 'out' | 'fwd' | null
  ct_state?: string | null
  netns?: number | null
  ifindex?: number | null
  pid?: number | null
  process_name?: string | null
  uid?: number | null
  sock_ino?: number | null
  host_id?: number | null
  // Packet headers (kernel ABI v2) and, for SYNs, the sender's TCP fingerprint
  ttl?: number | null
  ip_len?: number | null
  df?: boolean | null
  tcp_window?: number | null
  tcp_mss?: number | null
  tcp_wscale?: number | null
  tcp_options?: string | null
  os_guess?: string | null
}

/** A remote host running kguard-agent */
export interface AgentInfo {
  id: number
  name: string
  hostname: string | null
  engine: 'module' | 'ebpf' | null
  version: string | null
  online: boolean
  last_seen: string | null
  created_at: string | null
  remote_addr: string | null
  events_received: number
  kernel_dropped: number
  queue_dropped: number
  /** Over the last minute */
  events_per_second?: number
  blocklist?: {
    applied: string | null
    failed: number | null
    enforcing: boolean | null
    synced_at: string | null
  }
}

export interface SecurityAlert {
  id: number
  timestamp: string
  created_at: string
  alert_type: AlertType
  severity: AlertSeverity
  title: string
  description: string
  src_ip?: string
  dst_ip?: string
  dst_port?: number
  related_event_ids?: number[]
  metadata?: Record<string, unknown>
  acknowledged: boolean
  acknowledged_at?: string
  acknowledged_by?: string
  resolved: boolean
  resolved_at?: string
  resolution_notes?: string
  host_id?: number | null
}

/** Added to every alert's metadata by the backend (roadmap S6.3) */
export interface MitreTechnique {
  id: string
  name: string
  tactic: string
  url: string
}

export interface AddressInfo {
  ip: string
  scope?: 'not public'
  country?: string
  country_name?: string
  asn?: number
  as_org?: string
  threat_lists?: string[]
}

export interface AlertEnrichment {
  mitre: MitreTechnique[]
  src?: AddressInfo
  dst?: AddressInfo
}

export type AlertType =
  | 'PORT_SCAN'
  | 'BRUTE_FORCE'
  | 'SUSPICIOUS_PORT'
  | 'HIGH_FREQUENCY'
  | 'UNUSUAL_TRAFFIC'
  | 'UNKNOWN_PROTOCOL'
  | 'SYN_FLOOD'
  | 'SPOOFED_TRAFFIC'
  | 'AMPLIFICATION'
  | 'DNS_TUNNELING'
  | 'MALICIOUS_TLS'

export type AlertSeverity = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'

export interface SystemMetric {
  id: number
  timestamp: string
  metric_name: string
  metric_category: string
  value: number
  unit?: string
  source?: string
  tags?: string
}

export interface NetworkEventStats {
  total_events: number
  suspicious_events: number
  unique_src_ips: number
  unique_dst_ips: number
  protocol_distribution: Record<string, number>
  top_src_ips: Array<{ ip: string; count: number }>
  top_dst_ports: Array<{ port: number; count: number }>
  events_per_hour: Array<{ hour: string; count: number }>
}

export interface AlertStats {
  total_alerts: number
  unacknowledged_alerts: number
  unresolved_alerts: number
  critical_alerts: number
  high_alerts: number
  medium_alerts: number
  low_alerts: number
  alert_types_distribution: Record<string, number>
  alerts_per_hour: Array<{ hour: string; count: number }>
  top_source_ips: Array<{ ip: string; count: number }>
}

export interface TrafficSummary {
  timestamp: string
  total_packets: number
  tcp_packets: number
  udp_packets: number
  icmp_packets: number
  unique_connections: number
  suspicious_activity: number
}

export interface HealthCheck {
  status: string
  timestamp: string
  version: string
  database: boolean
  kernel_module: boolean
  uptime_seconds: number
}

export interface PaginatedResponse<T> {
  items: T[]
  total: number
  page: number
  size: number
  pages: number
}

export interface WebSocketMessage {
  type: string
  data: Record<string, unknown>
  timestamp: string
}

export interface ConnectionStatus {
  connected: boolean
  reconnecting: boolean
  error?: string
  lastConnected?: Date
}

export interface FilterOptions {
  src_ip?: string
  dst_ip?: string
  src_port?: number
  dst_port?: number
  protocol?: string
  is_suspicious?: boolean
  direction?: 'in' | 'out' | 'fwd'
  process_name?: string
  host_id?: number
  start_time?: Date
  end_time?: Date
}

export interface AlertFilterOptions {
  alert_type?: AlertType
  severity?: AlertSeverity
  src_ip?: string
  acknowledged?: boolean
  resolved?: boolean
  start_time?: Date
  end_time?: Date
}

export interface ChartDataPoint {
  name: string
  value: number
  timestamp?: string
}

export interface TimeSeriesData {
  timestamp: string
  [key: string]: string | number
}

/** A TLS ClientHello seen by an eBPF agent, with its client fingerprints */
export interface TlsHandshake {
  id: number
  timestamp: number
  host_id: number | null
  client_ip: string
  client_port: number
  server_ip: string
  server_port: number
  direction: 'in' | 'out' | null
  sni: string | null
  alpn: string | null
  tls_version: string | null
  ja3: string
  ja4: string
  known_bad: string | null
  process_name: string | null
}

/** A DNS lookup seen by an eBPF agent */
export interface DnsQuery {
  id: number
  timestamp: number
  host_id: number | null
  client_ip: string
  server_ip: string
  qname: string
  qtype_name: string | null
  domain: string | null
  subdomain_length: number | null
  entropy: number | null
  process_name: string | null
}

/** Response engine (S6.4) */
export interface Block {
  id: number
  cidr: string
  host_id: number | null
  reason: string
  source: 'manual' | 'auto'
  created_by: string
  alert_id: number | null
  created_at: string | null
  expires_at: string | null
  removed_at: string | null
  removed_by: string | null
  active: boolean
  seconds_left: number | null
}

export interface AllowEntry {
  id: number
  cidr: string
  note: string | null
  created_by: string
  created_at: string | null
}

export interface AuditEntry {
  id: number
  time: string | null
  actor: string
  action: string
  target: string | null
  details: Record<string, unknown> | null
}

export interface ResponseStatus {
  rules: {
    auto_block: boolean
    types: string[]
    min_severity: string
    listed_sources: boolean
    minutes: number
    lease_seconds: number
  }
  active_blocks: number
  local: { status: string; managed: number; last_error: string | null }
  agents: {
    id: number
    name: string
    engine: string | null
    in_sync: boolean
    failed: number | null
    enforcing: boolean | null
    synced_at: string | null
  }[]
}

/** A socket from /proc/net, with its process (U7.2) */
export interface SocketInfo {
  proto: 'TCP' | 'UDP'
  family: number
  local: string
  lport: number
  remote: string
  rport: number
  state: string
  uid: number
  user: string | null
  pid: number | null
  process: string | null
  /** Listeners only: not in the host's baseline or marked known */
  new?: boolean
}

export interface SocketSnapshot {
  host: string
  taken_at: string | null
  listeners: SocketInfo[]
  connections: SocketInfo[]
}

/** The kernel module's counters, as in /sys/kernel/debug/kguard/stats (U7.7) */
export interface KernelCounters {
  available: boolean
  reason?: string
  stats?: Record<string, number>
  ring_capacity?: number | null
  enforcing?: boolean | null
  reader?: string | null
}
