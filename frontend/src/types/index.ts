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

export type AlertType =
  | 'PORT_SCAN'
  | 'BRUTE_FORCE'
  | 'SUSPICIOUS_PORT'
  | 'HIGH_FREQUENCY'
  | 'UNUSUAL_TRAFFIC'
  | 'UNKNOWN_PROTOCOL'
  | 'SYN_FLOOD'

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
