import { NetworkEvent, SecurityAlert } from '../types'

export function event(over: Partial<NetworkEvent> = {}): NetworkEvent {
  return {
    id: 1,
    timestamp: Date.UTC(2026, 10, 10, 12, 0, 0) * 1e6,
    created_at: '2026-11-10T12:00:00',
    src_ip: '198.51.100.9',
    dst_ip: '10.0.0.1',
    src_port: 40000,
    dst_port: 22,
    protocol: 'TCP',
    flags: 0x02,
    is_suspicious: false,
    event_type: 'connection',
    direction: 'in',
    ct_state: 'new',
    process_name: 'sshd',
    pid: 812,
    host_id: null,
    ...over,
  }
}

export function alert(over: Partial<SecurityAlert> = {}): SecurityAlert {
  return {
    id: 5,
    timestamp: '2026-11-10T12:00:00',
    created_at: '2026-11-10T12:00:00',
    alert_type: 'PORT_SCAN',
    severity: 'HIGH',
    title: 'SYN Scan Detected from 198.51.100.9',
    description: '198.51.100.9 sent SYN probes to 40 ports',
    src_ip: '198.51.100.9',
    dst_ip: '10.0.0.1',
    related_event_ids: [1, 2],
    metadata: {},
    acknowledged: false,
    resolved: false,
    ...over,
  }
}

export function page<T>(items: T[], over = {}) {
  return { items, total: items.length, page: 1, size: 25, pages: 1, ...over }
}
