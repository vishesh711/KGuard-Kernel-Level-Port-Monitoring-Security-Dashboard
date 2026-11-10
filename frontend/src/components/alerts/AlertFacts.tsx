import { AlertType, SecurityAlert } from '../../types'

/** One labelled value in an alert's detail panel */
export interface Fact {
  label: string
  value: string
}

type Meta = Record<string, unknown>

function show(value: unknown): string | null {
  if (value === null || value === undefined || value === '') return null
  if (Array.isArray(value)) return value.length ? value.join(', ') : null
  if (typeof value === 'boolean') return value ? 'yes' : 'no'
  if (typeof value === 'number') return Number.isInteger(value) ? value.toLocaleString() : value.toFixed(2)
  if (typeof value === 'object') {
    return Object.entries(value as Record<string, unknown>)
      .map(([k, v]) => `${k}: ${v}`)
      .join(', ')
  }
  return String(value)
}

const SCAN_TYPES: Record<string, string> = {
  syn: 'TCP SYN (half-open)',
  udp: 'UDP',
  fin: 'FIN',
  null: 'NULL (no flags)',
  xmas: 'Xmas (FIN, PSH, URG)',
  ack: 'ACK (firewall mapping)',
  maimon: 'Maimon (FIN, ACK)',
  connect: 'TCP connect',
}

const SYN_COOKIES: Record<string, string> = {
  '0': 'off',
  '1': 'on when needed',
  '2': 'always on',
}

/** Which metadata each alert type has, and how to label it */
const FIELDS: Partial<Record<AlertType, [string, string, ((v: unknown) => string | null)?][]>> = {
  PORT_SCAN: [
    ['scan_type', 'Scan type', (v) => SCAN_TYPES[String(v)] ?? show(v)],
    ['unique_ports', 'Ports probed'],
    ['sample_ports', 'Ports'],
    ['window_seconds', 'Over (seconds)'],
    ['sender_fingerprint', 'Sender OS / tool (TCP fingerprint)'],
    ['fingerprints', 'Fingerprints seen'],
    ['action', 'Kernel action'],
  ],
  BRUTE_FORCE: [
    ['connections', 'Connection attempts'],
    ['window_seconds', 'Over (seconds)'],
    ['threshold', 'Threshold'],
    ['sender_fingerprint', 'Sender OS / tool (TCP fingerprint)'],
  ],
  SYN_FLOOD: [
    ['half_open', 'Half-open connections'],
    ['distinct_sources', 'Distinct sources'],
    ['window_seconds', 'Over (seconds)'],
    ['syn_cookies', 'SYN cookies on this server', (v) => SYN_COOKIES[String(v)] ?? show(v)],
    ['attempts', 'Attempts (kernel)'],
    ['sender_fingerprint', 'Sender OS / tool (TCP fingerprint)'],
    ['action', 'Kernel action'],
  ],
  HIGH_FREQUENCY: [
    ['attempts_per_minute', 'Attempts per minute'],
    ['event_count', 'Attempts'],
    ['window_seconds', 'Over (seconds)'],
  ],
  SPOOFED_TRAFFIC: [
    ['spoof_reason', 'Why it is spoofed'],
    ['bogon_category', 'Address range'],
    ['initial_ttl', 'Initial TTL'],
    ['usual_hops', 'Usual hop count'],
    ['odd_hops', 'Hop count seen'],
    ['packets', 'Packets'],
    ['distinct_sources', 'Distinct sources'],
    ['sample_sources', 'Sources'],
  ],
  AMPLIFICATION: [
    ['service', 'Service'],
    ['role', 'This host is the'],
    ['amplification', 'Amplification factor'],
    ['request_bytes', 'Request bytes'],
    ['reply_bytes', 'Reply bytes'],
    ['mbit_per_second', 'Reply rate (Mbit/s)'],
    ['reflectors', 'Reflectors'],
    ['sample_reflectors', 'Reflector addresses'],
  ],
  DNS_TUNNELING: [
    ['domain', 'Domain'],
    ['queries', 'Queries'],
    ['unique_subdomains', 'Unique subdomains'],
    ['mean_subdomain_length', 'Mean subdomain length'],
    ['random_looking', 'Random-looking names'],
    ['record_types', 'Record types'],
    ['bytes_in_names', 'Bytes carried in names'],
    ['score', 'Score'],
    ['example', 'Example name'],
  ],
  MALICIOUS_TLS: [
    ['label', 'Known as'],
    ['ja3', 'JA3'],
    ['ja4', 'JA4'],
    ['sni', 'Server name (SNI)'],
    ['process', 'Process'],
  ],
  UNUSUAL_TRAFFIC: [
    ['count', 'Count in interval'],
    ['mean', 'Usual mean'],
    ['std', 'Usual deviation'],
    ['times_normal', 'Times the usual'],
    ['interval_seconds', 'Interval (seconds)'],
  ],
  SUSPICIOUS_PORT: [['event_count', 'Attempts']],
}

/** The type-specific facts for an alert, in display order, skipping missing ones */
export function alertFacts(alert: SecurityAlert): Fact[] {
  const meta = (alert.metadata ?? {}) as Meta
  const facts: Fact[] = []
  if (alert.alert_type === 'SUSPICIOUS_PORT' && alert.dst_port) {
    facts.push({ label: 'Port', value: String(alert.dst_port) })
  }
  if (alert.alert_type === 'BRUTE_FORCE' && alert.dst_port) {
    facts.push({ label: 'Login port', value: String(alert.dst_port) })
  }
  for (const [key, label, render] of FIELDS[alert.alert_type] ?? []) {
    const value = render ? render(meta[key]) : show(meta[key])
    if (value !== null && meta[key] !== undefined) facts.push({ label, value })
  }
  const method = show(meta.detection_method)
  if (method) facts.push({ label: 'Detected by', value: method.replace(/_/g, ' ') })
  return facts
}
