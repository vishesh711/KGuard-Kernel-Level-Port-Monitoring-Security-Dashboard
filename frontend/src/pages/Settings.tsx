import { useQuery } from '@tanstack/react-query'
import { api } from '../services/api'
import { ErrorMessage, Loading } from '../components/ui/States'

type Dict = Record<string, unknown>

function Section({ title, rows }: { title: string; rows: [string, unknown][] }) {
  return (
    <section className="card" aria-label={title}>
      <h2 className="card-header text-sm font-semibold">{title}</h2>
      <dl className="card-content divide-y divide-gray-100">
        {rows.map(([label, value]) => (
          <div key={label} className="grid grid-cols-2 gap-4 py-2 text-sm">
            <dt className="text-gray-500">{label}</dt>
            <dd className="text-gray-900">{render(value)}</dd>
          </div>
        ))}
      </dl>
    </section>
  )
}

function render(value: unknown): string {
  if (value === null || value === undefined || value === '') return '—'
  if (typeof value === 'boolean') return value ? 'on' : 'off'
  if (Array.isArray(value)) return value.length ? value.join(', ') : 'none'
  if (typeof value === 'object') {
    return Object.entries(value as Dict)
      .map(([k, v]) => `${k}: ${v}`)
      .join(', ')
  }
  return String(value)
}

/** Read-only: KGuard is configured through environment variables (see backend/README.md) */
export function Settings() {
  const health = useQuery({ queryKey: ['health', 'detailed'], queryFn: () => api.getDetailedHealth() })
  const response = useQuery({ queryKey: ['response', 'status'], queryFn: () => api.getResponseStatus() })

  if (health.isPending || response.isPending) return <Loading />
  if (health.isError) return <ErrorMessage error={health.error} />
  if (response.isError) return <ErrorMessage error={response.error} />

  const s = health.data.services as Dict
  const det = s.anomaly_detector as Dict
  const state = det.state as Dict
  const notify = s.notifications as Dict
  const channels = notify.channels as Record<string, Dict>
  const enrichment = s.enrichment as Dict
  const config = health.data.configuration as Dict
  const rules = response.data.rules

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-gray-900">Settings</h1>
        <p className="mt-1 text-sm text-gray-600">
          Current configuration. It is set with environment variables on the backend (see backend/README.md).
        </p>
      </div>
      <div className="grid gap-6 lg:grid-cols-2">
        <Section
          title="Detection thresholds"
          rows={[
            ['Port scan: distinct ports', det.port_scan_threshold],
            ['Within (seconds)', det.detection_window_seconds],
            ['Connection rate (per minute)', det.high_frequency_threshold],
            ['Brute force: attempts', det.brute_force_threshold],
            ['SYN flood: half-open connections', det.syn_flood_threshold],
            ['Same alert repeated after (seconds)', det.alert_cooldown_seconds],
            ['Trusted sources', det.trusted_sources],
            ['Kernel module detects scans itself', det.kernel_detection],
            ['Detection state kept in', state?.backend],
          ]}
        />
        <Section
          title="Automatic blocking"
          rows={[
            ['On', rules.auto_block],
            ['Alert types', rules.types],
            ['Minimum severity', rules.min_severity],
            ['Also block sources on threat lists', rules.listed_sources],
            ['First block lasts (minutes)', rules.minutes],
            ['Enforcer lease (seconds)', rules.lease_seconds],
            ['This server enforces', response.data.local.status],
          ]}
        />
        <Section
          title="Notifications"
          rows={[
            ['Minimum severity', notify.min_severity],
            ['Per channel, at most per hour', notify.max_per_hour],
            ...Object.entries(channels).map(
              ([name, c]) =>
                [name, c.configured ? `on · ${c.sent} sent, ${c.failed} failed` : 'off'] as [string, unknown],
            ),
          ]}
        />
        <Section
          title="Enrichment and data"
          rows={[
            ['GeoIP databases', enrichment.geoip],
            ['Threat lists (networks)', enrichment.threat_lists],
            ['Keep events (days)', (config.retention_days as Dict)?.events],
            ['Keep resolved alerts (days)', (config.retention_days as Dict)?.resolved_alerts],
            ['Log level', config.log_level],
          ]}
        />
      </div>
    </div>
  )
}
