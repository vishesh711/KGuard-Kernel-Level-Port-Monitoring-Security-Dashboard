import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import {
  Bar,
  BarChart,
  CartesianGrid,
  Line,
  LineChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts'
import { format } from 'date-fns'
import { api } from '../services/api'
import { parseServerDate } from '../lib/time'
import { Empty, ErrorMessage, Loading } from '../components/ui/States'

const RANGES = [
  { hours: 1, label: 'Last hour' },
  { hours: 24, label: 'Last 24 hours' },
  { hours: 168, label: 'Last 7 days' },
]

function Card({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section className="card" aria-label={title}>
      <h2 className="card-header text-sm font-semibold">{title}</h2>
      <div className="card-content">{children}</div>
    </section>
  )
}

function Ranking({ rows, label }: { rows: { name: string; count: number }[]; label: string }) {
  if (!rows.length) return <Empty>No data in this period.</Empty>
  const max = Math.max(...rows.map((r) => r.count))
  return (
    <table className="w-full text-sm">
      <thead className="text-left text-xs text-gray-500">
        <tr>
          <th className="pb-1">{label}</th>
          <th className="pb-1 text-right">Count</th>
        </tr>
      </thead>
      <tbody>
        {rows.map((r) => (
          <tr key={r.name}>
            <td className="py-1 font-mono">
              {r.name}
              <div
                className="mt-0.5 h-1 rounded bg-blue-500"
                style={{ width: `${(r.count / max) * 100}%` }}
              />
            </td>
            <td className="py-1 text-right tabular-nums">{r.count.toLocaleString()}</td>
          </tr>
        ))}
      </tbody>
    </table>
  )
}

const hourLabel = (hours: number) => (iso: string) =>
  format(parseServerDate(iso), hours > 24 ? 'MMM d HH:00' : 'HH:00')

export function Analytics() {
  const [hours, setHours] = useState(24)
  const events = useQuery({
    queryKey: ['events', 'stats', hours],
    queryFn: () => api.getEventStats(hours),
    refetchInterval: 60_000,
  })
  const alerts = useQuery({
    queryKey: ['alerts', 'stats', hours],
    queryFn: () => api.getAlertStats(hours),
    refetchInterval: 60_000,
  })

  if (events.isPending || alerts.isPending) return <Loading />
  if (events.isError) return <ErrorMessage error={events.error} />
  if (alerts.isError) return <ErrorMessage error={alerts.error} />

  const types = Object.entries(alerts.data.alert_types_distribution)
    .map(([name, count]) => ({ name: name.replace(/_/g, ' ').toLowerCase(), count }))
    .sort((a, b) => b.count - a.count)

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Analytics</h1>
          <p className="mt-1 text-sm text-gray-600">
            Who talks to this network, on which ports, and what was found
          </p>
        </div>
        <select
          aria-label="Time range"
          className="rounded-md border border-gray-300 px-2 py-1.5 text-sm"
          value={hours}
          onChange={(e) => setHours(Number(e.target.value))}
        >
          {RANGES.map((r) => (
            <option key={r.hours} value={r.hours}>
              {r.label}
            </option>
          ))}
        </select>
      </div>

      <div className="grid grid-cols-2 gap-4 md:grid-cols-4">
        {[
          ['Events', events.data.total_events],
          ['Suspicious events', events.data.suspicious_events],
          ['Alerts', alerts.data.total_alerts],
          ['Distinct sources', events.data.unique_src_ips],
        ].map(([label, value]) => (
          <div key={label} className="card card-content">
            <div className="text-xs text-gray-500">{label}</div>
            <div className="text-2xl font-semibold tabular-nums">{Number(value).toLocaleString()}</div>
          </div>
        ))}
      </div>

      <div className="grid gap-6 lg:grid-cols-2">
        <Card title="Alerts over time">
          <div className="h-64">
            <ResponsiveContainer>
              <LineChart data={alerts.data.alerts_per_hour}>
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis dataKey="hour" tickFormatter={hourLabel(hours)} fontSize={11} />
                <YAxis allowDecimals={false} fontSize={11} />
                <Tooltip labelFormatter={hourLabel(hours)} />
                <Line type="monotone" dataKey="count" name="Alerts" stroke="#dc2626" dot={false} />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </Card>
        <Card title="Events over time">
          <div className="h-64">
            <ResponsiveContainer>
              <BarChart data={events.data.events_per_hour}>
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis dataKey="hour" tickFormatter={hourLabel(hours)} fontSize={11} />
                <YAxis fontSize={11} />
                <Tooltip labelFormatter={hourLabel(hours)} />
                <Bar dataKey="count" name="Events" fill="#2563eb" />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </Card>
        <Card title="Top source addresses">
          <Ranking
            rows={events.data.top_src_ips.map((r) => ({ name: r.ip, count: r.count }))}
            label="Address"
          />
        </Card>
        <Card title="Top destination ports">
          <Ranking
            rows={events.data.top_dst_ports.map((r) => ({ name: String(r.port), count: r.count }))}
            label="Port"
          />
        </Card>
        <Card title="Alert types">
          <Ranking rows={types} label="Type" />
        </Card>
        <Card title="Sources with the most alerts">
          <Ranking
            rows={alerts.data.top_source_ips.map((r) => ({ name: r.ip, count: r.count }))}
            label="Address"
          />
        </Card>
      </div>
    </div>
  )
}
