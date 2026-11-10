import { useState } from 'react'
import { Link } from 'react-router-dom'
import { keepPreviousData, useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api } from '../services/api'
import { AlertFilterOptions, AlertSeverity, AlertType, SecurityAlert } from '../types'
import { Pagination } from '../components/ui/Pagination'
import { Empty, ErrorMessage, Loading } from '../components/ui/States'
import { SeverityPill } from '../components/alerts/SeverityPill'
import { EnrichmentTags } from '../components/dashboard/RecentAlerts'
import { formatServerTime } from '../lib/format'
import { useIsAdmin } from '../context/auth'

const TYPES: AlertType[] = [
  'PORT_SCAN',
  'BRUTE_FORCE',
  'SYN_FLOOD',
  'HIGH_FREQUENCY',
  'SUSPICIOUS_PORT',
  'SPOOFED_TRAFFIC',
  'AMPLIFICATION',
  'DNS_TUNNELING',
  'MALICIOUS_TLS',
  'UNUSUAL_TRAFFIC',
  'UNKNOWN_PROTOCOL',
]
const SEVERITIES: AlertSeverity[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']

type Status = '' | 'open' | 'acknowledged' | 'resolved'

function statusFilter(status: Status): AlertFilterOptions {
  if (status === 'open') return { acknowledged: false, resolved: false }
  if (status === 'acknowledged') return { acknowledged: true, resolved: false }
  if (status === 'resolved') return { resolved: true }
  return {}
}

function StatusText({ alert }: { alert: SecurityAlert }) {
  if (alert.resolved) return <span className="text-green-700">Resolved</span>
  if (alert.acknowledged) return <span className="text-gray-600">Acknowledged</span>
  return <span className="font-medium text-red-700">Open</span>
}

export function Alerts() {
  const isAdmin = useIsAdmin()
  const client = useQueryClient()
  const [page, setPage] = useState(1)
  const [type, setType] = useState<AlertType | ''>('')
  const [severity, setSeverity] = useState<AlertSeverity | ''>('')
  const [status, setStatus] = useState<Status>('open')

  const filters: AlertFilterOptions = {
    ...statusFilter(status),
    ...(type ? { alert_type: type } : {}),
    ...(severity ? { severity } : {}),
  }
  const alerts = useQuery({
    queryKey: ['alerts', 'list', page, filters],
    queryFn: () => api.getAlerts({ page, size: 25, filters }),
    placeholderData: keepPreviousData,
    refetchInterval: 30_000,
  })
  const ack = useMutation({
    mutationFn: (id: number) => api.acknowledgeAlert(id),
    onSuccess: () => client.invalidateQueries({ queryKey: ['alerts'] }),
  })

  const select = 'rounded-md border border-gray-300 px-2 py-1.5 text-sm'
  const change =
    <T,>(setter: (v: T) => void) =>
    (e: { target: { value: string } }) => {
      setter(e.target.value as T)
      setPage(1)
    }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-gray-900">Security Alerts</h1>
        <p className="mt-1 text-sm text-gray-600">What the detectors found, newest first</p>
      </div>

      <div className="card card-content flex flex-wrap gap-3">
        <label className="text-xs text-gray-600">
          Status
          <select className={`${select} mt-1 block`} value={status} onChange={change(setStatus)}>
            <option value="open">Open</option>
            <option value="acknowledged">Acknowledged</option>
            <option value="resolved">Resolved</option>
            <option value="">All</option>
          </select>
        </label>
        <label className="text-xs text-gray-600">
          Severity
          <select className={`${select} mt-1 block`} value={severity} onChange={change(setSeverity)}>
            <option value="">Any</option>
            {SEVERITIES.map((s) => (
              <option key={s}>{s}</option>
            ))}
          </select>
        </label>
        <label className="text-xs text-gray-600">
          Type
          <select className={`${select} mt-1 block`} value={type} onChange={change(setType)}>
            <option value="">Any</option>
            {TYPES.map((t) => (
              <option key={t} value={t}>
                {t.replace(/_/g, ' ').toLowerCase()}
              </option>
            ))}
          </select>
        </label>
      </div>

      <div className="card overflow-hidden">
        {alerts.isPending ? (
          <Loading />
        ) : alerts.isError ? (
          <ErrorMessage error={alerts.error} />
        ) : alerts.data.items.length === 0 ? (
          <Empty>No alerts match.</Empty>
        ) : (
          <>
            <ul className="divide-y divide-gray-100">
              {alerts.data.items.map((a) => (
                <li key={a.id} className="flex items-start gap-4 px-4 py-3">
                  <SeverityPill severity={a.severity} />
                  <div className="min-w-0 flex-1">
                    <Link to={`/alerts/${a.id}`} className="font-medium text-gray-900 hover:underline">
                      {a.title}
                    </Link>
                    <p className="line-clamp-1 text-sm text-gray-500">{a.description}</p>
                    <EnrichmentTags alert={a} />
                  </div>
                  <div className="text-right text-xs text-gray-500">
                    <div>{formatServerTime(a.timestamp)}</div>
                    <StatusText alert={a} />
                  </div>
                  {isAdmin && !a.acknowledged && !a.resolved && (
                    <button type="button" className="btn-secondary btn-sm" onClick={() => ack.mutate(a.id)}>
                      Acknowledge
                    </button>
                  )}
                </li>
              ))}
            </ul>
            <Pagination
              page={alerts.data.page}
              pages={alerts.data.pages}
              total={alerts.data.total}
              onPage={setPage}
            />
          </>
        )}
      </div>
    </div>
  )
}
