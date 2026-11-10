import { useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { isAxiosError } from 'axios'
import toast from 'react-hot-toast'
import { api } from '../services/api'
import { AlertEnrichment, SecurityAlert } from '../types'
import { alertFacts } from '../components/alerts/AlertFacts'
import { SeverityPill } from '../components/alerts/SeverityPill'
import { ErrorMessage, Loading } from '../components/ui/States'
import { endpoint, formatEventTime, formatServerTime, tcpFlags } from '../lib/format'
import { useIsAdmin } from '../context/auth'

function Row({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="grid grid-cols-3 gap-4 py-2 text-sm">
      <dt className="text-gray-500">{label}</dt>
      <dd className="col-span-2 break-words text-gray-900">{children}</dd>
    </div>
  )
}

function Enrichment({ alert }: { alert: SecurityAlert }) {
  const e = alert.metadata?.enrichment as AlertEnrichment | undefined
  if (!e) return null
  const src = e.src
  return (
    <>
      {src?.country && (
        <Row label="Source country">
          {src.country_name ?? src.country} ({src.country})
          {src.asn ? ` · AS${src.asn} ${src.as_org ?? ''}` : ''}
        </Row>
      )}
      {src?.scope && <Row label="Source address">{src.scope}</Row>}
      <Row label="Threat lists">
        {src?.threat_lists?.length ? (
          <span className="text-red-700">{src.threat_lists.join(', ')}</span>
        ) : (
          'not listed'
        )}
      </Row>
      <Row label="MITRE ATT&CK">
        {e.mitre.length
          ? e.mitre.map((t) => (
              <a
                key={t.id}
                href={t.url}
                target="_blank"
                rel="noreferrer"
                className="mr-3 text-indigo-700 hover:underline"
              >
                {t.id} {t.name} <span className="text-gray-500">({t.tactic})</span>
              </a>
            ))
          : 'no single technique'}
      </Row>
    </>
  )
}

function RelatedEvents({ alert }: { alert: SecurityAlert }) {
  const ids = alert.related_event_ids ?? []
  const events = useQuery({
    queryKey: ['events', 'byIds', alert.id],
    queryFn: () => api.getEventsByIds(ids),
    enabled: ids.length > 0,
  })
  if (!ids.length) return <p className="text-sm text-gray-500">No related events recorded.</p>
  if (events.isPending) return <Loading />
  if (events.isError) return <ErrorMessage error={events.error} />
  return (
    <table className="min-w-full text-xs">
      <thead className="text-left text-gray-500">
        <tr>
          <th className="py-1 pr-3">Time</th>
          <th className="py-1 pr-3">Source</th>
          <th className="py-1 pr-3">Destination</th>
          <th className="py-1 pr-3">Protocol</th>
          <th className="py-1 pr-3">TTL / window</th>
          <th className="py-1 pr-3">OS guess</th>
        </tr>
      </thead>
      <tbody className="divide-y divide-gray-100 font-mono">
        {events.data.map((e) => (
          <tr key={e.id}>
            <td className="py-1 pr-3">{formatEventTime(e.timestamp)}</td>
            <td className="py-1 pr-3">{endpoint(e.src_ip, e.src_port)}</td>
            <td className="py-1 pr-3">{endpoint(e.dst_ip, e.dst_port)}</td>
            <td className="py-1 pr-3">
              {e.protocol} {tcpFlags(e.protocol, e.flags)}
            </td>
            <td className="py-1 pr-3">
              {e.ttl ?? '—'} / {e.tcp_window ?? '—'}
            </td>
            <td className="py-1 pr-3 font-sans">{e.os_guess ?? '—'}</td>
          </tr>
        ))}
      </tbody>
    </table>
  )
}

async function savePcap(id: number) {
  try {
    const blob = await api.downloadPcap(id)
    if (!blob) {
      toast.error('No packet capture for this alert')
      return
    }
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `kguard-alert-${id}.pcap`
    a.click()
    URL.revokeObjectURL(url)
  } catch {
    toast.error('Download failed')
  }
}

function Actions({ alert }: { alert: SecurityAlert }) {
  const client = useQueryClient()
  const [notes, setNotes] = useState('')
  const done = () => client.invalidateQueries({ queryKey: ['alerts'] })
  const failed = (e: unknown) =>
    toast.error(isAxiosError(e) ? (e.response?.data?.detail ?? e.message) : 'Failed')
  const ack = useMutation({
    mutationFn: () => api.acknowledgeAlert(alert.id),
    onSuccess: done,
    onError: failed,
  })
  const resolve = useMutation({
    mutationFn: () => api.resolveAlert(alert.id, { resolution_notes: notes || 'Resolved' }),
    onSuccess: done,
    onError: failed,
  })
  const block = useMutation({
    mutationFn: () =>
      api.addBlock({ cidr: alert.src_ip!, reason: `Alert ${alert.id}: ${alert.title}`, minutes: 60 * 24 }),
    onSuccess: () => {
      toast.success(`Blocked ${alert.src_ip} for 24 hours`)
      client.invalidateQueries({ queryKey: ['blocks'] })
    },
    onError: failed,
  })
  if (alert.resolved) return null
  return (
    <div className="flex flex-wrap items-center gap-2">
      {!alert.acknowledged && (
        <button type="button" className="btn-secondary btn-sm" onClick={() => ack.mutate()}>
          Acknowledge
        </button>
      )}
      <input
        className="rounded-md border border-gray-300 px-2 py-1 text-sm"
        placeholder="Resolution notes"
        aria-label="Resolution notes"
        value={notes}
        onChange={(e) => setNotes(e.target.value)}
      />
      <button type="button" className="btn-primary btn-sm" onClick={() => resolve.mutate()}>
        Resolve
      </button>
      {alert.src_ip && (
        <button type="button" className="btn-danger btn-sm" onClick={() => block.mutate()}>
          Block source 24 h
        </button>
      )}
    </div>
  )
}

export function AlertDetail() {
  const { id } = useParams()
  const isAdmin = useIsAdmin()
  const alert = useQuery({
    queryKey: ['alerts', 'detail', Number(id)],
    queryFn: () => api.getAlert(Number(id)),
  })
  if (alert.isPending) return <Loading />
  if (alert.isError) return <ErrorMessage error={alert.error} />
  const a = alert.data
  const facts = alertFacts(a)
  const status = a.resolved ? 'Resolved' : a.acknowledged ? 'Acknowledged' : 'Open'

  return (
    <div className="space-y-6">
      <div>
        <Link to="/alerts" className="text-sm text-blue-700 hover:underline">
          ← All alerts
        </Link>
        <div className="mt-2 flex flex-wrap items-center gap-3">
          <SeverityPill severity={a.severity} />
          <h1 className="text-2xl font-bold text-gray-900">{a.title}</h1>
        </div>
        <p className="mt-1 text-sm text-gray-600">{a.description}</p>
      </div>

      {isAdmin && <Actions alert={a} />}

      <div className="grid gap-6 lg:grid-cols-2">
        <section className="card card-content" aria-label="Summary">
          <h2 className="mb-2 font-semibold">Summary</h2>
          <dl className="divide-y divide-gray-100">
            <Row label="Type">{a.alert_type.replace(/_/g, ' ')}</Row>
            <Row label="When">{formatServerTime(a.timestamp)}</Row>
            <Row label="Status">
              {status}
              {a.acknowledged_by ? ` by ${a.acknowledged_by}` : ''}
              {a.resolution_notes ? `: ${a.resolution_notes}` : ''}
            </Row>
            {a.src_ip && <Row label="Source">{a.src_ip}</Row>}
            {a.dst_ip && <Row label="Destination">{endpoint(a.dst_ip, a.dst_port)}</Row>}
            <Enrichment alert={a} />
          </dl>
        </section>

        <section className="card card-content" aria-label={`${a.alert_type} details`}>
          <h2 className="mb-2 font-semibold">{a.alert_type.replace(/_/g, ' ').toLowerCase()} details</h2>
          {facts.length ? (
            <dl className="divide-y divide-gray-100">
              {facts.map((f) => (
                <Row key={f.label} label={f.label}>
                  {f.value}
                </Row>
              ))}
            </dl>
          ) : (
            <p className="text-sm text-gray-500">No further details.</p>
          )}
          <button type="button" className="btn-secondary btn-sm mt-4" onClick={() => savePcap(a.id)}>
            Download pcap
          </button>
        </section>
      </div>

      <section className="card card-content" aria-label="Related events">
        <h2 className="mb-2 font-semibold">Related events</h2>
        <RelatedEvents alert={a} />
      </section>
    </div>
  )
}
