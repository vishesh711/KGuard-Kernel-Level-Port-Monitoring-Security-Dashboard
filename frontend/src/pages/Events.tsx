import { FormEvent, useState } from 'react'
import { keepPreviousData, useQuery } from '@tanstack/react-query'
import { api } from '../services/api'
import { FilterOptions, NetworkEvent } from '../types'
import { EMPTY_EVENT_FILTERS, EventFilterForm, toFilters } from '../lib/filters'
import { endpoint, formatEventTime, tcpFlags } from '../lib/format'
import { Pagination } from '../components/ui/Pagination'
import { Empty, ErrorMessage, Loading } from '../components/ui/States'
import { useAgents } from '../hooks/queries'

const PAGE_SIZE = 50

const DIRECTION: Record<string, string> = { in: '→ in', out: '← out', fwd: '⇄ fwd' }

function EventRow({ event, host }: { event: NetworkEvent; host: string }) {
  return (
    <tr className={event.is_suspicious ? 'bg-red-50' : undefined}>
      <td className="whitespace-nowrap px-3 py-2 font-mono text-xs text-gray-600">
        {formatEventTime(event.timestamp)}
      </td>
      <td className="px-3 py-2 text-xs text-gray-600">{host}</td>
      <td className="px-3 py-2 text-xs text-gray-600">
        {event.direction ? DIRECTION[event.direction] : '—'}
      </td>
      <td className="px-3 py-2 font-mono text-xs">{endpoint(event.src_ip, event.src_port)}</td>
      <td className="px-3 py-2 font-mono text-xs">{endpoint(event.dst_ip, event.dst_port)}</td>
      <td className="px-3 py-2 text-xs">
        {event.protocol}
        <span className="ml-1 text-gray-400">{tcpFlags(event.protocol, event.flags)}</span>
      </td>
      <td className="px-3 py-2 text-xs text-gray-600">{event.ct_state ?? '—'}</td>
      <td className="px-3 py-2 text-xs">
        {event.process_name ? (
          <span>
            {event.process_name}
            {event.pid ? <span className="text-gray-400"> ({event.pid})</span> : null}
          </span>
        ) : (
          <span className="text-gray-400">—</span>
        )}
      </td>
      <td className="px-3 py-2 text-xs">
        {event.is_suspicious ? (
          <span className="rounded bg-red-100 px-1.5 py-0.5 text-red-800">
            {event.event_type || 'suspicious'}
          </span>
        ) : null}
      </td>
    </tr>
  )
}

export function Events() {
  const [form, setForm] = useState<EventFilterForm>(EMPTY_EVENT_FILTERS)
  const [filters, setFilters] = useState<FilterOptions>({})
  const [page, setPage] = useState(1)
  const agents = useAgents()

  const events = useQuery({
    queryKey: ['events', 'list', page, filters],
    queryFn: () => api.getEvents({ page, size: PAGE_SIZE, filters }),
    placeholderData: keepPreviousData,
    refetchInterval: 30_000,
  })

  const hostName = (id: number | null | undefined) =>
    id === null || id === undefined
      ? 'this server'
      : (agents.data?.find((a) => a.id === id)?.name ?? `agent ${id}`)

  const apply = (e: FormEvent) => {
    e.preventDefault()
    setFilters(toFilters(form))
    setPage(1)
  }
  const set = (key: keyof EventFilterForm) => (e: { target: { value: string } }) =>
    setForm({ ...form, [key]: e.target.value })
  const input = 'rounded-md border border-gray-300 px-2 py-1.5 text-sm'

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-gray-900">Network Events</h1>
        <p className="mt-1 text-sm text-gray-600">Every connection the kernel module and agents report</p>
      </div>

      <form
        onSubmit={apply}
        className="card card-content flex flex-wrap items-end gap-3"
        aria-label="Filters"
      >
        <label className="text-xs text-gray-600">
          Source IP
          <input className={`${input} mt-1 block w-36`} value={form.src_ip} onChange={set('src_ip')} />
        </label>
        <label className="text-xs text-gray-600">
          Destination IP
          <input className={`${input} mt-1 block w-36`} value={form.dst_ip} onChange={set('dst_ip')} />
        </label>
        <label className="text-xs text-gray-600">
          Port
          <input
            className={`${input} mt-1 block w-20`}
            inputMode="numeric"
            pattern="[0-9]*"
            value={form.dst_port}
            onChange={set('dst_port')}
          />
        </label>
        <label className="text-xs text-gray-600">
          Protocol
          <select className={`${input} mt-1 block`} value={form.protocol} onChange={set('protocol')}>
            <option value="">Any</option>
            {['TCP', 'UDP', 'ICMP', 'ICMPv6'].map((p) => (
              <option key={p}>{p}</option>
            ))}
          </select>
        </label>
        <label className="text-xs text-gray-600">
          Direction
          <select className={`${input} mt-1 block`} value={form.direction} onChange={set('direction')}>
            <option value="">Any</option>
            <option value="in">In</option>
            <option value="out">Out</option>
            <option value="fwd">Forwarded</option>
          </select>
        </label>
        <label className="text-xs text-gray-600">
          Process
          <input
            className={`${input} mt-1 block w-28`}
            value={form.process_name}
            onChange={set('process_name')}
          />
        </label>
        <label className="text-xs text-gray-600">
          Host
          <select className={`${input} mt-1 block`} value={form.host_id} onChange={set('host_id')}>
            <option value="">All</option>
            <option value="0">This server</option>
            {agents.data?.map((a) => (
              <option key={a.id} value={a.id}>
                {a.name}
              </option>
            ))}
          </select>
        </label>
        <label className="text-xs text-gray-600">
          Suspicious
          <select className={`${input} mt-1 block`} value={form.suspicious} onChange={set('suspicious')}>
            <option value="">Any</option>
            <option value="yes">Only suspicious</option>
            <option value="no">Only normal</option>
          </select>
        </label>
        <button type="submit" className="btn-primary btn-sm">
          Apply
        </button>
        <button
          type="button"
          className="btn-secondary btn-sm"
          onClick={() => {
            setForm(EMPTY_EVENT_FILTERS)
            setFilters({})
            setPage(1)
          }}
        >
          Clear
        </button>
      </form>

      <div className="card overflow-hidden">
        {events.isPending ? (
          <Loading />
        ) : events.isError ? (
          <ErrorMessage error={events.error} />
        ) : events.data.items.length === 0 ? (
          <Empty>No events match.</Empty>
        ) : (
          <>
            <div className="overflow-x-auto">
              <table className="min-w-full divide-y divide-gray-200">
                <thead className="bg-gray-50 text-left text-xs font-medium uppercase text-gray-500">
                  <tr>
                    <th className="px-3 py-2">Time</th>
                    <th className="px-3 py-2">Host</th>
                    <th className="px-3 py-2">Dir</th>
                    <th className="px-3 py-2">Source</th>
                    <th className="px-3 py-2">Destination</th>
                    <th className="px-3 py-2">Protocol</th>
                    <th className="px-3 py-2">State</th>
                    <th className="px-3 py-2">Process</th>
                    <th className="px-3 py-2"></th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-100 bg-white">
                  {events.data.items.map((e) => (
                    <EventRow key={e.id} event={e} host={hostName(e.host_id)} />
                  ))}
                </tbody>
              </table>
            </div>
            <Pagination
              page={events.data.page}
              pages={events.data.pages}
              total={events.data.total}
              onPage={setPage}
            />
          </>
        )}
      </div>
    </div>
  )
}
