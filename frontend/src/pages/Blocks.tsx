import { FormEvent, useState } from 'react'
import { Link } from 'react-router-dom'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { isAxiosError } from 'axios'
import toast from 'react-hot-toast'
import { api } from '../services/api'
import { useIsAdmin } from '../context/auth'
import { useAgents } from '../hooks/queries'
import { Empty, ErrorMessage, Loading } from '../components/ui/States'
import { formatServerTime, timeLeft } from '../lib/format'

function detail(e: unknown): string {
  if (isAxiosError(e)) {
    const d = e.response?.data?.detail
    return typeof d === 'string' ? d : e.message
  }
  return 'Failed'
}

function AddBlock() {
  const client = useQueryClient()
  const agents = useAgents()
  const [cidr, setCidr] = useState('')
  const [reason, setReason] = useState('')
  const [minutes, setMinutes] = useState('60')
  const [host, setHost] = useState('')
  const add = useMutation({
    mutationFn: () =>
      api.addBlock({
        cidr: cidr.trim(),
        reason: reason.trim(),
        minutes: minutes ? Number(minutes) : null,
        host_id: host ? Number(host) : null,
      }),
    onSuccess: (b) => {
      toast.success(b.created ? `Blocked ${b.cidr}` : `${b.cidr} was already blocked; kept the later expiry`)
      setCidr('')
      setReason('')
      client.invalidateQueries({ queryKey: ['blocks'] })
    },
    onError: (e) => toast.error(detail(e)),
  })
  const submit = (e: FormEvent) => {
    e.preventDefault()
    add.mutate()
  }
  const input = 'mt-1 block rounded-md border border-gray-300 px-2 py-1.5 text-sm'
  return (
    <form
      onSubmit={submit}
      className="card card-content flex flex-wrap items-end gap-3"
      aria-label="Block an address"
    >
      <label className="text-xs text-gray-600">
        Address or prefix
        <input
          className={`${input} w-48`}
          placeholder="203.0.113.7 or 203.0.113.0/24"
          required
          value={cidr}
          onChange={(e) => setCidr(e.target.value)}
        />
      </label>
      <label className="flex-1 text-xs text-gray-600">
        Reason
        <input
          className={`${input} w-full`}
          required
          value={reason}
          onChange={(e) => setReason(e.target.value)}
        />
      </label>
      <label className="text-xs text-gray-600">
        For
        <select className={input} value={minutes} onChange={(e) => setMinutes(e.target.value)}>
          <option value="60">1 hour</option>
          <option value="1440">1 day</option>
          <option value="10080">1 week</option>
          <option value="">Until unblocked</option>
        </select>
      </label>
      <label className="text-xs text-gray-600">
        On
        <select className={input} value={host} onChange={(e) => setHost(e.target.value)}>
          <option value="">Every host</option>
          {agents.data?.map((a) => (
            <option key={a.id} value={a.id}>
              {a.name}
            </option>
          ))}
        </select>
      </label>
      <button type="submit" className="btn-danger btn-sm" disabled={add.isPending}>
        Block
      </button>
    </form>
  )
}

function Allowlist({ isAdmin }: { isAdmin: boolean }) {
  const client = useQueryClient()
  const [cidr, setCidr] = useState('')
  const [note, setNote] = useState('')
  const entries = useQuery({ queryKey: ['blocks', 'allowlist'], queryFn: () => api.getAllowlist() })
  const refresh = () => client.invalidateQueries({ queryKey: ['blocks'] })
  const add = useMutation({
    mutationFn: () => api.addAllow({ cidr: cidr.trim(), note: note.trim() }),
    onSuccess: () => {
      setCidr('')
      setNote('')
      refresh()
    },
    onError: (e) => toast.error(detail(e)),
  })
  const remove = useMutation({ mutationFn: (id: number) => api.removeAllow(id), onSuccess: refresh })
  return (
    <section className="card" aria-label="Allowlist">
      <h2 className="card-header text-sm font-semibold">Never block (allowlist)</h2>
      <div className="card-content space-y-3">
        {entries.isPending ? (
          <Loading />
        ) : entries.isError ? (
          <ErrorMessage error={entries.error} />
        ) : entries.data.length === 0 ? (
          <p className="text-sm text-gray-500">Empty.</p>
        ) : (
          <ul className="divide-y divide-gray-100 text-sm">
            {entries.data.map((e) => (
              <li key={e.id} className="flex items-center justify-between py-1.5">
                <span>
                  <span className="font-mono">{e.cidr}</span>
                  {e.note && <span className="ml-2 text-gray-500">{e.note}</span>}
                </span>
                {isAdmin && (
                  <button
                    type="button"
                    className="text-xs text-red-700 hover:underline"
                    onClick={() => remove.mutate(e.id)}
                  >
                    Remove
                  </button>
                )}
              </li>
            ))}
          </ul>
        )}
        {isAdmin && (
          <form
            className="flex gap-2"
            onSubmit={(e) => {
              e.preventDefault()
              add.mutate()
            }}
          >
            <input
              aria-label="Allow address or prefix"
              className="w-40 rounded-md border border-gray-300 px-2 py-1 text-sm"
              placeholder="10.0.0.0/8"
              required
              value={cidr}
              onChange={(e) => setCidr(e.target.value)}
            />
            <input
              aria-label="Note"
              className="flex-1 rounded-md border border-gray-300 px-2 py-1 text-sm"
              placeholder="Note"
              value={note}
              onChange={(e) => setNote(e.target.value)}
            />
            <button type="submit" className="btn-secondary btn-sm">
              Allow
            </button>
          </form>
        )}
      </div>
    </section>
  )
}

function AuditLog() {
  const audit = useQuery({ queryKey: ['blocks', 'audit'], queryFn: () => api.getAudit(1, 20) })
  return (
    <section className="card" aria-label="Audit log">
      <h2 className="card-header text-sm font-semibold">Audit log</h2>
      <div className="card-content">
        {audit.isPending ? (
          <Loading />
        ) : audit.isError ? (
          <ErrorMessage error={audit.error} />
        ) : audit.data.items.length === 0 ? (
          <p className="text-sm text-gray-500">Nothing yet.</p>
        ) : (
          <ul className="space-y-1 text-xs">
            {audit.data.items.map((e) => (
              <li key={e.id}>
                <span className="text-gray-500">{formatServerTime(e.time)}</span> <strong>{e.actor}</strong>{' '}
                {e.action.replace(/_/g, ' ')} <span className="font-mono">{e.target}</span>
              </li>
            ))}
          </ul>
        )}
      </div>
    </section>
  )
}

export function Blocks() {
  const isAdmin = useIsAdmin()
  const client = useQueryClient()
  const agents = useAgents()
  const [history, setHistory] = useState(false)
  const blocks = useQuery({
    queryKey: ['blocks', 'list', history],
    queryFn: () => api.getBlocks(history),
    refetchInterval: 15_000,
  })
  const status = useQuery({ queryKey: ['blocks', 'status'], queryFn: () => api.getResponseStatus() })
  const unblock = useMutation({
    mutationFn: (id: number) => api.removeBlock(id),
    onSuccess: (b) => {
      toast.success(`Unblocked ${b.cidr}`)
      client.invalidateQueries({ queryKey: ['blocks'] })
    },
    onError: (e) => toast.error(detail(e)),
  })
  const hostName = (id: number | null) =>
    id === null ? 'every host' : (agents.data?.find((a) => a.id === id)?.name ?? `agent ${id}`)

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-gray-900">Blocked Addresses</h1>
        <p className="mt-1 text-sm text-gray-600">
          Agents drop these in XDP or with the kernel module; changes reach them within seconds.
        </p>
      </div>

      {status.data && (
        <div className="flex flex-wrap gap-2 text-xs" aria-label="Enforcement">
          <span className="rounded bg-gray-100 px-2 py-1">This server: {status.data.local.status}</span>
          {status.data.agents.map((a) => (
            <span
              key={a.id}
              className={`rounded px-2 py-1 ${a.in_sync && a.enforcing !== false ? 'bg-green-50 text-green-800' : 'bg-yellow-50 text-yellow-800'}`}
            >
              {a.name}: {a.in_sync ? 'up to date' : 'not yet applied'}
              {a.enforcing === false ? ' (monitor only)' : ''}
              {a.failed ? `, ${a.failed} failed` : ''}
            </span>
          ))}
          <span className="rounded bg-gray-100 px-2 py-1">
            Automatic blocking: {status.data.rules.auto_block ? 'on' : 'off'}
          </span>
        </div>
      )}

      {isAdmin && <AddBlock />}

      <div className="card overflow-hidden">
        <div className="flex items-center justify-between border-b px-4 py-2">
          <h2 className="text-sm font-semibold">{history ? 'All blocks' : 'Active blocks'}</h2>
          <label className="flex items-center gap-2 text-xs text-gray-600">
            <input type="checkbox" checked={history} onChange={(e) => setHistory(e.target.checked)} />
            Show history
          </label>
        </div>
        {blocks.isPending ? (
          <Loading />
        ) : blocks.isError ? (
          <ErrorMessage error={blocks.error} />
        ) : blocks.data.length === 0 ? (
          <Empty>Nothing is blocked.</Empty>
        ) : (
          <table className="min-w-full divide-y divide-gray-200 text-sm">
            <thead className="bg-gray-50 text-left text-xs uppercase text-gray-500">
              <tr>
                <th className="px-4 py-2">Address</th>
                <th className="px-4 py-2">Reason</th>
                <th className="px-4 py-2">By</th>
                <th className="px-4 py-2">On</th>
                <th className="px-4 py-2">Since</th>
                <th className="px-4 py-2">Expires</th>
                <th className="px-4 py-2"></th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-100">
              {blocks.data.map((b) => (
                <tr key={b.id} className={b.active ? undefined : 'text-gray-400'}>
                  <td className="px-4 py-2 font-mono">{b.cidr}</td>
                  <td className="px-4 py-2">
                    {b.reason}
                    {b.alert_id && (
                      <Link
                        to={`/alerts/${b.alert_id}`}
                        className="ml-2 text-xs text-blue-700 hover:underline"
                      >
                        alert {b.alert_id}
                      </Link>
                    )}
                  </td>
                  <td className="px-4 py-2">
                    {b.created_by}
                    {b.source === 'auto' && (
                      <span className="ml-1 rounded bg-purple-50 px-1 text-xs text-purple-700">auto</span>
                    )}
                  </td>
                  <td className="px-4 py-2">{hostName(b.host_id)}</td>
                  <td className="px-4 py-2 text-xs">{formatServerTime(b.created_at)}</td>
                  <td className="px-4 py-2">{timeLeft(b)}</td>
                  <td className="px-4 py-2 text-right">
                    {isAdmin && b.active && (
                      <button
                        type="button"
                        className="btn-secondary btn-sm"
                        aria-label={`Unblock ${b.cidr}`}
                        onClick={() => unblock.mutate(b.id)}
                      >
                        Unblock
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      <div className="grid gap-6 lg:grid-cols-2">
        <Allowlist isAdmin={isAdmin} />
        <AuditLog />
      </div>
    </div>
  )
}
