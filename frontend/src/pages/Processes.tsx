import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import toast from 'react-hot-toast'
import { api } from '../services/api'
import { SocketInfo } from '../types'
import { useAgents } from '../hooks/queries'
import { useIsAdmin } from '../context/auth'
import { Empty, ErrorMessage, Loading } from '../components/ui/States'
import { endpoint, formatServerTime } from '../lib/format'

function Owner({ s }: { s: SocketInfo }) {
  if (!s.process) return <span className="text-gray-400">unknown</span>
  return (
    <span>
      {s.process} <span className="text-gray-400">({s.pid})</span>
    </span>
  )
}

export function Processes() {
  const isAdmin = useIsAdmin()
  const client = useQueryClient()
  const agents = useAgents()
  const [host, setHost] = useState(0)
  const sockets = useQuery({
    queryKey: ['sockets', host],
    queryFn: () => api.getSockets(host),
    refetchInterval: 3000,
  })
  const markKnown = useMutation({
    mutationFn: (s: SocketInfo) =>
      api.markListenerKnown({ host_id: host, proto: s.proto, port: s.lport, process: s.process ?? '' }),
    onSuccess: () => {
      toast.success('Marked as expected')
      client.invalidateQueries({ queryKey: ['sockets'] })
    },
  })

  const newOnes = sockets.data?.listeners.filter((l) => l.new).length ?? 0

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Processes</h1>
          <p className="mt-1 text-sm text-gray-600">
            Listening ports and connections with their process and user. A listener that was not there when
            KGuard first looked is highlighted until it is marked expected.
          </p>
        </div>
        <label className="text-xs text-gray-600">
          Host
          <select
            className="mt-1 block rounded-md border border-gray-300 px-2 py-1.5 text-sm"
            value={host}
            onChange={(e) => setHost(Number(e.target.value))}
          >
            <option value={0}>This server</option>
            {agents.data?.map((a) => (
              <option key={a.id} value={a.id}>
                {a.name}
              </option>
            ))}
          </select>
        </label>
      </div>

      {sockets.isPending ? (
        <Loading />
      ) : sockets.isError ? (
        <ErrorMessage error={sockets.error} />
      ) : (
        <>
          <p className="text-xs text-gray-500">
            {sockets.data.taken_at
              ? `As of ${formatServerTime(sockets.data.taken_at)}`
              : 'This agent has not reported its sockets yet.'}
            {newOnes > 0 && (
              <span className="ml-2 font-medium text-red-700">{newOnes} unexpected listener(s)</span>
            )}
          </p>
          <section className="card overflow-x-auto" aria-label="Listening ports">
            <h2 className="card-header text-sm font-semibold">Listening ports</h2>
            {sockets.data.listeners.length === 0 ? (
              <Empty>Nothing is listening.</Empty>
            ) : (
              <table className="min-w-full divide-y divide-gray-200 text-sm">
                <thead className="bg-gray-50 text-left text-xs uppercase text-gray-500">
                  <tr>
                    <th className="px-4 py-2">Protocol</th>
                    <th className="px-4 py-2">Address</th>
                    <th className="px-4 py-2">Process</th>
                    <th className="px-4 py-2">User</th>
                    <th className="px-4 py-2"></th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-100">
                  {sockets.data.listeners.map((s) => (
                    <tr
                      key={`${s.proto}-${s.local}-${s.lport}-${s.pid}`}
                      className={s.new ? 'bg-red-50' : undefined}
                      data-new={s.new ? 'true' : undefined}
                    >
                      <td className="px-4 py-2">{s.proto}</td>
                      <td className="px-4 py-2 font-mono">{endpoint(s.local, s.lport)}</td>
                      <td className="px-4 py-2">
                        <Owner s={s} />
                      </td>
                      <td className="px-4 py-2">{s.user ?? s.uid}</td>
                      <td className="px-4 py-2 text-right">
                        {s.new && (
                          <span className="mr-2 rounded bg-red-100 px-1.5 py-0.5 text-xs text-red-800">
                            new
                          </span>
                        )}
                        {s.new && isAdmin && (
                          <button
                            type="button"
                            className="btn-secondary btn-sm"
                            aria-label={`Mark ${s.proto} ${s.lport} expected`}
                            onClick={() => markKnown.mutate(s)}
                          >
                            Mark expected
                          </button>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </section>
          <section className="card overflow-x-auto" aria-label="Connections">
            <h2 className="card-header text-sm font-semibold">Connections</h2>
            {sockets.data.connections.length === 0 ? (
              <Empty>No connections.</Empty>
            ) : (
              <table className="min-w-full divide-y divide-gray-200 text-sm">
                <thead className="bg-gray-50 text-left text-xs uppercase text-gray-500">
                  <tr>
                    <th className="px-4 py-2">Protocol</th>
                    <th className="px-4 py-2">Local</th>
                    <th className="px-4 py-2">Remote</th>
                    <th className="px-4 py-2">State</th>
                    <th className="px-4 py-2">Process</th>
                    <th className="px-4 py-2">User</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-100">
                  {sockets.data.connections.map((s, i) => (
                    <tr key={`${s.proto}-${s.local}-${s.lport}-${s.remote}-${s.rport}-${i}`}>
                      <td className="px-4 py-2">{s.proto}</td>
                      <td className="px-4 py-2 font-mono">{endpoint(s.local, s.lport)}</td>
                      <td className="px-4 py-2 font-mono">{endpoint(s.remote, s.rport)}</td>
                      <td className="px-4 py-2 text-xs">{s.state}</td>
                      <td className="px-4 py-2">
                        <Owner s={s} />
                      </td>
                      <td className="px-4 py-2">{s.user ?? s.uid}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </section>
        </>
      )}
    </div>
  )
}
