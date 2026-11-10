import { formatDistanceToNow } from 'date-fns'
import { useAgents } from '../hooks/queries'
import { parseServerDate } from '../lib/time'
import { AgentInfo } from '../types'

const ENGINE_LABELS: Record<string, string> = {
  module: 'Kernel module',
  ebpf: 'eBPF',
}

function StatusPill({ online }: { online: boolean }) {
  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-full px-2.5 py-0.5 text-xs font-medium ${
        online ? 'bg-green-100 text-green-800' : 'bg-gray-100 text-gray-600'
      }`}
    >
      <span className={`h-1.5 w-1.5 rounded-full ${online ? 'bg-green-500' : 'bg-gray-400'}`} />
      {online ? 'Online' : 'Offline'}
    </span>
  )
}

function BlocklistState({ agent }: { agent: AgentInfo }) {
  const b = agent.blocklist
  if (!b?.synced_at) return <span className="text-gray-400">never synced</span>
  if (b.enforcing === false) return <span className="text-yellow-700">monitor only</span>
  if (b.failed) return <span className="text-red-700">{b.failed} not applied</span>
  return <span className="text-green-700">enforcing</span>
}

function HostRow({ agent }: { agent: AgentInfo }) {
  const lost = agent.kernel_dropped + agent.queue_dropped
  return (
    <tr>
      <td className="px-4 py-3">
        <div className="font-medium text-gray-900">{agent.name}</div>
        <div className="text-xs text-gray-500">{agent.hostname ?? '—'}</div>
      </td>
      <td className="px-4 py-3">
        <StatusPill online={agent.online} />
      </td>
      <td className="px-4 py-3 text-sm text-gray-700">
        {agent.engine ? (ENGINE_LABELS[agent.engine] ?? agent.engine) : '—'}
        {agent.version && <span className="ml-1 text-xs text-gray-400">v{agent.version}</span>}
      </td>
      <td className="px-4 py-3 text-sm text-gray-700">
        {agent.last_seen
          ? formatDistanceToNow(parseServerDate(agent.last_seen), { addSuffix: true })
          : 'Never'}
      </td>
      <td className="px-4 py-3 text-right text-sm tabular-nums text-gray-900">
        {(agent.events_per_second ?? 0).toLocaleString(undefined, { maximumFractionDigits: 1 })}
      </td>
      <td className="px-4 py-3 text-right text-sm tabular-nums text-gray-900">
        {agent.events_received.toLocaleString()}
      </td>
      <td
        className={`px-4 py-3 text-right text-sm tabular-nums ${lost ? 'text-red-700' : 'text-gray-500'}`}
        title={`Kernel: ${agent.kernel_dropped}, agent queue: ${agent.queue_dropped}`}
      >
        {lost.toLocaleString()}
      </td>
      <td className="px-4 py-3 text-sm">
        <BlocklistState agent={agent} />
      </td>
    </tr>
  )
}

export function Hosts() {
  const agents = useAgents()

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-gray-900">Hosts</h1>
        <p className="mt-1 text-sm text-gray-600">Servers sending events through kguard-agent</p>
      </div>

      <div className="card overflow-x-auto">
        {agents.isError ? (
          <p className="card-content text-sm text-red-700">Could not load hosts from the backend.</p>
        ) : agents.data && agents.data.length === 0 ? (
          <div className="card-content space-y-2 text-sm text-gray-600">
            <p className="font-medium text-gray-900">No agents yet</p>
            <p>
              Set <code className="font-mono">AGENT_ENROLLMENT_KEY</code> on the backend, then on each server
              run:
            </p>
            <pre className="overflow-x-auto rounded bg-gray-50 p-3 font-mono text-xs text-gray-800">
              {'sudo kguard-agent enroll --server https://BACKEND --key KEY --name web-1\n' +
                'sudo kguard-agent run --engine ebpf --server https://BACKEND'}
            </pre>
          </div>
        ) : (
          <table className="min-w-full divide-y divide-gray-200">
            <thead className="bg-gray-50">
              <tr className="text-left text-xs font-medium uppercase tracking-wide text-gray-500">
                <th className="px-4 py-3">Host</th>
                <th className="px-4 py-3">Status</th>
                <th className="px-4 py-3">Engine</th>
                <th className="px-4 py-3">Last seen</th>
                <th className="px-4 py-3 text-right">Events/s</th>
                <th className="px-4 py-3 text-right">Events</th>
                <th className="px-4 py-3 text-right">Lost</th>
                <th className="px-4 py-3">Blocklist</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-200 bg-white">
              {(agents.data ?? []).map((agent) => (
                <HostRow key={agent.id} agent={agent} />
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  )
}
