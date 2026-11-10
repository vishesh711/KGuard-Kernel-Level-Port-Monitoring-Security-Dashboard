import { useQuery } from '@tanstack/react-query'
import { api } from '../services/api'
import { compactNumber } from '../lib/format'

function Stat({ label, value, warn = false }: { label: string; value: string; warn?: boolean }) {
  return (
    <div>
      <dt className="text-xs text-gray-500">{label}</dt>
      <dd className={`text-lg font-semibold tabular-nums ${warn ? 'text-red-700' : 'text-gray-900'}`}>
        {value}
      </dd>
    </div>
  )
}

/** The kernel module's counters on this server (the numbers in /sys/kernel/debug/kguard/stats) */
export function KernelHealth() {
  const counters = useQuery({
    queryKey: ['kernel', 'counters'],
    queryFn: () => api.getKernelCounters(),
    refetchInterval: 5000,
  })
  const c = counters.data
  return (
    <section className="card" aria-label="Kernel module">
      <h2 className="card-header text-sm font-semibold">Kernel module on this server</h2>
      <div className="card-content">
        {!c ? (
          <p className="text-sm text-gray-500">Loading…</p>
        ) : !c.available ? (
          <p className="text-sm text-gray-500">Not available: {c.reason}</p>
        ) : (
          <dl className="grid grid-cols-2 gap-4 sm:grid-cols-4 lg:grid-cols-6">
            <Stat label="Packets seen" value={compactNumber(c.stats!.packets ?? 0)} />
            <Stat label="Events written" value={compactNumber(c.stats!.events ?? 0)} />
            <Stat
              label="Events dropped"
              value={compactNumber(c.stats!.dropped ?? 0)}
              warn={(c.stats!.dropped ?? 0) > 0}
            />
            <Stat
              label="Buffer fill"
              value={
                c.ring_capacity
                  ? `${(((c.stats!.ring_fill ?? 0) / c.ring_capacity) * 100).toFixed(1)}%`
                  : String(c.stats!.ring_fill ?? 0)
              }
            />
            <Stat label="ns per packet" value={String(c.stats!.ns_per_packet ?? 0)} />
            <Stat label="Mode" value={c.enforcing ? 'enforcing' : 'monitor only'} />
            <Stat label="Sources tracked" value={compactNumber(c.stats!.sources ?? 0)} />
            <Stat label="Blocked addresses" value={String(c.stats!.blocks ?? 0)} />
            <Stat label="Dropped (blocked)" value={compactNumber(c.stats!.block_drops ?? 0)} />
            <Stat label="Dropped (SYN rate)" value={compactNumber(c.stats!.rate_drops ?? 0)} />
            <Stat label="Spoofed packets" value={compactNumber(c.stats!.spoofed ?? 0)} />
            <Stat label="Kernel alerts" value={compactNumber(c.stats!.alerts ?? 0)} />
          </dl>
        )}
      </div>
    </section>
  )
}
