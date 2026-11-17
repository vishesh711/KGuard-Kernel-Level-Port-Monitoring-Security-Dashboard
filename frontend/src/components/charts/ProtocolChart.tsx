import { CHART } from './theme'

interface ProtocolChartProps {
  data: Record<string, number>
}

const COLORS: Record<string, string> = {
  TCP: CHART.blue,
  UDP: CHART.green,
  ICMP: CHART.amber,
  ICMPV6: CHART.violet,
}

/** Share of each protocol, as bars: readable even when one protocol is 99% of the traffic */
export function ProtocolChart({ data }: ProtocolChartProps) {
  const rows = Object.entries(data ?? {})
    .filter(([, count]) => count > 0)
    .sort((a, b) => b[1] - a[1])
  const total = rows.reduce((sum, [, count]) => sum + count, 0)

  if (total === 0) {
    return (
      <div className="flex h-40 flex-col items-center justify-center gap-1 text-center">
        <p className="text-sm font-medium text-gray-600">No protocol data yet</p>
        <p className="text-xs text-gray-500">Shows the mix of TCP, UDP and ICMP once events arrive.</p>
      </div>
    )
  }

  return (
    <ul className="flex min-h-[10rem] flex-col justify-center gap-4 py-2">
      {rows.map(([protocol, count]) => {
        const share = (count / total) * 100
        return (
          <li key={protocol}>
            <div className="mb-1.5 flex items-baseline justify-between text-sm">
              <span className="font-medium text-gray-800">{protocol}</span>
              <span className="font-mono text-xs tabular-nums text-gray-500">
                {count.toLocaleString()} · {share < 0.1 ? '<0.1' : share.toFixed(1)}%
              </span>
            </div>
            <div className="h-2 overflow-hidden rounded-full bg-gray-100">
              <div
                className="h-full rounded-full"
                style={{
                  width: `${Math.max(share, 1)}%`,
                  backgroundColor: COLORS[protocol.toUpperCase()] ?? CHART.slate,
                }}
              />
            </div>
          </li>
        )
      })}
    </ul>
  )
}
