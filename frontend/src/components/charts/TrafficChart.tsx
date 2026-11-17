import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Legend } from 'recharts'
import { TrafficSummary } from '../../types'
import { format } from 'date-fns'
import { parseServerDate } from '../../lib/time'
import { CHART } from './theme'

interface TrafficChartProps {
  data: TrafficSummary[]
}

const SERIES = [
  { key: 'total_packets', name: 'Total', color: CHART.blue },
  { key: 'tcp_packets', name: 'TCP', color: CHART.green },
  { key: 'udp_packets', name: 'UDP', color: CHART.amber },
  { key: 'suspicious_activity', name: 'Suspicious', color: CHART.red },
] as const

export function TrafficChart({ data }: TrafficChartProps) {
  const empty = !data || data.length === 0 || data.every((d) => !d.total_packets && !d.suspicious_activity)
  if (empty) {
    return (
      <div className="flex h-64 flex-col items-center justify-center gap-1 text-center">
        <p className="text-sm font-medium text-gray-600">No traffic recorded yet</p>
        <p className="text-xs text-gray-500">
          The chart fills in as the kernel module or agents send events.
        </p>
      </div>
    )
  }

  const chartData = data.map((item) => ({
    ...item,
    time: format(parseServerDate(item.timestamp), 'HH:mm'),
    fullTime: format(parseServerDate(item.timestamp), 'MMM dd, HH:mm'),
  }))

  return (
    <div className="h-64">
      <ResponsiveContainer width="100%" height="100%">
        <AreaChart data={chartData} margin={{ top: 4, right: 8, left: -12, bottom: 0 }}>
          <defs>
            {SERIES.map((s) => (
              <linearGradient key={s.key} id={`fill-${s.key}`} x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor={s.color} stopOpacity={0.35} />
                <stop offset="100%" stopColor={s.color} stopOpacity={0} />
              </linearGradient>
            ))}
          </defs>
          <CartesianGrid stroke={CHART.grid} vertical={false} />
          <XAxis
            dataKey="time"
            stroke={CHART.axis}
            fontSize={11}
            tickLine={false}
            axisLine={false}
            minTickGap={24}
          />
          <YAxis stroke={CHART.axis} fontSize={11} tickLine={false} axisLine={false} allowDecimals={false} />
          <Tooltip
            contentStyle={CHART.tooltip}
            labelStyle={{ color: CHART.text }}
            cursor={{ stroke: CHART.axis, strokeDasharray: '3 3' }}
            labelFormatter={(value, payload) => (payload && payload[0] ? payload[0].payload.fullTime : value)}
          />
          <Legend iconType="circle" iconSize={8} wrapperStyle={{ fontSize: 12, color: CHART.text }} />
          {SERIES.map((s) => (
            <Area
              key={s.key}
              type="monotone"
              dataKey={s.key}
              name={s.name}
              stroke={s.color}
              strokeWidth={2}
              fill={`url(#fill-${s.key})`}
              dot={false}
              activeDot={{ r: 3 }}
            />
          ))}
        </AreaChart>
      </ResponsiveContainer>
    </div>
  )
}
