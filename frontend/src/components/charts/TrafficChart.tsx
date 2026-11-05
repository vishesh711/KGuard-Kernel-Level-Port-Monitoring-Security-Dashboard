import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts'
import { TrafficSummary } from '../../types'
import { format } from 'date-fns'
import { parseServerDate } from '../../lib/time'

interface TrafficChartProps {
  data: TrafficSummary[]
}

export function TrafficChart({ data }: TrafficChartProps) {
  if (!data || data.length === 0) {
    return (
      <div className="h-64 flex items-center justify-center text-gray-500">
        <p>No traffic data available</p>
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
        <LineChart data={chartData}>
          <CartesianGrid strokeDasharray="3 3" stroke="#f0f0f0" />
          <XAxis dataKey="time" stroke="#6b7280" fontSize={12} tickLine={false} />
          <YAxis stroke="#6b7280" fontSize={12} tickLine={false} axisLine={false} />
          <Tooltip
            contentStyle={{
              backgroundColor: '#fff',
              border: '1px solid #e5e7eb',
              borderRadius: '6px',
              boxShadow: '0 4px 6px -1px rgba(0, 0, 0, 0.1)',
            }}
            labelFormatter={(value, payload) => {
              if (payload && payload[0]) {
                return payload[0].payload.fullTime
              }
              return value
            }}
          />
          <Line
            type="monotone"
            dataKey="total_packets"
            stroke="#3b82f6"
            strokeWidth={2}
            dot={false}
            name="Total Packets"
          />
          <Line
            type="monotone"
            dataKey="tcp_packets"
            stroke="#10b981"
            strokeWidth={2}
            dot={false}
            name="TCP"
          />
          <Line
            type="monotone"
            dataKey="udp_packets"
            stroke="#f59e0b"
            strokeWidth={2}
            dot={false}
            name="UDP"
          />
          <Line
            type="monotone"
            dataKey="suspicious_activity"
            stroke="#ef4444"
            strokeWidth={2}
            dot={false}
            name="Suspicious"
          />
        </LineChart>
      </ResponsiveContainer>
    </div>
  )
}
