import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip, Legend } from 'recharts'

interface ProtocolChartProps {
  data: Record<string, number>
}

const COLORS = {
  TCP: '#3b82f6',
  UDP: '#10b981',
  ICMP: '#f59e0b',
  OTHER: '#6b7280',
}

export function ProtocolChart({ data }: ProtocolChartProps) {
  if (!data || Object.keys(data).length === 0) {
    return (
      <div className="h-64 flex items-center justify-center text-gray-500">
        <p>No protocol data available</p>
      </div>
    )
  }

  const chartData = Object.entries(data).map(([protocol, count]) => ({
    name: protocol,
    value: count,
    color: COLORS[protocol as keyof typeof COLORS] || COLORS.OTHER,
  }))

  const total = chartData.reduce((sum, item) => sum + item.value, 0)

  return (
    <div className="h-64">
      <ResponsiveContainer width="100%" height="100%">
        <PieChart>
          <Pie
            data={chartData}
            cx="50%"
            cy="50%"
            innerRadius={40}
            outerRadius={80}
            paddingAngle={2}
            dataKey="value"
          >
            {chartData.map((entry, index) => (
              <Cell key={`cell-${index}`} fill={entry.color} />
            ))}
          </Pie>
          <Tooltip 
            contentStyle={{
              backgroundColor: '#fff',
              border: '1px solid #e5e7eb',
              borderRadius: '6px',
              boxShadow: '0 4px 6px -1px rgba(0, 0, 0, 0.1)',
            }}
            formatter={(value: number) => [
              `${value} (${((value / total) * 100).toFixed(1)}%)`,
              'Count'
            ]}
          />
          <Legend 
            verticalAlign="bottom" 
            height={36}
            formatter={(value, entry) => (
              <span style={{ color: entry.color }}>
                {value}
              </span>
            )}
          />
        </PieChart>
      </ResponsiveContainer>
    </div>
  )
}