// A key number on the overview: title, value, and what it means

interface StatsCardProps {
  title: string
  value: string | number
  icon: React.ComponentType<{ className?: string }>
  loading?: boolean
  subtitle?: string
  color?: 'primary' | 'success' | 'warning' | 'danger'
  trend?: string
}

const ACCENTS = {
  primary: { bar: 'bg-primary-400', icon: 'text-primary-400' },
  success: { bar: 'bg-success-400', icon: 'text-success-400' },
  warning: { bar: 'bg-warning-400', icon: 'text-warning-400' },
  danger: { bar: 'bg-danger-400', icon: 'text-danger-400' },
}

export function StatsCard({
  title,
  value,
  icon: Icon,
  loading = false,
  subtitle,
  color = 'primary',
  trend,
}: StatsCardProps) {
  const accent = ACCENTS[color]
  return (
    <div className="card relative overflow-hidden">
      <span className={`absolute inset-x-0 top-0 h-0.5 ${accent.bar}`} aria-hidden="true" />
      <div className="px-5 py-4">
        <div className="flex items-start justify-between gap-x-3">
          <p className="text-[11px] font-semibold uppercase leading-4 tracking-wider text-gray-500">
            {title}
          </p>
          <Icon className={`h-5 w-5 shrink-0 ${accent.icon}`} aria-hidden="true" />
        </div>
        <div className="mt-2 flex items-baseline gap-x-2">
          {loading ? (
            <div className="h-8 w-20 animate-pulse rounded bg-gray-100" />
          ) : (
            <span className="font-mono text-3xl font-semibold tabular-nums text-gray-900">{value}</span>
          )}
          {trend && <span className="text-sm font-semibold text-success-600">{trend}</span>}
        </div>
        {subtitle && <p className="mt-1 text-xs text-gray-500">{subtitle}</p>}
      </div>
    </div>
  )
}
