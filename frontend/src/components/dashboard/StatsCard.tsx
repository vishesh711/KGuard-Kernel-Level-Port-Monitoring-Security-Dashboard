// StatsCard component for displaying statistics

interface StatsCardProps {
  title: string
  value: string | number
  icon: React.ComponentType<{ className?: string }>
  loading?: boolean
  subtitle?: string
  color?: 'primary' | 'success' | 'warning' | 'danger'
  trend?: string
}

export function StatsCard({ 
  title, 
  value, 
  icon: Icon, 
  loading = false, 
  subtitle, 
  color = 'primary',
  trend 
}: StatsCardProps) {
  const getColorClasses = () => {
    switch (color) {
      case 'success':
        return 'text-success-600 bg-success-50'
      case 'warning':
        return 'text-warning-600 bg-warning-50'
      case 'danger':
        return 'text-danger-600 bg-danger-50'
      default:
        return 'text-primary-600 bg-primary-50'
    }
  }

  return (
    <div className="card">
      <div className="card-content">
        <div className="flex items-center">
          <div className="flex-shrink-0">
            <div className={`inline-flex items-center justify-center p-3 rounded-lg ${getColorClasses()}`}>
              <Icon className="h-6 w-6" aria-hidden="true" />
            </div>
          </div>
          <div className="ml-5 w-0 flex-1">
            <dl>
              <dt className="text-sm font-medium text-gray-500 truncate">
                {title}
              </dt>
              <dd className="flex items-baseline">
                <div className="text-2xl font-semibold text-gray-900">
                  {loading ? (
                    <div className="h-8 w-16 bg-gray-200 rounded animate-pulse"></div>
                  ) : (
                    value
                  )}
                </div>
                {trend && (
                  <div className="ml-2 flex items-baseline text-sm font-semibold text-success-600">
                    {trend}
                  </div>
                )}
              </dd>
              {subtitle && (
                <dd className="text-sm text-gray-500">
                  {subtitle}
                </dd>
              )}
            </dl>
          </div>
        </div>
      </div>
    </div>
  )
}