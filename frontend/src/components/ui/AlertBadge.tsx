import { AlertSeverity } from '../../types'

interface AlertBadgeProps {
  count: number
  severity?: AlertSeverity
  size?: 'sm' | 'md' | 'lg'
}

export function AlertBadge({ count, severity = 'MEDIUM', size = 'sm' }: AlertBadgeProps) {
  const getSeverityColor = () => {
    switch (severity) {
      case 'CRITICAL':
        return 'bg-danger-600 text-white'
      case 'HIGH':
        return 'bg-warning-600 text-white'
      case 'MEDIUM':
        return 'bg-warning-500 text-white'
      case 'LOW':
        return 'bg-primary-500 text-white'
      default:
        return 'bg-gray-500 text-white'
    }
  }

  const getSizeClasses = () => {
    switch (size) {
      case 'sm':
        return 'h-4 w-4 text-xs'
      case 'md':
        return 'h-5 w-5 text-sm'
      case 'lg':
        return 'h-6 w-6 text-base'
      default:
        return 'h-4 w-4 text-xs'
    }
  }

  if (count === 0) return null

  return (
    <span className={`
      inline-flex items-center justify-center rounded-full font-medium
      ${getSeverityColor()} ${getSizeClasses()}
    `}>
      {count > 99 ? '99+' : count}
    </span>
  )
}