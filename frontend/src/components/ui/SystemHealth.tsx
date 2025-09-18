import { useQuery } from '@tanstack/react-query'
import { CheckCircleIcon, ExclamationCircleIcon, XCircleIcon } from '@heroicons/react/24/outline'
import { api } from '../../services/api'

export function SystemHealth() {
  const { data: health, isLoading } = useQuery({
    queryKey: ['health'],
    queryFn: () => api.getHealth(),
    refetchInterval: 30000, // Refresh every 30 seconds
  })

  if (isLoading) {
    return (
      <div className="flex items-center space-x-2">
        <div className="h-4 w-4 animate-spin rounded-full border-2 border-gray-300 border-t-primary-600"></div>
        <span className="text-sm text-gray-600">Checking...</span>
      </div>
    )
  }

  const getStatusIcon = () => {
    switch (health?.status) {
      case 'healthy':
        return <CheckCircleIcon className="h-4 w-4 text-success-600" />
      case 'degraded':
        return <ExclamationCircleIcon className="h-4 w-4 text-warning-600" />
      case 'unhealthy':
        return <XCircleIcon className="h-4 w-4 text-danger-600" />
      default:
        return <XCircleIcon className="h-4 w-4 text-gray-400" />
    }
  }

  const getStatusText = () => {
    switch (health?.status) {
      case 'healthy':
        return 'System Healthy'
      case 'degraded':
        return 'System Degraded'
      case 'unhealthy':
        return 'System Unhealthy'
      default:
        return 'Unknown Status'
    }
  }

  const getStatusColor = () => {
    switch (health?.status) {
      case 'healthy':
        return 'text-success-600'
      case 'degraded':
        return 'text-warning-600'
      case 'unhealthy':
        return 'text-danger-600'
      default:
        return 'text-gray-600'
    }
  }

  return (
    <div className="flex items-center space-x-2">
      {getStatusIcon()}
      <span className={`text-sm font-medium ${getStatusColor()}`}>
        {getStatusText()}
      </span>
    </div>
  )
}