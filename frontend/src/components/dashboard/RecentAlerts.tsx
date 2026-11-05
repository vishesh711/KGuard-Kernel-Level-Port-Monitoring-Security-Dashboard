import { SecurityAlert, AlertSeverity } from '../../types'
import { formatDistanceToNow } from 'date-fns'
import { parseServerDate } from '../../lib/time'
import { ExclamationTriangleIcon, ShieldExclamationIcon } from '@heroicons/react/24/outline'

interface RecentAlertsProps {
  alerts: SecurityAlert[]
}

export function RecentAlerts({ alerts }: RecentAlertsProps) {
  if (alerts.length === 0) {
    return (
      <div className="p-6 text-center text-gray-500">
        <p>No recent alerts</p>
      </div>
    )
  }

  const getSeverityColor = (severity: AlertSeverity) => {
    switch (severity) {
      case 'CRITICAL':
        return 'bg-red-100 text-red-800 border-red-200'
      case 'HIGH':
        return 'bg-orange-100 text-orange-800 border-orange-200'
      case 'MEDIUM':
        return 'bg-yellow-100 text-yellow-800 border-yellow-200'
      case 'LOW':
        return 'bg-blue-100 text-blue-800 border-blue-200'
      default:
        return 'bg-gray-100 text-gray-800 border-gray-200'
    }
  }

  const getSeverityIcon = (severity: AlertSeverity) => {
    if (severity === 'CRITICAL' || severity === 'HIGH') {
      return <ShieldExclamationIcon className="h-5 w-5" />
    }
    return <ExclamationTriangleIcon className="h-5 w-5" />
  }

  return (
    <div className="flow-root">
      <ul role="list" className="divide-y divide-gray-200">
        {alerts.map((alert) => (
          <li key={alert.id} className="px-6 py-4">
            <div className="flex items-start space-x-3">
              <div className="flex-shrink-0">
                <div
                  className={`inline-flex items-center justify-center w-8 h-8 rounded-full ${getSeverityColor(alert.severity)}`}
                >
                  {getSeverityIcon(alert.severity)}
                </div>
              </div>
              <div className="min-w-0 flex-1">
                <div className="flex items-center justify-between">
                  <p className="text-sm font-medium text-gray-900">{alert.title}</p>
                  <span
                    className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${getSeverityColor(alert.severity)}`}
                  >
                    {alert.severity}
                  </span>
                </div>
                <p className="text-sm text-gray-500 mt-1 line-clamp-2">{alert.description}</p>
                <div className="flex items-center justify-between mt-2">
                  <p className="text-xs text-gray-400">
                    {formatDistanceToNow(parseServerDate(alert.timestamp), { addSuffix: true })}
                  </p>
                  {alert.src_ip && <p className="text-xs text-gray-500 font-mono">{alert.src_ip}</p>}
                </div>
              </div>
            </div>
          </li>
        ))}
      </ul>
    </div>
  )
}
