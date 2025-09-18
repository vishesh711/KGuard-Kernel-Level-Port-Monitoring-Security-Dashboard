import { WifiIcon, ExclamationTriangleIcon } from '@heroicons/react/24/outline'

export function ConnectionStatus() {
  // Simplified version without WebSocket for now
  const connectionStatus = { connected: false, reconnecting: false, error: null }

  const getStatusColor = () => {
    if (connectionStatus.connected) return 'text-green-600'
    if (connectionStatus.reconnecting) return 'text-yellow-600'
    return 'text-red-600'
  }

  const getStatusText = () => {
    if (connectionStatus.connected) return 'Connected'
    if (connectionStatus.reconnecting) return 'Reconnecting...'
    return 'Disconnected'
  }

  const getStatusIcon = () => {
    if (connectionStatus.connected) {
      return <WifiIcon className="h-4 w-4" />
    }
    return <ExclamationTriangleIcon className="h-4 w-4" />
  }

  return (
    <div className="flex items-center space-x-2 px-3 py-2 rounded-md bg-gray-50">
      <div className={`${getStatusColor()}`}>
        {getStatusIcon()}
      </div>
      <div className="flex flex-col">
        <span className={`text-xs font-medium ${getStatusColor()}`}>
          {getStatusText()}
        </span>
        {connectionStatus.error && (
          <span className="text-xs text-gray-500 truncate">
            {connectionStatus.error}
          </span>
        )}
      </div>
    </div>
  )
}