import { WifiIcon, ExclamationTriangleIcon } from '@heroicons/react/24/outline'
import { useLiveStatus } from '../../context/liveStatus'

export function ConnectionStatus() {
  const connectionStatus = useLiveStatus()

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

  return (
    <div className="flex items-center space-x-2 px-3 py-2 rounded-md bg-gray-50">
      <div className={getStatusColor()}>
        {connectionStatus.connected ? (
          <WifiIcon className="h-4 w-4" />
        ) : (
          <ExclamationTriangleIcon className="h-4 w-4" />
        )}
      </div>
      <div className="flex flex-col">
        <span className={`text-xs font-medium ${getStatusColor()}`}>{getStatusText()}</span>
        {connectionStatus.error && !connectionStatus.connected && (
          <span className="text-xs text-gray-500 truncate">{connectionStatus.error}</span>
        )}
      </div>
    </div>
  )
}
