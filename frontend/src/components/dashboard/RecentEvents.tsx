import { NetworkEvent } from '../../types'
import { formatDistanceToNow } from 'date-fns'
import { parseServerDate } from '../../lib/time'

interface RecentEventsProps {
  events: NetworkEvent[]
}

export function RecentEvents({ events }: RecentEventsProps) {
  if (events.length === 0) {
    return (
      <div className="p-6 text-center text-gray-500">
        <p>No recent events</p>
      </div>
    )
  }

  const getProtocolColor = (protocol: string) => {
    switch (protocol.toUpperCase()) {
      case 'TCP':
        return 'bg-blue-100 text-blue-800'
      case 'UDP':
        return 'bg-green-100 text-green-800'
      case 'ICMP':
        return 'bg-yellow-100 text-yellow-800'
      default:
        return 'bg-gray-100 text-gray-800'
    }
  }

  return (
    <div className="flow-root">
      <ul role="list" className="divide-y divide-gray-200">
        {events.map((event) => (
          <li key={event.id} className="px-6 py-4">
            <div className="flex items-center justify-between">
              <div className="flex items-center space-x-3">
                <div className="flex-shrink-0">
                  <span
                    className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${getProtocolColor(event.protocol)}`}
                  >
                    {event.protocol}
                  </span>
                </div>
                <div className="min-w-0 flex-1">
                  <p className="text-sm font-medium text-gray-900 truncate">
                    {event.src_ip}:{event.src_port} → {event.dst_ip}:{event.dst_port}
                  </p>
                  <p className="text-sm text-gray-500">
                    {formatDistanceToNow(parseServerDate(event.created_at), { addSuffix: true })}
                  </p>
                </div>
              </div>
              <div className="flex-shrink-0">
                {event.is_suspicious && (
                  <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-red-100 text-red-800">
                    Suspicious
                  </span>
                )}
              </div>
            </div>
          </li>
        ))}
      </ul>
    </div>
  )
}
