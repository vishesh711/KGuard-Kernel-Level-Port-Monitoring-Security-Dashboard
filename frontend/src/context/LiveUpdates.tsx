import { ReactNode, useCallback, useRef } from 'react'
import { useQueryClient } from '@tanstack/react-query'
import { useWebSocket } from '../hooks/useWebSocket'
import { NetworkEvent, WebSocketMessage } from '../types'
import { addLiveEvent, staleEventQueries } from '../lib/liveCache'
import { LiveStatusContext } from './liveStatus'

/** Refetch event data at most this often while events stream in */
const EVENT_REFRESH_MS = 2000

/**
 * Opens one WebSocket for the whole app. New alerts refresh alert data
 * straight away. New events go straight into the lists of newest events
 * (no request needed); other event data refreshes at most every 2 seconds.
 */
export function LiveUpdatesProvider({ children }: { children: ReactNode }) {
  const queryClient = useQueryClient()
  const lastEventRefresh = useRef(0)

  const onMessage = useCallback(
    (message: WebSocketMessage) => {
      if (message.type === 'security_alert') {
        queryClient.invalidateQueries({ queryKey: ['alerts'] })
        queryClient.invalidateQueries({ queryKey: ['events'] })
      } else if (message.type === 'network_event') {
        // Shown at once in the newest-events lists...
        addLiveEvent(queryClient, message.data as unknown as NetworkEvent)
        // ...while filtered lists and statistics refresh at most every 2 seconds
        const now = Date.now()
        if (now - lastEventRefresh.current >= EVENT_REFRESH_MS) {
          lastEventRefresh.current = now
          queryClient.invalidateQueries({ queryKey: ['events'], predicate: staleEventQueries })
        }
      }
    },
    [queryClient],
  )

  const { connectionStatus } = useWebSocket({ onMessage })

  return <LiveStatusContext.Provider value={connectionStatus}>{children}</LiveStatusContext.Provider>
}
