import { ReactNode, useCallback, useRef } from 'react'
import { useQueryClient } from '@tanstack/react-query'
import { useWebSocket } from '../hooks/useWebSocket'
import { WebSocketMessage } from '../types'
import { LiveStatusContext } from './liveStatus'

/** Refetch event data at most this often while events stream in */
const EVENT_REFRESH_MS = 2000

/**
 * Opens one WebSocket for the whole app. New alerts refresh alert data
 * straight away; new events refresh event data at most every 2 seconds.
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
        const now = Date.now()
        if (now - lastEventRefresh.current >= EVENT_REFRESH_MS) {
          lastEventRefresh.current = now
          queryClient.invalidateQueries({ queryKey: ['events'] })
        }
      }
    },
    [queryClient],
  )

  const { connectionStatus } = useWebSocket({ onMessage })

  return <LiveStatusContext.Provider value={connectionStatus}>{children}</LiveStatusContext.Provider>
}
