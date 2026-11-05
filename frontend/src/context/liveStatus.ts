import { createContext, useContext } from 'react'
import { ConnectionStatus } from '../types'

export const LiveStatusContext = createContext<ConnectionStatus>({
  connected: false,
  reconnecting: false,
})

/** Live-update connection state, provided by LiveUpdatesProvider */
export function useLiveStatus() {
  return useContext(LiveStatusContext)
}
