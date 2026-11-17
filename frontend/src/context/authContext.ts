import { createContext, useContext } from 'react'
import { Session } from '../lib/session'

export interface AuthState {
  session: Session | null
  login: (username: string, password: string) => Promise<void>
  logout: () => void
}

export const AuthContext = createContext<AuthState>({
  session: null,
  login: async () => {},
  logout: () => {},
})

/** The logged-in user, provided by AuthProvider */
export function useAuth() {
  return useContext(AuthContext)
}

/** True when the logged-in user may change things (acknowledge, block, ...) */
export function useIsAdmin() {
  return useContext(AuthContext).session?.role === 'admin'
}
