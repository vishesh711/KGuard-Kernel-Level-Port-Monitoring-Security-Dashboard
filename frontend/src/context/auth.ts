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
