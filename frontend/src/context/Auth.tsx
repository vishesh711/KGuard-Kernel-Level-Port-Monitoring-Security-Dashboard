import { ReactNode, useCallback, useEffect, useState } from 'react'
import { useQueryClient } from '@tanstack/react-query'
import { api } from '../services/api'
import { SESSION_ENDED, Session, clearSession, loadSession, saveSession } from '../lib/session'
import { AuthContext } from './auth'

export function AuthProvider({ children }: { children: ReactNode }) {
  const queryClient = useQueryClient()
  const [session, setSession] = useState<Session | null>(() => loadSession())

  const login = useCallback(async (username: string, password: string) => {
    const result = await api.login(username, password)
    const next: Session = {
      token: result.access_token,
      username: result.username,
      role: result.role,
      expiresAt: Date.now() + result.expires_in * 1000,
    }
    saveSession(next)
    setSession(next)
  }, [])

  const logout = useCallback(() => {
    clearSession()
    setSession(null)
    queryClient.clear()
  }, [queryClient])

  // The API refused the token (expired or revoked): back to the login screen
  useEffect(() => {
    const ended = () => {
      setSession(null)
      queryClient.clear()
    }
    window.addEventListener(SESSION_ENDED, ended)
    return () => window.removeEventListener(SESSION_ENDED, ended)
  }, [queryClient])

  return <AuthContext.Provider value={{ session, login, logout }}>{children}</AuthContext.Provider>
}
