/**
 * The login token, kept in sessionStorage: it lasts until the tab is closed
 * and is never sent anywhere but the API's Authorization header.
 */
export type Role = 'admin' | 'viewer'

export interface Session {
  token: string
  username: string
  role: Role
  /** Milliseconds since the epoch */
  expiresAt: number
}

const KEY = 'kguard.session'
/** Fired on window when the API refuses the token (expired, revoked) */
export const SESSION_ENDED = 'kguard:session-ended'

export function loadSession(): Session | null {
  try {
    const raw = sessionStorage.getItem(KEY)
    if (!raw) return null
    const session = JSON.parse(raw) as Session
    if (!session.token || session.expiresAt <= Date.now()) {
      sessionStorage.removeItem(KEY)
      return null
    }
    return session
  } catch {
    return null
  }
}

export function saveSession(session: Session) {
  try {
    sessionStorage.setItem(KEY, JSON.stringify(session))
  } catch {
    // Storage blocked: the login lasts until the page is reloaded
  }
  current = session
}

let current: Session | null = null

export function getToken(): string | null {
  return (current ?? loadSession())?.token ?? null
}

export function clearSession() {
  current = null
  try {
    sessionStorage.removeItem(KEY)
  } catch {
    // ignore
  }
}

/** Forget the login and tell the app to show the login screen */
export function endSession() {
  clearSession()
  window.dispatchEvent(new Event(SESSION_ENDED))
}
