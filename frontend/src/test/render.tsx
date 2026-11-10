import { ReactElement } from 'react'
import { render } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { LiveStatusContext } from '../context/liveStatus'
import { AuthContext } from '../context/auth'
import { Role } from '../lib/session'

interface Options {
  connected?: boolean
  role?: Role | null
  /** Start at this URL; with `path`, the element is mounted at that route pattern */
  url?: string
  path?: string
}

export function renderWithProviders(
  ui: ReactElement,
  { connected = true, role = 'admin', url = '/', path }: Options = {},
) {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  const session = role
    ? { token: 't', username: role === 'admin' ? 'alice' : 'victor', role, expiresAt: Date.now() + 60_000 }
    : null
  const result = render(
    <QueryClientProvider client={queryClient}>
      <AuthContext.Provider value={{ session, login: async () => {}, logout: () => {} }}>
        <LiveStatusContext.Provider value={{ connected, reconnecting: false }}>
          <MemoryRouter initialEntries={[url]}>
            {path ? (
              <Routes>
                <Route path={path} element={ui} />
              </Routes>
            ) : (
              ui
            )}
          </MemoryRouter>
        </LiveStatusContext.Provider>
      </AuthContext.Provider>
    </QueryClientProvider>,
  )
  return { ...result, queryClient }
}
