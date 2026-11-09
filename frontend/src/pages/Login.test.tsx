import { beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { AxiosError, AxiosHeaders } from 'axios'
import App from '../App'
import { AuthProvider } from '../context/Auth'
import { api } from '../services/api'
import { endSession, getToken, loadSession } from '../lib/session'
import { MemoryRouter } from 'react-router-dom'

vi.mock('../services/api', () => ({ api: { login: vi.fn() } }))
// The dashboard behind the login is not under test here
vi.mock('../context/LiveUpdates', () => ({
  LiveUpdatesProvider: ({ children }: { children: unknown }) => children,
}))
vi.mock('../components/layout/Layout', () => ({
  Layout: () => <p>dashboard</p>,
}))

const mocked = vi.mocked(api)

function renderApp() {
  render(
    <QueryClientProvider client={new QueryClient()}>
      <MemoryRouter>
        <AuthProvider>
          <App />
        </AuthProvider>
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

function httpError(status: number, headers: Record<string, string> = {}) {
  return new AxiosError('failed', 'ERR', undefined, undefined, {
    status,
    statusText: '',
    data: {},
    headers,
    config: { headers: new AxiosHeaders() },
  })
}

function signIn(password = 'correct horse') {
  fireEvent.change(screen.getByLabelText('Username'), { target: { value: 'alice' } })
  fireEvent.change(screen.getByLabelText('Password'), { target: { value: password } })
  fireEvent.click(screen.getByRole('button', { name: 'Sign in' }))
}

describe('Login', () => {
  beforeEach(() => {
    vi.resetAllMocks()
    sessionStorage.clear()
    endSession()
  })

  it('shows the login screen until signed in, then keeps the token', async () => {
    mocked.login.mockResolvedValue({
      access_token: 'tok-123',
      token_type: 'bearer',
      expires_in: 3600,
      username: 'alice',
      role: 'viewer',
    })
    renderApp()
    expect(screen.queryByText('dashboard')).not.toBeInTheDocument()

    signIn()
    expect(await screen.findByText('dashboard')).toBeInTheDocument()
    expect(mocked.login).toHaveBeenCalledWith('alice', 'correct horse')
    expect(getToken()).toBe('tok-123')
    expect(loadSession()).toMatchObject({ username: 'alice', role: 'viewer' })
  })

  it('says why a login failed', async () => {
    mocked.login.mockRejectedValueOnce(httpError(401))
    mocked.login.mockRejectedValueOnce(httpError(429, { 'retry-after': '42' }))
    renderApp()

    signIn('wrong')
    expect(await screen.findByRole('alert')).toHaveTextContent('Wrong username or password')
    expect(screen.getByLabelText('Password')).toHaveValue('')

    signIn('wrong again')
    await waitFor(() => expect(screen.getByRole('alert')).toHaveTextContent('try again in 42 seconds'))
    expect(screen.queryByText('dashboard')).not.toBeInTheDocument()
  })

  it('returns to the login screen when the API ends the session', async () => {
    mocked.login.mockResolvedValue({
      access_token: 'tok-1',
      token_type: 'bearer',
      expires_in: 3600,
      username: 'alice',
      role: 'admin',
    })
    renderApp()
    signIn()
    expect(await screen.findByText('dashboard')).toBeInTheDocument()

    endSession() // what the API client does on a 401
    expect(await screen.findByRole('button', { name: 'Sign in' })).toBeInTheDocument()
    expect(getToken()).toBeNull()
  })

  it('forgets an expired session', () => {
    sessionStorage.setItem(
      'kguard.session',
      JSON.stringify({ token: 'old', username: 'a', role: 'viewer', expiresAt: Date.now() - 1 }),
    )
    expect(loadSession()).toBeNull()
  })
})
