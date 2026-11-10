import type { ReactNode } from 'react'
import { screen } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'
import App from './App'
import { renderWithProviders } from './test/render'

// Only the routing is under test: stand-ins for the page and the layout
vi.mock('./pages/Dashboard', () => ({ Dashboard: () => <h1>Dashboard page</h1> }))
vi.mock('./components/layout/Layout', () => ({
  Layout: ({ children }: { children: ReactNode }) => <>{children}</>,
}))
vi.mock('./context/LiveUpdates', () => ({
  LiveUpdatesProvider: ({ children }: { children: ReactNode }) => <>{children}</>,
}))

describe('App routing', () => {
  it('sends an unknown address (e.g. /login after signing in) to the dashboard', async () => {
    renderWithProviders(<App />, { url: '/login' })
    expect(await screen.findByRole('heading', { name: 'Dashboard page' })).toBeInTheDocument()
  })
})
