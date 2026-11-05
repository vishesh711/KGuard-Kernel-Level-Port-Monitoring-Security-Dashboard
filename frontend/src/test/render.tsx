import { ReactElement } from 'react'
import { render } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'
import { LiveStatusContext } from '../context/liveStatus'

export function renderWithProviders(ui: ReactElement, { connected = true } = {}) {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  const result = render(
    <QueryClientProvider client={queryClient}>
      <LiveStatusContext.Provider value={{ connected, reconnecting: false }}>
        <MemoryRouter>{ui}</MemoryRouter>
      </LiveStatusContext.Provider>
    </QueryClientProvider>,
  )
  return { ...result, queryClient }
}
