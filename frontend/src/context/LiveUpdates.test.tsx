import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { act, render } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { LiveUpdatesProvider } from './LiveUpdates'
import { useLiveStatus } from './liveStatus'

vi.mock('react-hot-toast', () => {
  const toast = Object.assign(vi.fn(), { error: vi.fn() })
  return { default: toast }
})

class FakeWebSocket {
  static OPEN = 1
  static instances: FakeWebSocket[] = []
  readyState = 0
  onopen: (() => void) | null = null
  onmessage: ((event: { data: string }) => void) | null = null
  onclose: ((event: { code: number; reason: string }) => void) | null = null
  onerror: ((event: unknown) => void) | null = null

  constructor(public url: string) {
    FakeWebSocket.instances.push(this)
  }

  send() {}

  close() {
    this.readyState = 3
  }

  open() {
    this.readyState = FakeWebSocket.OPEN
    this.onopen?.()
  }

  receive(message: object) {
    this.onmessage?.({ data: JSON.stringify(message) })
  }
}

function Status() {
  const live = useLiveStatus()
  return <span>{live.connected ? 'connected' : 'disconnected'}</span>
}

describe('LiveUpdatesProvider', () => {
  beforeEach(() => {
    FakeWebSocket.instances = []
    vi.stubGlobal('WebSocket', FakeWebSocket)
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  function setup() {
    const queryClient = new QueryClient()
    const invalidate = vi.spyOn(queryClient, 'invalidateQueries')
    const view = render(
      <QueryClientProvider client={queryClient}>
        <LiveUpdatesProvider>
          <Status />
        </LiveUpdatesProvider>
      </QueryClientProvider>,
    )
    const socket = FakeWebSocket.instances[FakeWebSocket.instances.length - 1]
    return { view, socket, invalidate }
  }

  it('reports the connection state', () => {
    const { view, socket } = setup()
    expect(view.getByText('disconnected')).toBeInTheDocument()
    act(() => socket.open())
    expect(view.getByText('connected')).toBeInTheDocument()
  })

  it('refreshes alert and event data when an alert arrives', () => {
    const { socket, invalidate } = setup()
    act(() => socket.open())
    act(() =>
      socket.receive({
        type: 'security_alert',
        data: { title: 'Port Scan Detected', severity: 'HIGH' },
        timestamp: '2026-01-05T10:00:00',
      }),
    )
    expect(invalidate).toHaveBeenCalledWith({ queryKey: ['alerts'] })
    expect(invalidate).toHaveBeenCalledWith({ queryKey: ['events'] })
  })

  it('refreshes event data at most every two seconds', () => {
    const { socket, invalidate } = setup()
    act(() => socket.open())
    act(() => {
      for (let i = 0; i < 20; i++) {
        socket.receive({ type: 'network_event', data: { id: i }, timestamp: '' })
      }
    })
    const eventRefreshes = invalidate.mock.calls.filter(
      ([filters]) => JSON.stringify(filters) === JSON.stringify({ queryKey: ['events'] }),
    )
    expect(eventRefreshes).toHaveLength(1)
  })
})
