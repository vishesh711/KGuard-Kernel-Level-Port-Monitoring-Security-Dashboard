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

  function setupWithData() {
    const queryClient = new QueryClient()
    const page = (ids: number[], size: number) => ({
      items: ids.map((id) => ({ id })),
      total: ids.length,
      page: 1,
      size,
      pages: 1,
    })
    queryClient.setQueryData(['events', 'list', 1, {}], page([2, 1], 2))
    queryClient.setQueryData(['events', 'recent', 8], page([2, 1], 8))
    queryClient.setQueryData(['events', 'list', 1, { protocol: 'UDP' }], page([], 50))
    render(
      <QueryClientProvider client={queryClient}>
        <LiveUpdatesProvider>
          <Status />
        </LiveUpdatesProvider>
      </QueryClientProvider>,
    )
    const socket = FakeWebSocket.instances[FakeWebSocket.instances.length - 1]
    return { socket, client: queryClient }
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
    const eventRefreshes = invalidate.mock.calls.filter(([filters]) => filters?.queryKey?.[0] === 'events')
    expect(eventRefreshes).toHaveLength(1)
  })

  it('puts new events at the top of the newest-events lists without a request', () => {
    const { socket, client } = setupWithData()
    act(() => socket.open())
    act(() =>
      socket.receive({ type: 'network_event', data: { id: 99, src_ip: '203.0.113.5' }, timestamp: '' }),
    )
    const first = client.getQueryData<{ items: { id: number }[]; total: number; pages: number }>([
      'events',
      'list',
      1,
      {},
    ])
    expect(first?.items.map((e) => e.id)).toEqual([99, 2]) // size 2: the oldest falls off
    expect(first?.total).toBe(3)
    expect(first?.pages).toBe(2)
    expect(client.getQueryData<{ items: { id: number }[] }>(['events', 'recent', 8])?.items[0].id).toBe(99)
    // A filtered list is not touched (it refreshes from the server instead)
    expect(
      client.getQueryData<{ items: { id: number }[] }>(['events', 'list', 1, { protocol: 'UDP' }])?.items,
    ).toEqual([])
    // The same event twice is not added twice
    act(() => socket.receive({ type: 'network_event', data: { id: 99 }, timestamp: '' }))
    expect(client.getQueryData<{ total: number }>(['events', 'list', 1, {}])?.total).toBe(3)
  })
})
