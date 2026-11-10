import { beforeEach, describe, expect, it, vi } from 'vitest'
import { screen } from '@testing-library/react'
import { Hosts } from './Hosts'
import { renderWithProviders } from '../test/render'
import { api } from '../services/api'

vi.mock('../services/api', () => ({ api: { getAgents: vi.fn() } }))

const mocked = vi.mocked(api)

const agent = {
  id: 1,
  name: 'web-1',
  hostname: 'web-1.lan',
  engine: 'ebpf' as const,
  version: '1.0.0',
  online: true,
  last_seen: new Date().toISOString(),
  created_at: null,
  remote_addr: '10.0.0.5',
  events_received: 12345,
  kernel_dropped: 2,
  queue_dropped: 1,
  events_per_second: 42.5,
  blocklist: { applied: 'abc', failed: 0, enforcing: true, synced_at: '2026-11-10T12:00:00' },
}

describe('Hosts', () => {
  beforeEach(() => vi.resetAllMocks())

  it('lists agents with their status, engine and counts', async () => {
    mocked.getAgents.mockResolvedValue([
      agent,
      {
        ...agent,
        id: 2,
        name: 'db-1',
        online: false,
        engine: 'module',
        events_per_second: 0,
        blocklist: { applied: 'abc', failed: 0, enforcing: false, synced_at: '2026-11-10T12:00:00' },
      },
    ])
    renderWithProviders(<Hosts />)

    expect(await screen.findByText('web-1')).toBeInTheDocument()
    expect(screen.getByText('db-1')).toBeInTheDocument()
    expect(screen.getByText('Online')).toBeInTheDocument()
    expect(screen.getByText('Offline')).toBeInTheDocument()
    expect(screen.getByText('eBPF')).toBeInTheDocument()
    expect(screen.getByText('Kernel module')).toBeInTheDocument()
    expect(screen.getAllByText('12,345')).toHaveLength(2)
    expect(screen.getAllByText('3')).toHaveLength(2)
    // Two agents, two separate rows with their own rate and blocklist state
    const rows = screen.getAllByRole('row').slice(1)
    expect(rows).toHaveLength(2)
    expect(rows[0]).toHaveTextContent('web-1')
    expect(rows[0]).toHaveTextContent('42.5')
    expect(rows[0]).toHaveTextContent('enforcing')
    expect(rows[1]).toHaveTextContent('db-1')
    expect(rows[1]).toHaveTextContent('monitor only')
  })

  it('explains how to enroll when there are no agents', async () => {
    mocked.getAgents.mockResolvedValue([])
    renderWithProviders(<Hosts />)
    expect(await screen.findByText('No agents yet')).toBeInTheDocument()
    expect(screen.getByText(/kguard-agent enroll/)).toBeInTheDocument()
  })
})
