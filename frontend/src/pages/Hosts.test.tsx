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
}

describe('Hosts', () => {
  beforeEach(() => vi.resetAllMocks())

  it('lists agents with their status, engine and counts', async () => {
    mocked.getAgents.mockResolvedValue([
      agent,
      { ...agent, id: 2, name: 'db-1', online: false, engine: 'module' },
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
  })

  it('explains how to enroll when there are no agents', async () => {
    mocked.getAgents.mockResolvedValue([])
    renderWithProviders(<Hosts />)
    expect(await screen.findByText('No agents yet')).toBeInTheDocument()
    expect(screen.getByText(/kguard-agent enroll/)).toBeInTheDocument()
  })
})
