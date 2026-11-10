import { beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, screen, waitFor, within } from '@testing-library/react'
import { Blocks } from './Blocks'
import { renderWithProviders } from '../test/render'
import { api } from '../services/api'
import { Block } from '../types'
import { timeLeft } from '../lib/format'

vi.mock('../services/api', () => ({
  api: {
    getBlocks: vi.fn(),
    addBlock: vi.fn(),
    removeBlock: vi.fn(),
    getAllowlist: vi.fn(),
    addAllow: vi.fn(),
    removeAllow: vi.fn(),
    getAudit: vi.fn(),
    getResponseStatus: vi.fn(),
    getAgents: vi.fn(),
  },
}))
const mocked = vi.mocked(api)

function block(over: Partial<Block> = {}): Block {
  return {
    id: 3,
    cidr: '198.51.100.7/32',
    host_id: null,
    reason: 'scanner',
    source: 'manual',
    created_by: 'alice',
    alert_id: null,
    created_at: '2026-11-10T12:00:00',
    expires_at: '2026-11-10T13:00:00',
    removed_at: null,
    removed_by: null,
    active: true,
    seconds_left: 3000,
    ...over,
  }
}

describe('Blocked addresses page', () => {
  beforeEach(() => {
    vi.resetAllMocks()
    mocked.getBlocks.mockResolvedValue([
      block(),
      block({
        id: 4,
        cidr: '203.0.113.0/24',
        source: 'auto',
        created_by: 'auto-response',
        alert_id: 9,
        seconds_left: null,
      }),
    ])
    mocked.getAllowlist.mockResolvedValue([
      { id: 1, cidr: '10.0.0.0/8', note: 'office', created_by: 'alice', created_at: null },
    ])
    mocked.getAudit.mockResolvedValue({
      items: [
        {
          id: 1,
          time: '2026-11-10T12:00:00',
          actor: 'alice',
          action: 'block',
          target: '198.51.100.7/32',
          details: null,
        },
      ],
      total: 1,
    })
    mocked.getResponseStatus.mockResolvedValue({
      rules: {
        auto_block: true,
        types: [],
        min_severity: 'HIGH',
        listed_sources: false,
        minutes: 60,
        lease_seconds: 300,
      },
      active_blocks: 2,
      local: { status: 'not permitted', managed: 0, last_error: null },
      agents: [
        { id: 1, name: 'edge-1', engine: 'ebpf', in_sync: true, failed: 0, enforcing: true, synced_at: null },
      ],
    })
    mocked.getAgents.mockResolvedValue([])
  })

  it('lists blocks with reason, origin and time left', async () => {
    renderWithProviders(<Blocks />)
    expect(within(await screen.findByRole('table')).getByText('198.51.100.7/32')).toBeInTheDocument()
    expect(screen.getByText('50 min')).toBeInTheDocument()
    expect(screen.getByText('until unblocked')).toBeInTheDocument()
    expect(screen.getByText('auto')).toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'alert 9' })).toHaveAttribute('href', '/alerts/9')
    expect(screen.getByText('edge-1: up to date')).toBeInTheDocument()
    expect(
      within(screen.getByRole('region', { name: 'Allowlist' })).getByText('10.0.0.0/8'),
    ).toBeInTheDocument()
  })

  it('admins block and unblock', async () => {
    mocked.addBlock.mockResolvedValue({ ...block(), created: true })
    mocked.removeBlock.mockResolvedValue(block({ active: false }))
    renderWithProviders(<Blocks />, { role: 'admin' })
    const form = within(await screen.findByRole('form', { name: 'Block an address' }))
    fireEvent.change(form.getByLabelText('Address or prefix'), { target: { value: ' 192.0.2.66 ' } })
    fireEvent.change(form.getByLabelText('Reason'), { target: { value: 'brute force on ssh' } })
    fireEvent.change(form.getByLabelText('For'), { target: { value: '' } })
    fireEvent.click(form.getByRole('button', { name: 'Block' }))
    await waitFor(() =>
      expect(mocked.addBlock).toHaveBeenCalledWith({
        cidr: '192.0.2.66',
        reason: 'brute force on ssh',
        minutes: null,
        host_id: null,
      }),
    )
    fireEvent.click(screen.getByRole('button', { name: 'Unblock 198.51.100.7/32' }))
    await waitFor(() => expect(mocked.removeBlock.mock.calls[0][0]).toBe(3))
  })

  it('viewers see the list but no way to change it', async () => {
    renderWithProviders(<Blocks />, { role: 'viewer' })
    expect(within(await screen.findByRole('table')).getByText('198.51.100.7/32')).toBeInTheDocument()
    expect(screen.queryByRole('form', { name: 'Block an address' })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /Unblock/ })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Remove' })).not.toBeInTheDocument()
    expect(screen.queryByLabelText('Allow address or prefix')).not.toBeInTheDocument()
  })
})

describe('timeLeft', () => {
  it('describes what is left', () => {
    expect(timeLeft(block({ seconds_left: 30 }))).toBe('1 min')
    expect(timeLeft(block({ seconds_left: 7200 }))).toBe('2 h')
    expect(timeLeft(block({ seconds_left: 3 * 86400 }))).toBe('3 d')
    expect(timeLeft(block({ active: false, removed_by: 'expiry' }))).toBe('expired')
    expect(timeLeft(block({ active: false, removed_by: 'alice' }))).toBe('removed')
  })
})
