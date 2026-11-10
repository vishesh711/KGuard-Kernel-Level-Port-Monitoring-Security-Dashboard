import { describe, expect, it, vi } from 'vitest'
import { screen } from '@testing-library/react'
import { KernelHealth } from './KernelHealth'
import { renderWithProviders } from '../test/render'
import { api } from '../services/api'

vi.mock('../services/api', () => ({ api: { getKernelCounters: vi.fn() } }))
const mocked = vi.mocked(api)

describe('KernelHealth', () => {
  it('shows the module counters', async () => {
    mocked.getKernelCounters.mockResolvedValue({
      available: true,
      stats: { packets: 1520, events: 1500, dropped: 3, ring_fill: 512, ns_per_packet: 187, blocks: 2 },
      ring_capacity: 65536,
      enforcing: true,
    })
    renderWithProviders(<KernelHealth />)
    expect((await screen.findByText('Buffer fill')).nextElementSibling).toHaveTextContent('0.8%')
    expect(screen.getByText('ns per packet').nextElementSibling).toHaveTextContent('187')
    expect(screen.getByText('Events dropped').nextElementSibling).toHaveTextContent('3')
    expect(screen.getByText('Events dropped').nextElementSibling).toHaveClass('text-red-700')
    expect(screen.getByText('Mode').nextElementSibling).toHaveTextContent('enforcing')
  })

  it('says why it is not available', async () => {
    mocked.getKernelCounters.mockResolvedValue({ available: false, reason: 'kernel module not loaded' })
    renderWithProviders(<KernelHealth />)
    expect(await screen.findByText('Not available: kernel module not loaded')).toBeInTheDocument()
  })
})
