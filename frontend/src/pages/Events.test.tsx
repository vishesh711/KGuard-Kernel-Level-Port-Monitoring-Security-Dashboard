import { beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, screen, waitFor } from '@testing-library/react'
import { Events } from './Events'
import { renderWithProviders } from '../test/render'
import { api } from '../services/api'
import { event, page } from '../test/fixtures'

vi.mock('../services/api', () => ({ api: { getEvents: vi.fn(), getAgents: vi.fn() } }))
const mocked = vi.mocked(api)

describe('Events page', () => {
  beforeEach(() => {
    vi.resetAllMocks()
    mocked.getAgents.mockResolvedValue([])
  })

  it('shows events with process, state and flags', async () => {
    mocked.getEvents.mockResolvedValue(
      page(
        [
          event(),
          event({ id: 2, src_port: 40001, is_suspicious: true, event_type: 'port_scan', dst_port: 23 }),
        ],
        {
          total: 120,
          pages: 3,
        },
      ),
    )
    renderWithProviders(<Events />)
    expect(await screen.findByText('198.51.100.9:40000')).toBeInTheDocument()
    expect(screen.getAllByText('sshd')).toHaveLength(2)
    expect(screen.getByText('port_scan')).toBeInTheDocument()
    expect(screen.getAllByText('SYN')).toHaveLength(2)
    expect(screen.getByText('Page 1 of 3')).toBeInTheDocument()
  })

  it('sends the filters and pages', async () => {
    mocked.getEvents.mockResolvedValue(page([event()], { total: 120, pages: 3 }))
    renderWithProviders(<Events />)
    await screen.findByText('198.51.100.9:40000')

    fireEvent.change(screen.getByLabelText('Source IP'), { target: { value: ' 198.51.100.9 ' } })
    fireEvent.change(screen.getByLabelText('Port'), { target: { value: '22' } })
    fireEvent.change(screen.getByLabelText('Suspicious'), { target: { value: 'yes' } })
    fireEvent.change(screen.getByLabelText('Host'), { target: { value: '0' } })
    fireEvent.click(screen.getByRole('button', { name: 'Apply' }))
    await waitFor(() =>
      expect(mocked.getEvents).toHaveBeenLastCalledWith({
        page: 1,
        size: 50,
        filters: { src_ip: '198.51.100.9', dst_port: 22, is_suspicious: true, host_id: 0 },
      }),
    )
    fireEvent.click(screen.getByRole('button', { name: 'Next' }))
    await waitFor(() => expect(mocked.getEvents.mock.lastCall?.[0]?.page).toBe(2))
  })
})
