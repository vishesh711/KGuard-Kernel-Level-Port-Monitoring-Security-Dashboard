import { beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, screen, waitFor, within } from '@testing-library/react'
import { Analytics } from './Analytics'
import { renderWithProviders } from '../test/render'
import { api } from '../services/api'

vi.mock('../services/api', () => ({ api: { getEventStats: vi.fn(), getAlertStats: vi.fn() } }))
const mocked = vi.mocked(api)

describe('Analytics page', () => {
  beforeEach(() => {
    vi.resetAllMocks()
    mocked.getEventStats.mockResolvedValue({
      total_events: 12345,
      suspicious_events: 40,
      unique_src_ips: 17,
      unique_dst_ips: 3,
      protocol_distribution: { TCP: 12000, UDP: 345 },
      top_src_ips: [
        { ip: '198.51.100.9', count: 900 },
        { ip: '10.0.0.5', count: 300 },
      ],
      top_dst_ports: [{ port: 443, count: 5000 }],
      events_per_hour: [{ hour: '2026-11-10T11:00:00', count: 12345 }],
    })
    mocked.getAlertStats.mockResolvedValue({
      total_alerts: 6,
      unacknowledged_alerts: 6,
      unresolved_alerts: 6,
      critical_alerts: 0,
      high_alerts: 6,
      medium_alerts: 0,
      low_alerts: 0,
      alert_types_distribution: { PORT_SCAN: 5, BRUTE_FORCE: 1 },
      alerts_per_hour: [{ hour: '2026-11-10T11:00:00', count: 6 }],
      top_source_ips: [{ ip: '198.51.100.9', count: 5 }],
    })
  })

  it('shows totals, top addresses, ports and alert types', async () => {
    renderWithProviders(<Analytics />)
    expect(await screen.findByText('12,345')).toBeInTheDocument()
    const sources = within(screen.getByRole('region', { name: 'Top source addresses' }))
    expect(sources.getByText('198.51.100.9')).toBeInTheDocument()
    expect(sources.getByText('900')).toBeInTheDocument()
    expect(
      within(screen.getByRole('region', { name: 'Top destination ports' })).getByText('443'),
    ).toBeInTheDocument()
    expect(
      within(screen.getByRole('region', { name: 'Alert types' })).getByText('port scan'),
    ).toBeInTheDocument()
  })

  it('changes the time range', async () => {
    renderWithProviders(<Analytics />)
    await screen.findByText('12,345')
    fireEvent.change(screen.getByLabelText('Time range'), { target: { value: '168' } })
    await waitFor(() => expect(mocked.getEventStats).toHaveBeenLastCalledWith(168))
    expect(mocked.getAlertStats).toHaveBeenLastCalledWith(168)
  })
})
