import { beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, screen, waitFor } from '@testing-library/react'
import { Alerts } from './Alerts'
import { renderWithProviders } from '../test/render'
import { api } from '../services/api'
import { alert, page } from '../test/fixtures'

vi.mock('../services/api', () => ({ api: { getAlerts: vi.fn(), acknowledgeAlert: vi.fn() } }))
const mocked = vi.mocked(api)

describe('Alerts page', () => {
  beforeEach(() => {
    vi.resetAllMocks()
    mocked.getAlerts.mockResolvedValue(page([alert()]))
    mocked.acknowledgeAlert.mockResolvedValue({})
  })

  it('lists open alerts with a link to each', async () => {
    renderWithProviders(<Alerts />)
    const link = await screen.findByRole('link', { name: 'SYN Scan Detected from 198.51.100.9' })
    expect(link).toHaveAttribute('href', '/alerts/5')
    expect(mocked.getAlerts).toHaveBeenCalledWith({
      page: 1,
      size: 25,
      filters: { acknowledged: false, resolved: false },
    })
  })

  it('filters by severity and type', async () => {
    renderWithProviders(<Alerts />)
    await screen.findByText('Open')
    fireEvent.change(screen.getByLabelText('Severity'), { target: { value: 'CRITICAL' } })
    fireEvent.change(screen.getByLabelText('Type'), { target: { value: 'SYN_FLOOD' } })
    fireEvent.change(screen.getByLabelText('Status'), { target: { value: '' } })
    await waitFor(() =>
      expect(mocked.getAlerts).toHaveBeenLastCalledWith({
        page: 1,
        size: 25,
        filters: { severity: 'CRITICAL', alert_type: 'SYN_FLOOD' },
      }),
    )
  })

  it('admins can acknowledge', async () => {
    renderWithProviders(<Alerts />, { role: 'admin' })
    fireEvent.click(await screen.findByRole('button', { name: 'Acknowledge' }))
    await waitFor(() => expect(mocked.acknowledgeAlert.mock.calls[0][0]).toBe(5))
  })

  it('viewers see no acknowledge button', async () => {
    renderWithProviders(<Alerts />, { role: 'viewer' })
    await screen.findByText('Open')
    expect(screen.queryByRole('button', { name: 'Acknowledge' })).not.toBeInTheDocument()
  })
})
