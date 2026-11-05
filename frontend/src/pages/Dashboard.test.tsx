import { describe, expect, it, vi, beforeEach } from 'vitest'
import { screen } from '@testing-library/react'
import { Dashboard } from './Dashboard'
import { renderWithProviders } from '../test/render'
import { api } from '../services/api'

vi.mock('../services/api', () => ({
  api: {
    getHealth: vi.fn(),
    getEventStats: vi.fn(),
    getAlertStats: vi.fn(),
    getTrafficSummary: vi.fn(),
    getEvents: vi.fn(),
    getAlerts: vi.fn(),
  },
}))

const mocked = vi.mocked(api)

beforeEach(() => {
  vi.resetAllMocks()
  mocked.getHealth.mockResolvedValue({
    status: 'healthy',
    timestamp: '2026-01-05T10:00:00',
    version: '1.0.0',
    database: true,
    kernel_module: true,
    uptime_seconds: 7500,
  })
  mocked.getEventStats.mockResolvedValue({
    total_events: 4321,
    suspicious_events: 17,
    unique_src_ips: 3,
    unique_dst_ips: 2,
    protocol_distribution: { TCP: 4000, UDP: 321 },
    top_src_ips: [],
    top_dst_ports: [],
    events_per_hour: [],
  })
  mocked.getAlertStats.mockResolvedValue({
    total_alerts: 2,
    unacknowledged_alerts: 2,
    unresolved_alerts: 2,
    critical_alerts: 0,
    high_alerts: 1,
    medium_alerts: 1,
    low_alerts: 0,
    alert_types_distribution: {},
    alerts_per_hour: [],
    top_source_ips: [],
  })
  mocked.getTrafficSummary.mockResolvedValue([])
  mocked.getEvents.mockResolvedValue({
    items: [
      {
        id: 1,
        timestamp: 1,
        created_at: '2026-01-05T10:00:00',
        src_ip: '203.0.113.9',
        dst_ip: '10.0.0.1',
        src_port: 51515,
        dst_port: 22,
        protocol: 'TCP',
        flags: 2,
        is_suspicious: true,
        event_type: 'port_scan',
      },
    ],
    total: 1,
    page: 1,
    size: 8,
    pages: 1,
  })
  mocked.getAlerts.mockResolvedValue({
    items: [
      {
        id: 7,
        timestamp: '2026-01-05T10:00:00',
        created_at: '2026-01-05T10:00:00',
        alert_type: 'PORT_SCAN',
        severity: 'HIGH',
        title: 'Port Scan Detected from 203.0.113.9',
        description: '203.0.113.9 tried 15 different ports',
        src_ip: '203.0.113.9',
        acknowledged: false,
        resolved: false,
      },
    ],
    total: 1,
    page: 1,
    size: 5,
    pages: 1,
  })
})

describe('Dashboard', () => {
  it('shows numbers from the API, not placeholders', async () => {
    renderWithProviders(<Dashboard />)

    expect(await screen.findByText('4321')).toBeInTheDocument()
    expect(screen.getByText('17')).toBeInTheDocument()
    expect(screen.getByText('2h 5m')).toBeInTheDocument()
    expect(await screen.findByText('Port Scan Detected from 203.0.113.9')).toBeInTheDocument()
    expect(screen.getByText('203.0.113.9:51515 → 10.0.0.1:22')).toBeInTheDocument()
    expect(screen.getByText('Live updates on')).toBeInTheDocument()
  })

  it('says when the backend is unreachable', async () => {
    mocked.getHealth.mockRejectedValue(new Error('Network Error'))
    mocked.getEventStats.mockRejectedValue(new Error('Network Error'))

    renderWithProviders(<Dashboard />, { connected: false })

    expect(await screen.findByRole('alert')).toHaveTextContent("Can't reach the KGuard backend")
    expect(screen.getByText('Live updates off')).toBeInTheDocument()
  })
})
