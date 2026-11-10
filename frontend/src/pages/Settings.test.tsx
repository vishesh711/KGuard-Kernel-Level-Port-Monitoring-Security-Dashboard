import { describe, expect, it, vi } from 'vitest'
import { screen, within } from '@testing-library/react'
import { Settings } from './Settings'
import { renderWithProviders } from '../test/render'
import { api } from '../services/api'

vi.mock('../services/api', () => ({ api: { getDetailedHealth: vi.fn(), getResponseStatus: vi.fn() } }))
const mocked = vi.mocked(api)

describe('Settings page', () => {
  it('shows thresholds, blocking rules and channels', async () => {
    mocked.getDetailedHealth.mockResolvedValue({
      services: {
        anomaly_detector: {
          port_scan_threshold: 10,
          detection_window_seconds: 60,
          high_frequency_threshold: 100,
          brute_force_threshold: 10,
          syn_flood_threshold: 200,
          alert_cooldown_seconds: 300,
          trusted_sources: [],
          kernel_detection: true,
          state: { backend: 'redis' },
        },
        notifications: {
          min_severity: 'HIGH',
          max_per_hour: 30,
          channels: { slack: { configured: true, sent: 3, failed: 0 }, email: { configured: false } },
        },
        enrichment: { geoip: { country: true, asn: false }, threat_lists: { firehol_level1: 4500 } },
      },
      configuration: { retention_days: { events: 7, resolved_alerts: 90 }, log_level: 'INFO' },
    })
    mocked.getResponseStatus.mockResolvedValue({
      rules: {
        auto_block: true,
        types: ['PORT_SCAN', 'BRUTE_FORCE'],
        min_severity: 'HIGH',
        listed_sources: false,
        minutes: 60,
        lease_seconds: 300,
      },
      active_blocks: 0,
      local: { status: 'not permitted', managed: 0, last_error: null },
      agents: [],
    })
    renderWithProviders(<Settings />)
    const detection = within(await screen.findByRole('region', { name: 'Detection thresholds' }))
    expect(detection.getByText('Port scan: distinct ports').nextElementSibling).toHaveTextContent('10')
    expect(detection.getByText('Detection state kept in').nextElementSibling).toHaveTextContent('redis')
    const blocking = within(screen.getByRole('region', { name: 'Automatic blocking' }))
    expect(blocking.getByText('Alert types').nextElementSibling).toHaveTextContent('PORT_SCAN, BRUTE_FORCE')
    const notify = within(screen.getByRole('region', { name: 'Notifications' }))
    expect(notify.getByText('slack').nextElementSibling).toHaveTextContent('on · 3 sent, 0 failed')
    expect(notify.getByText('email').nextElementSibling).toHaveTextContent('off')
  })
})
