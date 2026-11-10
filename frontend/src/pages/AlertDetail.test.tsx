import { beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, screen, waitFor, within } from '@testing-library/react'
import { AlertDetail } from './AlertDetail'
import { renderWithProviders } from '../test/render'
import { api } from '../services/api'
import { alert, event } from '../test/fixtures'
import { SecurityAlert } from '../types'

vi.mock('../services/api', () => ({
  api: {
    getAlert: vi.fn(),
    getEventsByIds: vi.fn(),
    acknowledgeAlert: vi.fn(),
    resolveAlert: vi.fn(),
    addBlock: vi.fn(),
    downloadPcap: vi.fn(),
  },
}))
const mocked = vi.mocked(api)

function show(a: SecurityAlert, role: 'admin' | 'viewer' = 'admin') {
  mocked.getAlert.mockResolvedValue(a)
  return renderWithProviders(<AlertDetail />, { url: `/alerts/${a.id}`, path: '/alerts/:id', role })
}

async function panel(type: string) {
  return within(await screen.findByRole('region', { name: `${type} details` }))
}

// Each alert type, the metadata its detector stores, and what its panel must say
const CASES: [SecurityAlert, [string, string][]][] = [
  [
    alert({
      metadata: {
        scan_type: 'syn',
        unique_ports: 40,
        sample_ports: [21, 22, 80],
        window_seconds: 3.2,
        sender_fingerprint: 'nmap',
        detection_method: 'sliding_window_distinct_ports',
      },
    }),
    [
      ['Scan type', 'TCP SYN (half-open)'],
      ['Ports probed', '40'],
      ['Ports', '21, 22, 80'],
      ['Sender OS / tool (TCP fingerprint)', 'nmap'],
      ['Detected by', 'sliding window distinct ports'],
    ],
  ],
  [
    alert({
      alert_type: 'BRUTE_FORCE',
      dst_port: 22,
      metadata: { connections: 25, window_seconds: 40, threshold: 10 },
    }),
    [
      ['Login port', '22'],
      ['Connection attempts', '25'],
    ],
  ],
  [
    alert({
      alert_type: 'SYN_FLOOD',
      severity: 'CRITICAL',
      metadata: { half_open: 900, distinct_sources: 450, syn_cookies: 1 },
    }),
    [
      ['Half-open connections', '900'],
      ['SYN cookies on this server', 'on when needed'],
    ],
  ],
  [
    alert({
      alert_type: 'SPOOFED_TRAFFIC',
      metadata: { spoof_reason: 'ttl', initial_ttl: 64, usual_hops: 3, odd_hops: 17 },
    }),
    [
      ['Why it is spoofed', 'ttl'],
      ['Hop count seen', '17'],
    ],
  ],
  [
    alert({
      alert_type: 'AMPLIFICATION',
      metadata: { service: 'memcached', role: 'victim', amplification: 51.2, reflectors: 3 },
    }),
    [
      ['Service', 'memcached'],
      ['Amplification factor', '51.20'],
    ],
  ],
  [
    alert({
      alert_type: 'DNS_TUNNELING',
      metadata: {
        domain: 'tunnel.example',
        queries: 300,
        random_looking: 290,
        example: 'a9f3.tunnel.example',
      },
    }),
    [
      ['Domain', 'tunnel.example'],
      ['Example name', 'a9f3.tunnel.example'],
    ],
  ],
  [
    alert({
      alert_type: 'MALICIOUS_TLS',
      metadata: { label: 'Cobalt Strike', ja3: 'abc123', ja4: 't13d1516h2_x', sni: 'cdn.bad.example' },
    }),
    [
      ['Known as', 'Cobalt Strike'],
      ['JA4', 't13d1516h2_x'],
      ['Server name (SNI)', 'cdn.bad.example'],
    ],
  ],
  [
    alert({ alert_type: 'UNUSUAL_TRAFFIC', metadata: { count: 5000, mean: 400, times_normal: 12.5 } }),
    [['Times the usual', '12.50']],
  ],
]

describe('Alert detail', () => {
  beforeEach(() => {
    vi.resetAllMocks()
    mocked.getEventsByIds.mockResolvedValue([event({ ttl: 52, tcp_window: 1024, os_guess: 'nmap' })])
  })

  it.each(CASES)('$alert_type has its own panel', async (a, facts) => {
    show(a)
    const details = await panel(a.alert_type)
    for (const [label, value] of facts) {
      const term = details.getByText(label)
      expect(term.nextElementSibling).toHaveTextContent(value)
    }
  })

  it('shows country, lists and MITRE technique', async () => {
    show(
      alert({
        metadata: {
          enrichment: {
            mitre: [
              { id: 'T1046', name: 'Network Service Discovery', tactic: 'Discovery', url: 'https://x/T1046' },
            ],
            src: {
              ip: '5.188.10.7',
              country: 'NL',
              country_name: 'Netherlands',
              threat_lists: ['firehol_level1'],
            },
          },
        },
      }),
    )
    const summary = within(await screen.findByRole('region', { name: 'Summary' }))
    expect(summary.getByText('Source country').nextElementSibling).toHaveTextContent('Netherlands (NL)')
    expect(summary.getByText('firehol_level1')).toBeInTheDocument()
    expect(summary.getByRole('link', { name: /T1046 Network Service Discovery/ })).toHaveAttribute(
      'href',
      'https://x/T1046',
    )
  })

  it('lists the related events', async () => {
    show(alert())
    const related = within(await screen.findByRole('region', { name: 'Related events' }))
    expect(await related.findByText('198.51.100.9:40000')).toBeInTheDocument()
    expect(related.getByText('52 / 1024')).toBeInTheDocument()
    expect(mocked.getEventsByIds).toHaveBeenCalledWith([1, 2])
  })

  it('downloads the pcap', async () => {
    mocked.downloadPcap.mockResolvedValue(new Blob(['pcap']))
    URL.createObjectURL = vi.fn(() => 'blob:x')
    URL.revokeObjectURL = vi.fn()
    const click = vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {})
    show(alert())
    fireEvent.click(await screen.findByRole('button', { name: 'Download pcap' }))
    await waitFor(() => expect(click).toHaveBeenCalled())
    expect(mocked.downloadPcap).toHaveBeenCalledWith(5)
  })

  it('admins can acknowledge, resolve and block', async () => {
    mocked.acknowledgeAlert.mockResolvedValue({})
    mocked.resolveAlert.mockResolvedValue({})
    mocked.addBlock.mockResolvedValue({} as never)
    show(alert())
    fireEvent.click(await screen.findByRole('button', { name: 'Acknowledge' }))
    fireEvent.change(screen.getByLabelText('Resolution notes'), { target: { value: 'scanner blocked' } })
    fireEvent.click(screen.getByRole('button', { name: 'Resolve' }))
    fireEvent.click(screen.getByRole('button', { name: 'Block source 24 h' }))
    await waitFor(() => {
      expect(mocked.acknowledgeAlert).toHaveBeenCalledWith(5)
      expect(mocked.resolveAlert).toHaveBeenCalledWith(5, { resolution_notes: 'scanner blocked' })
      expect(mocked.addBlock).toHaveBeenCalledWith({
        cidr: '198.51.100.9',
        reason: 'Alert 5: SYN Scan Detected from 198.51.100.9',
        minutes: 1440,
      })
    })
  })

  it('viewers see no actions', async () => {
    show(alert(), 'viewer')
    await panel('PORT_SCAN')
    for (const name of ['Acknowledge', 'Resolve', 'Block source 24 h']) {
      expect(screen.queryByRole('button', { name })).not.toBeInTheDocument()
    }
    expect(screen.getByRole('button', { name: 'Download pcap' })).toBeInTheDocument()
  })
})
