import { describe, expect, it } from 'vitest'
import { render, screen } from '@testing-library/react'
import { RecentAlerts } from './RecentAlerts'
import { SecurityAlert } from '../../types'

const base: SecurityAlert = {
  id: 1,
  timestamp: new Date().toISOString(),
  created_at: new Date().toISOString(),
  alert_type: 'PORT_SCAN',
  severity: 'HIGH',
  title: 'Port scan from 5.188.10.7',
  description: '40 ports in 10 s',
  src_ip: '5.188.10.7',
  acknowledged: false,
  resolved: false,
}

describe('RecentAlerts enrichment', () => {
  it('shows country, list matches and MITRE techniques', () => {
    render(
      <RecentAlerts
        alerts={[
          {
            ...base,
            metadata: {
              enrichment: {
                mitre: [
                  {
                    id: 'T1046',
                    name: 'Network Service Discovery',
                    tactic: 'Discovery',
                    url: 'https://attack.mitre.org/techniques/T1046/',
                  },
                ],
                src: {
                  ip: '5.188.10.7',
                  country: 'NL',
                  country_name: 'Netherlands',
                  asn: 64500,
                  threat_lists: ['firehol_level1'],
                },
              },
            },
          },
        ]}
      />,
    )
    expect(screen.getByText('NL · AS64500')).toHaveAttribute('title', 'Netherlands')
    expect(screen.getByText('firehol_level1')).toBeInTheDocument()
    const technique = screen.getByText('T1046')
    expect(technique).toHaveAttribute('href', 'https://attack.mitre.org/techniques/T1046/')
    expect(technique).toHaveAttribute('title', 'Network Service Discovery (Discovery)')
  })

  it('shows nothing extra for alerts without enrichment', () => {
    render(<RecentAlerts alerts={[base]} />)
    expect(screen.queryByText('T1046')).not.toBeInTheDocument()
  })
})
