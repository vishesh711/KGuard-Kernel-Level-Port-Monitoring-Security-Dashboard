import { describe, expect, it } from 'vitest'
import { render, screen } from '@testing-library/react'
import { RecentEvents } from './RecentEvents'
import { NetworkEvent } from '../../types'

const base: NetworkEvent = {
  id: 1,
  timestamp: 1,
  created_at: new Date().toISOString(),
  src_ip: '10.0.0.5',
  dst_ip: '10.0.0.1',
  src_port: 40000,
  dst_port: 4444,
  protocol: 'TCP',
  flags: 2,
  is_suspicious: false,
  event_type: 'normal',
}

describe('RecentEvents', () => {
  it('shows direction and the owning process when the kernel reports them', () => {
    render(<RecentEvents events={[{ ...base, direction: 'in', process_name: 'nc', pid: 4321 }]} />)
    expect(screen.getByText('in')).toBeInTheDocument()
    expect(screen.getByText('nc (4321)')).toBeInTheDocument()
  })

  it('names the sender from its TCP fingerprint', () => {
    render(
      <RecentEvents
        events={[
          { ...base, os_guess: 'nmap', tcp_options: 'M', ttl: 47 },
          { ...base, id: 2, os_guess: 'unknown' },
        ]}
      />,
    )
    expect(screen.getByText('nmap')).toHaveAttribute('title', 'TCP fingerprint: M, TTL 47')
    expect(screen.queryByText('unknown')).not.toBeInTheDocument()
  })

  it('still renders events from older modules without that context', () => {
    render(<RecentEvents events={[base]} />)
    expect(screen.getByText('10.0.0.5:40000 → 10.0.0.1:4444')).toBeInTheDocument()
  })
})
