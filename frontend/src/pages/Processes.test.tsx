import { beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, screen, waitFor, within } from '@testing-library/react'
import { Processes } from './Processes'
import { renderWithProviders } from '../test/render'
import { api } from '../services/api'
import { SocketInfo } from '../types'

vi.mock('../services/api', () => ({
  api: { getSockets: vi.fn(), markListenerKnown: vi.fn(), getAgents: vi.fn() },
}))
const mocked = vi.mocked(api)

function sock(over: Partial<SocketInfo>): SocketInfo {
  return {
    proto: 'TCP',
    family: 4,
    local: '0.0.0.0',
    lport: 22,
    remote: '0.0.0.0',
    rport: 0,
    state: 'LISTEN',
    uid: 0,
    user: 'root',
    pid: 812,
    process: 'sshd',
    new: false,
    ...over,
  }
}

describe('Processes page', () => {
  beforeEach(() => {
    vi.resetAllMocks()
    mocked.getAgents.mockResolvedValue([
      {
        id: 4,
        name: 'web-1',
        hostname: null,
        engine: 'ebpf',
        version: null,
        online: true,
        last_seen: null,
        created_at: null,
        remote_addr: null,
        events_received: 0,
        kernel_dropped: 0,
        queue_dropped: 0,
      },
    ])
    mocked.getSockets.mockResolvedValue({
      host: 'this server',
      taken_at: '2026-11-10T12:00:00',
      listeners: [
        sock({}),
        sock({ lport: 4444, pid: 999, process: 'nc', user: 'mallory', uid: 1001, new: true }),
      ],
      connections: [
        sock({
          state: 'ESTABLISHED',
          local: '10.0.0.1',
          remote: '198.51.100.9',
          rport: 51000,
          new: undefined,
        }),
      ],
    })
    mocked.markListenerKnown.mockResolvedValue(undefined)
  })

  it('shows listeners with process and user, and flags the new one', async () => {
    renderWithProviders(<Processes />)
    const listeners = within(await screen.findByRole('region', { name: 'Listening ports' }))
    const rows = listeners.getAllByRole('row').slice(1)
    expect(rows[0]).toHaveTextContent('sshd (812)')
    expect(rows[0]).not.toHaveAttribute('data-new')
    expect(rows[1]).toHaveTextContent('0.0.0.0:4444')
    expect(rows[1]).toHaveTextContent('nc (999)')
    expect(rows[1]).toHaveTextContent('mallory')
    expect(rows[1]).toHaveAttribute('data-new', 'true')
    expect(screen.getByText('1 unexpected listener(s)')).toBeInTheDocument()
    const conns = within(screen.getByRole('region', { name: 'Connections' }))
    expect(conns.getByText('198.51.100.9:51000')).toBeInTheDocument()
  })

  it('admins mark a listener expected', async () => {
    renderWithProviders(<Processes />, { role: 'admin' })
    fireEvent.click(await screen.findByRole('button', { name: 'Mark TCP 4444 expected' }))
    await waitFor(() =>
      expect(mocked.markListenerKnown).toHaveBeenCalledWith({
        host_id: 0,
        proto: 'TCP',
        port: 4444,
        process: 'nc',
      }),
    )
  })

  it('viewers cannot', async () => {
    renderWithProviders(<Processes />, { role: 'viewer' })
    await screen.findByRole('region', { name: 'Listening ports' })
    expect(screen.queryByRole('button', { name: /expected/ })).not.toBeInTheDocument()
  })

  it('switches host', async () => {
    renderWithProviders(<Processes />)
    await screen.findByRole('region', { name: 'Listening ports' })
    await screen.findByRole('option', { name: 'web-1' })
    fireEvent.change(screen.getByLabelText('Host'), { target: { value: '4' } })
    await waitFor(() => expect(mocked.getSockets).toHaveBeenLastCalledWith(4))
  })
})
