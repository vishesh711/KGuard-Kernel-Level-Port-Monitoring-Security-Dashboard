import { format } from 'date-fns'
import { parseServerDate } from './time'
import { Block } from '../types'

/** Kernel timestamps are nanoseconds since the epoch */
export function eventDate(ns: number): Date {
  return new Date(Math.floor(ns / 1e6))
}

export function formatEventTime(ns: number): string {
  return format(eventDate(ns), 'HH:mm:ss.SSS')
}

export function formatServerTime(value: string | null | undefined): string {
  return value ? format(parseServerDate(value), 'yyyy-MM-dd HH:mm:ss') : '—'
}

const TCP_FLAGS: [number, string][] = [
  [0x02, 'SYN'],
  [0x10, 'ACK'],
  [0x01, 'FIN'],
  [0x04, 'RST'],
  [0x08, 'PSH'],
  [0x20, 'URG'],
]

export function tcpFlags(protocol: string, flags: number): string {
  if (protocol !== 'TCP') return ''
  return TCP_FLAGS.filter(([bit]) => flags & bit)
    .map(([, name]) => name)
    .join(' ')
}

export function endpoint(ip: string, port: number | null | undefined): string {
  if (port === null || port === undefined || port === 0) return ip
  return ip.includes(':') ? `[${ip}]:${port}` : `${ip}:${port}`
}

export function compactNumber(n: number): string {
  return new Intl.NumberFormat(undefined, { notation: 'compact', maximumFractionDigits: 1 }).format(n)
}

/** How long a block has left, in words */
export function timeLeft(block: Block): string {
  if (!block.active) return block.removed_by === 'expiry' ? 'expired' : 'removed'
  if (block.seconds_left === null) return 'until unblocked'
  const s = block.seconds_left
  if (s < 3600) return `${Math.max(1, Math.round(s / 60))} min`
  if (s < 86400) return `${Math.round(s / 3600)} h`
  return `${Math.round(s / 86400)} d`
}
