import { describe, expect, it } from 'vitest'
import { formatUptime, parseServerDate } from './time'

describe('parseServerDate', () => {
  it('treats times without a zone as UTC', () => {
    expect(parseServerDate('2026-01-05T21:49:42.957').toISOString()).toBe('2026-01-05T21:49:42.957Z')
  })

  it('keeps an explicit zone', () => {
    expect(parseServerDate('2026-01-05T21:49:42Z').toISOString()).toBe('2026-01-05T21:49:42.000Z')
    expect(parseServerDate('2026-01-05T23:49:42+02:00').toISOString()).toBe('2026-01-05T21:49:42.000Z')
  })
})

describe('formatUptime', () => {
  it('shows hours and minutes under a day', () => {
    expect(formatUptime(3 * 3600 + 25 * 60)).toBe('3h 25m')
  })

  it('shows days and hours from one day up', () => {
    expect(formatUptime(2 * 86400 + 5 * 3600)).toBe('2d 5h')
  })
})
