import { afterEach, describe, expect, it } from 'vitest'
import type { InternalAxiosRequestConfig } from 'axios'
import { apiClient } from './api'
import { SESSION_ENDED, clearSession, getToken, saveSession } from '../lib/session'

type Reply = { status: number; data: unknown }

function respond(reply: Reply, seen: InternalAxiosRequestConfig[]) {
  apiClient.defaults.adapter = async (config) => {
    seen.push(config)
    const response = { ...reply, statusText: '', headers: {}, config }
    if (reply.status >= 400) {
      throw Object.assign(new Error('failed'), { isAxiosError: true, config, response })
    }
    return response
  }
}

describe('API client', () => {
  afterEach(() => clearSession())

  it('sends the login token on every request', async () => {
    saveSession({ token: 'abc', username: 'a', role: 'viewer', expiresAt: Date.now() + 60_000 })
    const seen: InternalAxiosRequestConfig[] = []
    respond({ status: 200, data: [] }, seen)
    await apiClient.get('/api/events/')
    expect(seen[0].headers.Authorization).toBe('Bearer abc')
  })

  it('ends the session when the API refuses the token', async () => {
    saveSession({ token: 'revoked', username: 'a', role: 'viewer', expiresAt: Date.now() + 60_000 })
    let ended = false
    window.addEventListener(SESSION_ENDED, () => (ended = true), { once: true })
    respond({ status: 401, data: {} }, [])
    await expect(apiClient.get('/api/events/')).rejects.toBeTruthy()
    expect(ended).toBe(true)
    expect(getToken()).toBeNull()
  })

  it('a failed login does not end anything', async () => {
    saveSession({ token: 'keep', username: 'a', role: 'viewer', expiresAt: Date.now() + 60_000 })
    respond({ status: 401, data: {} }, [])
    await expect(apiClient.post('/api/auth/login', {})).rejects.toBeTruthy()
    expect(getToken()).toBe('keep')
  })
})
