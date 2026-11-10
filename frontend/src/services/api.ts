import axios, { isAxiosError } from 'axios'
import {
  AgentInfo,
  AllowEntry,
  AuditEntry,
  Block,
  ResponseStatus,
  SocketSnapshot,
  KernelCounters,
  NetworkEvent,
  SecurityAlert,
  NetworkEventStats,
  AlertStats,
  TrafficSummary,
  HealthCheck,
  PaginatedResponse,
  FilterOptions,
  AlertFilterOptions,
} from '../types'
import { Role, endSession, getToken } from '../lib/session'

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000'

// Create axios instance
export const apiClient = axios.create({
  baseURL: API_BASE_URL,
  timeout: 10000,
  headers: {
    'Content-Type': 'application/json',
  },
})

// Every request carries the login token
apiClient.interceptors.request.use((config) => {
  const token = getToken()
  if (token) config.headers.Authorization = `Bearer ${token}`
  return config
})

// A refused token (expired, revoked, user disabled) ends the session
apiClient.interceptors.response.use(
  (response) => response,
  (error) => {
    const status = error.response?.status
    if (status === 401 && !String(error.config?.url ?? '').endsWith('/api/auth/login')) {
      endSession()
    } else if (status >= 500) {
      console.error('Server error:', error.response.data)
    }
    return Promise.reject(error)
  },
)

export interface LoginResult {
  access_token: string
  token_type: string
  expires_in: number
  username: string
  role: Role
}

export const api = {
  // Login
  async login(username: string, password: string): Promise<LoginResult> {
    const response = await apiClient.post('/api/auth/login', { username, password })
    return response.data
  },

  // Network Events
  async getEvents(
    params: {
      page?: number
      size?: number
      filters?: FilterOptions
    } = {},
  ): Promise<PaginatedResponse<NetworkEvent>> {
    const { page = 1, size = 25, filters = {} } = params
    const response = await apiClient.get('/api/events/', {
      params: {
        page,
        size,
        ...filters,
      },
    })
    return response.data
  },

  async getEvent(id: number): Promise<NetworkEvent> {
    const response = await apiClient.get(`/api/events/${id}`)
    return response.data
  },

  async getEventStats(hours: number = 24): Promise<NetworkEventStats> {
    const response = await apiClient.get('/api/events/stats/summary', {
      params: { hours },
    })
    return response.data
  },

  async getTrafficSummary(hours: number = 24, interval: number = 1): Promise<TrafficSummary[]> {
    const response = await apiClient.get('/api/events/stats/traffic', {
      params: { hours, interval },
    })
    return response.data
  },

  // Security Alerts
  async getAlerts(
    params: {
      page?: number
      size?: number
      filters?: AlertFilterOptions
    } = {},
  ): Promise<PaginatedResponse<SecurityAlert>> {
    const { page = 1, size = 25, filters = {} } = params
    const response = await apiClient.get('/api/alerts/', {
      params: {
        page,
        size,
        ...filters,
      },
    })
    return response.data
  },

  async getAlert(id: number): Promise<SecurityAlert> {
    const response = await apiClient.get(`/api/alerts/${id}`)
    return response.data
  },

  /** The backend records the logged-in user as the one who acknowledged */
  async acknowledgeAlert(id: number, data: { notes?: string } = {}) {
    const response = await apiClient.post(`/api/alerts/${id}/acknowledge`, data)
    return response.data
  },

  async resolveAlert(id: number, data: { resolution_notes: string }) {
    const response = await apiClient.post(`/api/alerts/${id}/resolve`, data)
    return response.data
  },

  async getEventsByIds(ids: number[]): Promise<NetworkEvent[]> {
    if (!ids.length) return []
    const response = await apiClient.get('/api/events/', {
      params: { ids: ids.slice(-100).join(','), size: 100 },
    })
    return response.data.items
  },

  /** The alert's packet capture as a file download (null if there is none) */
  async downloadPcap(id: number): Promise<Blob | null> {
    try {
      const response = await apiClient.get(`/api/alerts/${id}/pcap`, { responseType: 'blob' })
      return response.data
    } catch (e) {
      if (isAxiosError(e) && e.response?.status === 404) return null
      throw e
    }
  },

  async getAlertStats(hours: number = 24): Promise<AlertStats> {
    const response = await apiClient.get('/api/alerts/stats/summary', {
      params: { hours },
    })
    return response.data
  },

  async getActiveAlertsSummary() {
    const response = await apiClient.get('/api/alerts/active/summary')
    return response.data
  },

  // Response engine: blocks, allowlist, audit log
  async getBlocks(includeRemoved = false): Promise<Block[]> {
    const response = await apiClient.get('/api/response/blocks', {
      params: includeRemoved ? { include_removed: true } : {},
    })
    return response.data
  },

  async addBlock(body: { cidr: string; reason: string; minutes?: number | null; host_id?: number | null }) {
    const response = await apiClient.post('/api/response/blocks', body)
    return response.data as Block & { created: boolean }
  },

  async removeBlock(id: number) {
    const response = await apiClient.delete(`/api/response/blocks/${id}`)
    return response.data as Block
  },

  async getAllowlist(): Promise<AllowEntry[]> {
    const response = await apiClient.get('/api/response/allowlist')
    return response.data
  },

  async addAllow(body: { cidr: string; note?: string }) {
    const response = await apiClient.post('/api/response/allowlist', body)
    return response.data as AllowEntry
  },

  async removeAllow(id: number) {
    await apiClient.delete(`/api/response/allowlist/${id}`)
  },

  async getAudit(page = 1, size = 50): Promise<{ items: AuditEntry[]; total: number }> {
    const response = await apiClient.get('/api/response/audit', { params: { page, size } })
    return response.data
  },

  async getResponseStatus(): Promise<ResponseStatus> {
    const response = await apiClient.get('/api/response/status')
    return response.data
  },

  // Listening ports and connections (U7.2)
  async getSockets(hostId = 0): Promise<SocketSnapshot> {
    const response = await apiClient.get('/api/sockets', { params: { host_id: hostId } })
    return response.data
  },

  async markListenerKnown(body: { host_id: number; proto: string; port: number; process: string }) {
    await apiClient.post('/api/sockets/known', body)
  },

  async getKernelCounters(): Promise<KernelCounters> {
    const response = await apiClient.get('/api/health/kernel/counters')
    return response.data
  },

  // Agents (remote hosts)
  async getAgents(): Promise<AgentInfo[]> {
    const response = await apiClient.get('/api/agents/')
    return response.data
  },

  // Health and System
  async getHealth(): Promise<HealthCheck> {
    const response = await apiClient.get('/api/health/')
    return response.data
  },

  async getDetailedHealth() {
    const response = await apiClient.get('/api/health/detailed')
    return response.data
  },

  async getDatabaseHealth() {
    const response = await apiClient.get('/api/health/database')
    return response.data
  },

  async getKernelHealth() {
    const response = await apiClient.get('/api/health/kernel')
    return response.data
  },

  async getServicesHealth() {
    const response = await apiClient.get('/api/health/services')
    return response.data
  },

  async getSystemMetrics() {
    const response = await apiClient.get('/api/health/metrics')
    return response.data
  },

  // Utility functions
  async cleanupOldEvents(days: number = 30) {
    const response = await apiClient.delete('/api/events/cleanup', {
      params: { days },
    })
    return response.data
  },

  async cleanupOldAlerts(days: number = 90) {
    const response = await apiClient.delete('/api/alerts/cleanup', {
      params: { days },
    })
    return response.data
  },
}

export default api
