import axios from 'axios'
import {
  AgentInfo,
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

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000'

// Create axios instance
const apiClient = axios.create({
  baseURL: API_BASE_URL,
  timeout: 10000,
  headers: {
    'Content-Type': 'application/json',
  },
})

// Request interceptor
apiClient.interceptors.request.use(
  (config) => {
    // Add any auth headers here if needed
    return config
  },
  (error) => {
    return Promise.reject(error)
  },
)

// Response interceptor
apiClient.interceptors.response.use(
  (response) => {
    return response
  },
  (error) => {
    console.error('API Error:', error)

    // Handle common errors
    if (error.response?.status === 401) {
      // Handle unauthorized
    } else if (error.response?.status >= 500) {
      // Handle server errors
      console.error('Server error:', error.response.data)
    }

    return Promise.reject(error)
  },
)

export const api = {
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

  async acknowledgeAlert(id: number, data: { acknowledged_by: string; notes?: string }) {
    const response = await apiClient.post(`/api/alerts/${id}/acknowledge`, data)
    return response.data
  },

  async resolveAlert(id: number, data: { resolved_by: string; resolution_notes: string }) {
    const response = await apiClient.post(`/api/alerts/${id}/resolve`, data)
    return response.data
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
