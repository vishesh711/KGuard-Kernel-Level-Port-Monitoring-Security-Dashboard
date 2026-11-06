import { useQuery } from '@tanstack/react-query'
import { api } from '../services/api'

/** Query keys shared by components and live-update invalidation */
export const queryKeys = {
  health: ['health'] as const,
  eventStats: (hours: number) => ['events', 'stats', hours] as const,
  traffic: (hours: number, interval: number) => ['events', 'traffic', hours, interval] as const,
  recentEvents: (size: number) => ['events', 'recent', size] as const,
  alertStats: (hours: number) => ['alerts', 'stats', hours] as const,
  recentAlerts: (size: number) => ['alerts', 'recent', size] as const,
  activeAlerts: ['alerts', 'active'] as const,
  agents: ['agents'] as const,
}

/** Fallback polling when the live connection is down */
const REFRESH_MS = 30_000

export function useHealth() {
  return useQuery({
    queryKey: queryKeys.health,
    queryFn: () => api.getHealth(),
    refetchInterval: REFRESH_MS,
  })
}

export function useEventStats(hours = 24) {
  return useQuery({
    queryKey: queryKeys.eventStats(hours),
    queryFn: () => api.getEventStats(hours),
    refetchInterval: REFRESH_MS,
  })
}

export function useTrafficSummary(hours = 24, interval = 1) {
  return useQuery({
    queryKey: queryKeys.traffic(hours, interval),
    queryFn: () => api.getTrafficSummary(hours, interval),
    refetchInterval: REFRESH_MS,
  })
}

export function useRecentEvents(size = 8) {
  return useQuery({
    queryKey: queryKeys.recentEvents(size),
    queryFn: () => api.getEvents({ page: 1, size }),
    refetchInterval: REFRESH_MS,
  })
}

export function useAlertStats(hours = 24) {
  return useQuery({
    queryKey: queryKeys.alertStats(hours),
    queryFn: () => api.getAlertStats(hours),
    refetchInterval: REFRESH_MS,
  })
}

export function useRecentAlerts(size = 5) {
  return useQuery({
    queryKey: queryKeys.recentAlerts(size),
    queryFn: () => api.getAlerts({ page: 1, size }),
    refetchInterval: REFRESH_MS,
  })
}

export function useActiveAlerts() {
  return useQuery({
    queryKey: queryKeys.activeAlerts,
    queryFn: () => api.getActiveAlertsSummary() as Promise<ActiveAlertsSummary>,
    refetchInterval: REFRESH_MS,
  })
}

export interface ActiveAlertsSummary {
  total_active: number
  severity_breakdown: Record<'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW', number>
  type_breakdown: Record<string, number>
}

export function useAgents() {
  return useQuery({
    queryKey: queryKeys.agents,
    queryFn: () => api.getAgents(),
    refetchInterval: 10_000,
  })
}
