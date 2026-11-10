import { ReactNode } from 'react'
import { Link } from 'react-router-dom'
import {
  ShieldCheckIcon,
  ExclamationTriangleIcon,
  EyeIcon,
  ServerIcon,
  ChartBarIcon,
  ClockIcon,
} from '@heroicons/react/24/outline'
import { StatsCard } from '../components/dashboard/StatsCard'
import { RecentEvents } from '../components/dashboard/RecentEvents'
import { RecentAlerts } from '../components/dashboard/RecentAlerts'
import { TrafficChart } from '../components/charts/TrafficChart'
import { ProtocolChart } from '../components/charts/ProtocolChart'
import { useLiveStatus } from '../context/liveStatus'
import {
  useAlertStats,
  useEventStats,
  useHealth,
  useRecentAlerts,
  useRecentEvents,
  useTrafficSummary,
} from '../hooks/queries'
import { formatUptime } from '../lib/time'

function Panel({
  title,
  icon,
  link,
  children,
}: {
  title: string
  icon: ReactNode
  link?: string
  children: ReactNode
}) {
  return (
    <div className="card">
      <div className="card-header">
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-2">
            {icon}
            <h3 className="text-lg font-medium text-gray-900">{title}</h3>
          </div>
          {link && (
            <Link to={link} className="text-sm text-blue-600 hover:text-blue-700">
              View all
            </Link>
          )}
        </div>
      </div>
      {children}
    </div>
  )
}

function StatusDot({ ok, label, detail }: { ok: boolean; label: string; detail: string }) {
  return (
    <div className="flex items-center space-x-3">
      <div className={`h-3 w-3 rounded-full ${ok ? 'bg-green-500' : 'bg-red-500'}`}></div>
      <div>
        <p className="text-sm font-medium text-gray-900">{label}</p>
        <p className="text-xs text-gray-500">{detail}</p>
      </div>
    </div>
  )
}

function Loading() {
  return <div className="h-64 animate-pulse rounded bg-gray-100" />
}

export function Dashboard() {
  const live = useLiveStatus()
  const health = useHealth()
  const eventStats = useEventStats(24)
  const alertStats = useAlertStats(24)
  const traffic = useTrafficSummary(24, 1)
  const recentEvents = useRecentEvents(8)
  const recentAlerts = useRecentAlerts(5)

  const backendDown = health.isError && eventStats.isError
  const alertColor = alertStats.data?.critical_alerts
    ? 'danger'
    : alertStats.data?.high_alerts
      ? 'warning'
      : 'success'

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-gray-900">Security Dashboard</h1>
        <p className="mt-1 text-sm text-gray-600">Real-time network monitoring and threat detection</p>
      </div>

      {backendDown && (
        <div className="rounded-md border border-red-200 bg-red-50 p-4 text-sm text-red-800" role="alert">
          Can&apos;t reach the KGuard backend. Check that it is running (and, if the dashboard is served apart
          from it, that VITE_API_BASE_URL points to it).
        </div>
      )}

      <div className="grid grid-cols-1 gap-6 sm:grid-cols-2 lg:grid-cols-4">
        <StatsCard
          title="Total Events"
          value={eventStats.data?.total_events ?? 0}
          icon={EyeIcon}
          loading={eventStats.isLoading}
          subtitle="Last 24 hours"
        />
        <StatsCard
          title="Suspicious Events"
          value={eventStats.data?.suspicious_events ?? 0}
          icon={ExclamationTriangleIcon}
          loading={eventStats.isLoading}
          subtitle="Flagged by detection"
          color="warning"
        />
        <StatsCard
          title="Active Alerts"
          value={alertStats.data?.unresolved_alerts ?? 0}
          icon={ShieldCheckIcon}
          loading={alertStats.isLoading}
          subtitle="Need attention"
          color={alertColor}
        />
        <StatsCard
          title="Backend Uptime"
          value={health.data ? formatUptime(health.data.uptime_seconds) : 'N/A'}
          icon={ServerIcon}
          loading={health.isLoading}
          subtitle={live.connected ? 'Live updates on' : 'Live updates off'}
          color={health.data?.status === 'healthy' ? 'success' : 'warning'}
        />
      </div>

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        <Panel title="Traffic Over Time" icon={<ChartBarIcon className="h-5 w-5 text-gray-400" />}>
          <div className="card-content">
            {traffic.isLoading ? <Loading /> : <TrafficChart data={traffic.data ?? []} />}
          </div>
        </Panel>
        <Panel title="Protocol Distribution" icon={<ChartBarIcon className="h-5 w-5 text-gray-400" />}>
          <div className="card-content">
            {eventStats.isLoading ? (
              <Loading />
            ) : (
              <ProtocolChart data={eventStats.data?.protocol_distribution ?? {}} />
            )}
          </div>
        </Panel>
      </div>

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        <Panel title="Recent Events" icon={<ClockIcon className="h-5 w-5 text-gray-400" />} link="/events">
          <div className="card-content p-0">
            <RecentEvents events={recentEvents.data?.items ?? []} />
          </div>
        </Panel>
        <Panel
          title="Recent Alerts"
          icon={<ExclamationTriangleIcon className="h-5 w-5 text-gray-400" />}
          link="/alerts"
        >
          <div className="card-content p-0">
            <RecentAlerts alerts={recentAlerts.data?.items ?? []} />
          </div>
        </Panel>
      </div>

      <div className="card">
        <div className="card-header">
          <h3 className="text-lg font-medium text-gray-900">System Status</h3>
        </div>
        <div className="card-content">
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
            <StatusDot
              ok={!!health.data?.database}
              label="Database"
              detail={health.data?.database ? 'Connected' : 'Disconnected'}
            />
            <StatusDot
              ok={!!health.data?.kernel_module}
              label="Kernel Module"
              detail={health.data?.kernel_module ? 'Active' : 'Not loaded'}
            />
            <StatusDot
              ok={live.connected}
              label="Live Updates"
              detail={live.connected ? 'Connected' : live.reconnecting ? 'Reconnecting…' : 'Disconnected'}
            />
          </div>
        </div>
      </div>
    </div>
  )
}
